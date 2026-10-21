// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ERC1155Holder} from "@openzeppelin/contracts/token/ERC1155/utils/ERC1155Holder.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import {ComplianceRegistry} from "../compliance/ComplianceRegistry.sol";
import {IConditionalTokens} from "../interfaces/IConditionalTokens.sol";
import {ZeusFeeEscrow} from "../escrow/ZeusFeeEscrow.sol";
import {ZeusDepositWalletFactory} from "../accounts/ZeusDepositWalletFactory.sol";
import {ZeusMarketRegistry} from "./ZeusMarketRegistry.sol";

/// @title Zeus Exchange
/// @notice Polymarket 风格的完全准备金 CLOB 交易引擎。
/// @dev 交易使用 EIP-712 限价订单，matcher 负责核验签名并执行 direct / mint / merge
///      三种原子结算路径。所有成交都受市场状态、合规门控和付费托管约束。
///      支持 1v多批量深度吃单 (Place Bet)、用户自主熔断 (UserPausable) 与 Builder 生态追踪。
contract ZeusExchange is AccessControl, ERC1155Holder, EIP712, Pausable, ReentrancyGuard {
  using SafeERC20 for IERC20;

  bytes32 public constant MATCHER_ROLE = keccak256("MATCHER_ROLE");
  uint256 public constant PRICE_SCALE = 1e18;
  uint256 public constant BASIS_POINTS = 10_000;
  bytes32 public constant ORDER_TYPEHASH = keccak256(
    "Order(uint256 salt,address maker,bytes32 conditionId,uint256 tokenId,uint8 side,uint256 price,uint256 amount,uint256 nonce,uint64 expiration,uint16 maxFeeBps,bytes32 metadata,bytes32 builder)"
  );

  enum Side {
    Buy,
    Sell
  }

  struct Order {
    uint256 salt;
    address maker;
    bytes32 conditionId;
    uint256 tokenId;
    Side side;
    uint256 price;
    uint256 amount;
    uint256 nonce;
    uint64 expiration;
    uint16 maxFeeBps;
    bytes32 metadata;
    bytes32 builder;
  }

  struct TradeValues {
    uint256 maker;
    uint256 taker;
  }

  error InvalidAddress();
  error AccountNotCompliant(address account);
  error InvalidFeeRate();
  error InvalidFillAmount();
  error InvalidOrder();
  error InvalidSignature();
  error MarketNotOpen();
  error NonceNotIncreasing();
  error NotOrderMaker();
  error OrderIsCancelled(bytes32 orderHash);
  error OrderNonceTooLow(uint256 orderNonce, uint256 minimumNonce);
  error OrderExpired();
  error OrderOverfilled();
  error PriceDoesNotCross();
  error UnsupportedMatch();
  error UserIsPaused(address user);
  error BatchLengthMismatch();
  error BatchEmpty();
  error DepositWalletFactoryAlreadyConfigured(address factory);

  event OrdersMatched(
    bytes32 indexed takerOrderHash,
    bytes32 indexed makerOrderHash,
    bytes32 indexed conditionId,
    uint256 fillAmount
  );
  event BatchOrdersMatched(
    bytes32 indexed takerOrderHash,
    bytes32 indexed conditionId,
    uint256 totalFillAmount,
    uint256 makerCount
  );
  event BuilderTrade(
    bytes32 indexed builder,
    address indexed maker,
    bytes32 indexed conditionId,
    uint256 fillAmount,
    uint256 tradeValue
  );
  event OrderCancelled(bytes32 indexed orderHash, address indexed maker);
  event MinimumNonceUpdated(address indexed maker, uint256 oldNonce, uint256 newNonce);
  event UserPauseUpdated(address indexed user, bool isPaused);
  event DepositWalletFactoryConfigured(address indexed factory);

  IConditionalTokens public immutable conditionalTokens;
  IERC20 public immutable collateralToken;
  ZeusMarketRegistry public immutable marketRegistry;
  ZeusFeeEscrow public immutable feeEscrow;
  ComplianceRegistry public immutable complianceRegistry;
  uint16 public immutable feeBps;
  ZeusDepositWalletFactory public depositWalletFactory;

  mapping(bytes32 orderHash => uint256 amount) public filledAmount;
  mapping(bytes32 orderHash => uint256 amount) public executedTradeValue;
  mapping(bytes32 orderHash => uint256 amount) public feeBearingTradeValue;
  mapping(bytes32 orderHash => uint256 amount) public chargedFeeAmount;
  mapping(bytes32 orderHash => bool isCancelled) public cancelled;
  mapping(address maker => uint256 nonce) public minimumNonce;
  mapping(address user => bool) public isUserPaused;

  constructor(
    address conditionalTokens_,
    address collateralToken_,
    address marketRegistry_,
    address feeEscrow_,
    address complianceRegistry_,
    uint16 feeBps_,
    address initialAdmin
  ) EIP712("Zeus CLOB Exchange", "1") {
    if (
      conditionalTokens_ == address(0) || collateralToken_ == address(0) || marketRegistry_ == address(0)
        || feeEscrow_ == address(0) || complianceRegistry_ == address(0) || initialAdmin == address(0)
    ) {
      revert InvalidAddress();
    }
    if (feeBps_ > BASIS_POINTS) revert InvalidFeeRate();

    conditionalTokens = IConditionalTokens(conditionalTokens_);
    collateralToken = IERC20(collateralToken_);
    marketRegistry = ZeusMarketRegistry(marketRegistry_);
    feeEscrow = ZeusFeeEscrow(feeEscrow_);
    complianceRegistry = ComplianceRegistry(complianceRegistry_);
    feeBps = feeBps_;
    _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);
    _grantRole(MATCHER_ROLE, initialAdmin);
    collateralToken.forceApprove(feeEscrow_, type(uint256).max);
    collateralToken.forceApprove(conditionalTokens_, type(uint256).max);
  }

  function hashOrder(Order calldata order) public view returns (bytes32) {
    return _hashTypedDataV4(
      keccak256(
        abi.encode(
          ORDER_TYPEHASH,
          order.salt,
          order.maker,
          order.conditionId,
          order.tokenId,
          order.side,
          order.price,
          order.amount,
          order.nonce,
          order.expiration,
          order.maxFeeBps,
          order.metadata,
          order.builder
        )
      )
    );
  }

  function cancelOrder(Order calldata order) external {
    if (canonicalAccountOf(msg.sender) != canonicalAccountOf(order.maker)) revert NotOrderMaker();

    bytes32 orderHash = hashOrder(order);
    cancelled[orderHash] = true;
    emit OrderCancelled(orderHash, msg.sender);
  }

  /// @notice Configures the deterministic user funding-account registry once.
  /// @dev EOA makers without a deployed funding wallet remain supported as an explicit power-user path.
  function setDepositWalletFactory(address factory) external onlyRole(DEFAULT_ADMIN_ROLE) {
    if (factory == address(0)) revert InvalidAddress();
    address configuredFactory = address(depositWalletFactory);
    if (configuredFactory != address(0)) {
      revert DepositWalletFactoryAlreadyConfigured(configuredFactory);
    }
    depositWalletFactory = ZeusDepositWalletFactory(factory);
    emit DepositWalletFactoryConfigured(factory);
  }

  function fundingAccountOf(address owner) public view returns (address account) {
    ZeusDepositWalletFactory factory = depositWalletFactory;
    if (address(factory) != address(0)) {
      account = factory.walletOf(owner);
    }
    return account == address(0) ? owner : account;
  }

  function canonicalAccountOf(address account) public view returns (address canonicalAccount) {
    ZeusDepositWalletFactory factory = depositWalletFactory;
    if (address(factory) != address(0)) {
      canonicalAccount = factory.ownerOfWallet(account);
    }
    return canonicalAccount == address(0) ? account : canonicalAccount;
  }

  function incrementNonce(uint256 newNonce) external {
    address maker = canonicalAccountOf(msg.sender);
    uint256 oldNonce = minimumNonce[maker];
    if (newNonce <= oldNonce) revert NonceNotIncreasing();

    minimumNonce[maker] = newNonce;
    emit MinimumNonceUpdated(maker, oldNonce, newNonce);
  }

  /// @notice 用户自主紧急熔断撤单（借鉴 ctf-exchange-v2 的 UserPausable 机制）
  function setUserPause(bool isPaused) external {
    address user = canonicalAccountOf(msg.sender);
    isUserPaused[user] = isPaused;
    emit UserPauseUpdated(user, isPaused);
  }

  function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
    _pause();
  }

  function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
    _unpause();
  }

  /// @notice 单对单标准撮合
  function matchOrders(
    Order calldata takerOrder,
    bytes calldata takerSignature,
    Order calldata makerOrder,
    bytes calldata makerSignature,
    uint256 fillAmount
  ) external onlyRole(MATCHER_ROLE) whenNotPaused nonReentrant {
    ZeusMarketRegistry.Market memory market = marketRegistry.getMarket(takerOrder.conditionId);
    if (
      !market.exists
        || marketRegistry.getMarketState(takerOrder.conditionId) != ZeusMarketRegistry.MarketState.Open
    ) {
      revert MarketNotOpen();
    }

    bytes32 takerOrderHash = _validateOrder(takerOrder, takerSignature, fillAmount, true);
    filledAmount[takerOrderHash] += fillAmount;

    _matchSingle(takerOrder, takerOrderHash, makerOrder, makerSignature, fillAmount, market);
    _validateExecutionLimit(takerOrder, takerOrderHash);
  }

  /// @notice 1对多批量吃单撮合（支持 Place Bet 快速下注吃深度，借鉴 ctf-exchange-v2）
  function matchOrdersBatch(
    Order calldata takerOrder,
    bytes calldata takerSignature,
    Order[] calldata makerOrders,
    bytes[] calldata makerSignatures,
    uint256[] calldata fillAmounts
  ) external onlyRole(MATCHER_ROLE) whenNotPaused nonReentrant {
    uint256 makerCount = makerOrders.length;
    if (makerCount == 0) revert BatchEmpty();
    if (makerCount != makerSignatures.length || makerCount != fillAmounts.length) {
      revert BatchLengthMismatch();
    }

    ZeusMarketRegistry.Market memory market = marketRegistry.getMarket(takerOrder.conditionId);
    if (
      !market.exists
        || marketRegistry.getMarketState(takerOrder.conditionId) != ZeusMarketRegistry.MarketState.Open
    ) {
      revert MarketNotOpen();
    }

    uint256 totalFillAmount;
    for (uint256 i = 0; i < makerCount; ++i) {
      totalFillAmount += fillAmounts[i];
    }

    bytes32 takerOrderHash = _validateOrder(takerOrder, takerSignature, totalFillAmount, true);
    filledAmount[takerOrderHash] += totalFillAmount;

    uint256 totalTakerTradeValue;
    address[] memory batchMakers = new address[](makerCount);
    uint256[] memory batchMakerTradeValues = new uint256[](makerCount);
    uint256 uniqueMakerCount;
    for (uint256 i = 0; i < makerCount; ++i) {
      uint256 fillAmount = fillAmounts[i];
      if (fillAmount == 0) revert InvalidFillAmount();
      TradeValues memory tradeValues =
        _matchSingle(takerOrder, takerOrderHash, makerOrders[i], makerSignatures[i], fillAmount, market);
      totalTakerTradeValue += tradeValues.taker;
      uniqueMakerCount = _accumulateMakerTradeValue(
        batchMakers,
        batchMakerTradeValues,
        uniqueMakerCount,
        canonicalAccountOf(makerOrders[i].maker),
        tradeValues.maker
      );
    }

    _requireCompliant(takerOrder.maker, totalTakerTradeValue);
    for (uint256 i = 0; i < uniqueMakerCount; ++i) {
      _requireCompliant(batchMakers[i], batchMakerTradeValues[i]);
    }
    _validateExecutionLimit(takerOrder, takerOrderHash);

    emit BatchOrdersMatched(takerOrderHash, takerOrder.conditionId, totalFillAmount, makerCount);
  }

  function _matchSingle(
    Order calldata takerOrder,
    bytes32 takerOrderHash,
    Order calldata makerOrder,
    bytes calldata makerSignature,
    uint256 fillAmount,
    ZeusMarketRegistry.Market memory market
  ) internal returns (TradeValues memory tradeValues) {
    if (
      takerOrder.conditionId != makerOrder.conditionId
        || canonicalAccountOf(takerOrder.maker) == canonicalAccountOf(makerOrder.maker)
    ) {
      revert UnsupportedMatch();
    }
    if (
      (takerOrder.tokenId != market.yesTokenId && takerOrder.tokenId != market.noTokenId)
        || (makerOrder.tokenId != market.yesTokenId && makerOrder.tokenId != market.noTokenId)
    ) {
      revert InvalidOrder();
    }

    uint8 matchKind;
    if (takerOrder.tokenId == makerOrder.tokenId && takerOrder.side != makerOrder.side) {
      matchKind = 0;
    } else if (
      takerOrder.tokenId != makerOrder.tokenId && takerOrder.side == Side.Buy
        && makerOrder.side == Side.Buy
    ) {
      matchKind = 1;
    } else if (
      takerOrder.tokenId != makerOrder.tokenId && takerOrder.side == Side.Sell
        && makerOrder.side == Side.Sell
    ) {
      matchKind = 2;
    } else {
      revert UnsupportedMatch();
    }

    bytes32 makerOrderHash = _validateOrder(makerOrder, makerSignature, fillAmount, false);
    uint256 previousMakerFill = filledAmount[makerOrderHash];
    filledAmount[makerOrderHash] += fillAmount;
    tradeValues = _calculateValidateAndSettle(
      takerOrder,
      takerOrderHash,
      makerOrder,
      makerOrderHash,
      fillAmount,
      previousMakerFill,
      matchKind
    );
    _validateExecutionLimit(makerOrder, makerOrderHash);

    if (makerOrder.builder != bytes32(0)) {
      emit BuilderTrade(
        makerOrder.builder,
        makerOrder.maker,
        takerOrder.conditionId,
        fillAmount,
        tradeValues.maker
      );
    }
    if (takerOrder.builder != bytes32(0)) {
      emit BuilderTrade(
        takerOrder.builder,
        takerOrder.maker,
        takerOrder.conditionId,
        fillAmount,
        tradeValues.taker
      );
    }

    emit OrdersMatched(takerOrderHash, makerOrderHash, takerOrder.conditionId, fillAmount);
  }

  function _calculateValidateAndSettle(
    Order calldata takerOrder,
    bytes32 takerOrderHash,
    Order calldata makerOrder,
    bytes32 makerOrderHash,
    uint256 fillAmount,
    uint256 previousMakerFill,
    uint8 matchKind
  ) internal returns (TradeValues memory tradeValues) {
    if (matchKind == 0) {
      tradeValues.maker =
        _calculateDirectCollateral(takerOrder, makerOrder, fillAmount, previousMakerFill);
      tradeValues.taker = tradeValues.maker;
    } else {
      (tradeValues.maker, tradeValues.taker) =
        _calculateComplementaryCollateral(takerOrder, makerOrder, fillAmount, previousMakerFill);
    }

    executedTradeValue[makerOrderHash] += tradeValues.maker;
    executedTradeValue[takerOrderHash] += tradeValues.taker;
    feeBearingTradeValue[takerOrderHash] += tradeValues.taker;
    uint256 cumulativeFee = feeBearingTradeValue[takerOrderHash] * feeBps / BASIS_POINTS;
    uint256 feeAmount = cumulativeFee - chargedFeeAmount[takerOrderHash];
    chargedFeeAmount[takerOrderHash] = cumulativeFee;

    _requireCompliant(
      makerOrder.maker,
      _complianceTradeValue(makerOrder, tradeValues.maker)
    );
    _requireCompliant(
      takerOrder.maker,
      _complianceTradeValue(takerOrder, tradeValues.taker)
    );

    if (matchKind == 0) {
      _settleDirect(takerOrder, makerOrder, fillAmount, tradeValues.maker, feeAmount);
    } else if (matchKind == 1) {
      _settleMint(
        takerOrder, makerOrder, fillAmount, tradeValues.maker, tradeValues.taker, feeAmount
      );
    } else {
      _settleMerge(
        takerOrder, makerOrder, fillAmount, tradeValues.maker, tradeValues.taker, feeAmount
      );
    }
  }

  function _validateExecutionLimit(Order calldata order, bytes32 orderHash) internal view {
    uint256 limitValue = order.side == Side.Buy
      ? Math.mulDiv(filledAmount[orderHash], order.price, PRICE_SCALE)
      : Math.mulDiv(
        filledAmount[orderHash], order.price, PRICE_SCALE, Math.Rounding.Ceil
      );
    uint256 executionValue = executedTradeValue[orderHash];
    if (
      (order.side == Side.Buy && executionValue > limitValue)
        || (order.side == Side.Sell && executionValue < limitValue)
    ) {
      revert InvalidFillAmount();
    }
  }

  function _accumulateMakerTradeValue(
    address[] memory makers,
    uint256[] memory tradeValues,
    uint256 makerCount,
    address maker,
    uint256 tradeValue
  ) internal pure returns (uint256) {
    for (uint256 i = 0; i < makerCount; ++i) {
      if (makers[i] == maker) {
        tradeValues[i] += tradeValue;
        return makerCount;
      }
    }
    makers[makerCount] = maker;
    tradeValues[makerCount] = tradeValue;
    return makerCount + 1;
  }

  function _requireCompliant(address account, uint256 tradeValue) internal view {
    address canonicalAccount = canonicalAccountOf(account);
    if (!complianceRegistry.canTrade(canonicalAccount, tradeValue)) {
      revert AccountNotCompliant(canonicalAccount);
    }
    address fundingAccount = fundingAccountOf(canonicalAccount);
    if (
      fundingAccount != canonicalAccount
        && !complianceRegistry.canTrade(fundingAccount, tradeValue)
    ) {
      revert AccountNotCompliant(fundingAccount);
    }
  }

  function _complianceTradeValue(Order calldata order, uint256 fillTradeValue)
    internal
    pure
    returns (uint256)
  {
    uint256 signedOrderValue = Math.mulDiv(
      order.amount,
      order.price,
      PRICE_SCALE,
      Math.Rounding.Ceil
    );
    return signedOrderValue > fillTradeValue ? signedOrderValue : fillTradeValue;
  }

  function _settleDirect(
    Order calldata takerOrder,
    Order calldata makerOrder,
    uint256 fillAmount,
    uint256 collateralAmount,
    uint256 feeAmount
  ) internal {
    (Order calldata buyOrder, Order calldata sellOrder) = _getBuyAndSellOrders(takerOrder, makerOrder);
    address buyAccount = fundingAccountOf(buyOrder.maker);
    address sellAccount = fundingAccountOf(sellOrder.maker);
    address takerAccount = fundingAccountOf(takerOrder.maker);

    if (takerOrder.side == Side.Buy) {
      collateralToken.safeTransferFrom(buyAccount, sellAccount, collateralAmount);
      if (feeAmount != 0) collateralToken.safeTransferFrom(takerAccount, address(this), feeAmount);
    } else {
      collateralToken.safeTransferFrom(buyAccount, sellAccount, collateralAmount - feeAmount);
      if (feeAmount != 0) collateralToken.safeTransferFrom(buyAccount, address(this), feeAmount);
    }

    conditionalTokens.safeTransferFrom(
      sellAccount,
      buyAccount,
      takerOrder.tokenId,
      fillAmount,
      ""
    );
    if (feeAmount != 0) feeEscrow.depositFee(takerOrder.conditionId, takerAccount, feeAmount);
  }

  function _settleMint(
    Order calldata takerOrder,
    Order calldata makerOrder,
    uint256 fillAmount,
    uint256 makerCollateralAmount,
    uint256 takerCollateralAmount,
    uint256 feeAmount
  ) internal {
    address makerAccount = fundingAccountOf(makerOrder.maker);
    address takerAccount = fundingAccountOf(takerOrder.maker);

    collateralToken.safeTransferFrom(makerAccount, address(this), makerCollateralAmount);
    collateralToken.safeTransferFrom(takerAccount, address(this), takerCollateralAmount + feeAmount);

    uint256[] memory partition = new uint256[](2);
    partition[0] = 1;
    partition[1] = 2;
    conditionalTokens.splitPosition(
      address(collateralToken),
      bytes32(0),
      takerOrder.conditionId,
      partition,
      fillAmount
    );
    conditionalTokens.safeTransferFrom(
      address(this),
      takerAccount,
      takerOrder.tokenId,
      fillAmount,
      ""
    );
    conditionalTokens.safeTransferFrom(
      address(this),
      makerAccount,
      makerOrder.tokenId,
      fillAmount,
      ""
    );
    if (feeAmount != 0) feeEscrow.depositFee(takerOrder.conditionId, takerAccount, feeAmount);
  }

  function _settleMerge(
    Order calldata takerOrder,
    Order calldata makerOrder,
    uint256 fillAmount,
    uint256 makerCollateralAmount,
    uint256 takerCollateralAmount,
    uint256 feeAmount
  ) internal {
    address makerAccount = fundingAccountOf(makerOrder.maker);
    address takerAccount = fundingAccountOf(takerOrder.maker);

    conditionalTokens.safeTransferFrom(
      takerAccount,
      address(this),
      takerOrder.tokenId,
      fillAmount,
      ""
    );
    conditionalTokens.safeTransferFrom(
      makerAccount,
      address(this),
      makerOrder.tokenId,
      fillAmount,
      ""
    );

    uint256[] memory partition = new uint256[](2);
    partition[0] = 1;
    partition[1] = 2;
    conditionalTokens.mergePositions(
      address(collateralToken),
      bytes32(0),
      takerOrder.conditionId,
      partition,
      fillAmount
    );

    collateralToken.safeTransfer(makerAccount, makerCollateralAmount);
    collateralToken.safeTransfer(takerAccount, takerCollateralAmount - feeAmount);
    if (feeAmount != 0) feeEscrow.depositFee(takerOrder.conditionId, takerAccount, feeAmount);
  }

  function _calculateDirectCollateral(
    Order calldata takerOrder,
    Order calldata makerOrder,
    uint256 fillAmount,
    uint256 previousMakerFill
  ) internal pure returns (uint256 collateralAmount) {
    (Order calldata buyOrder, Order calldata sellOrder) = _getBuyAndSellOrders(takerOrder, makerOrder);
    if (buyOrder.price < sellOrder.price) revert PriceDoesNotCross();

    Math.Rounding makerRounding = makerOrder.side == Side.Sell
      ? Math.Rounding.Ceil
      : Math.Rounding.Floor;
    uint256 cumulativeCollateral = Math.mulDiv(
      previousMakerFill + fillAmount,
      makerOrder.price,
      PRICE_SCALE,
      makerRounding
    );
    uint256 previousCollateral = Math.mulDiv(
      previousMakerFill, makerOrder.price, PRICE_SCALE, makerRounding
    );
    collateralAmount = cumulativeCollateral - previousCollateral;
  }

  function _calculateComplementaryCollateral(
    Order calldata takerOrder,
    Order calldata makerOrder,
    uint256 fillAmount,
    uint256 previousMakerFill
  ) internal pure returns (uint256 makerCollateralAmount, uint256 takerCollateralAmount) {
    Math.Rounding makerRounding = makerOrder.side == Side.Sell
      ? Math.Rounding.Ceil
      : Math.Rounding.Floor;
    uint256 cumulativeMakerCollateral = Math.mulDiv(
      previousMakerFill + fillAmount,
      makerOrder.price,
      PRICE_SCALE,
      makerRounding
    );
    uint256 previousMakerCollateral = Math.mulDiv(
      previousMakerFill, makerOrder.price, PRICE_SCALE, makerRounding
    );
    makerCollateralAmount = cumulativeMakerCollateral - previousMakerCollateral;

    if (takerOrder.side == Side.Buy) {
      if (takerOrder.price + makerOrder.price < PRICE_SCALE) revert PriceDoesNotCross();
      takerCollateralAmount = fillAmount - makerCollateralAmount;
    } else {
      if (takerOrder.price + makerOrder.price > PRICE_SCALE) revert PriceDoesNotCross();
      if (makerCollateralAmount > fillAmount) revert InvalidFillAmount();
      takerCollateralAmount = fillAmount - makerCollateralAmount;
    }
  }

  function _getBuyAndSellOrders(Order calldata takerOrder, Order calldata makerOrder)
    internal
    pure
    returns (Order calldata buyOrder, Order calldata sellOrder)
  {
    buyOrder = takerOrder.side == Side.Buy ? takerOrder : makerOrder;
    sellOrder = takerOrder.side == Side.Sell ? takerOrder : makerOrder;
  }

  function _validateOrder(
    Order calldata order,
    bytes calldata signature,
    uint256 fillAmount,
    bool chargesFee
  ) internal view returns (bytes32 orderHash) {
    if (
      order.maker == address(0) || order.amount == 0 || fillAmount == 0 || order.price == 0
        || order.price > PRICE_SCALE
    ) {
      revert InvalidOrder();
    }
    address canonicalMaker = canonicalAccountOf(order.maker);
    if (isUserPaused[canonicalMaker]) revert UserIsPaused(canonicalMaker);
    if (block.timestamp >= order.expiration) revert OrderExpired();
    if (chargesFee && order.maxFeeBps < feeBps) revert InvalidFeeRate();
    uint256 makerMinimumNonce = minimumNonce[canonicalMaker];
    if (order.nonce < makerMinimumNonce) revert OrderNonceTooLow(order.nonce, makerMinimumNonce);

    orderHash = hashOrder(order);
    if (cancelled[orderHash]) revert OrderIsCancelled(orderHash);
    if (filledAmount[orderHash] + fillAmount > order.amount) revert OrderOverfilled();
    if (!SignatureChecker.isValidSignatureNow(order.maker, orderHash, signature)) revert InvalidSignature();
  }

  function supportsInterface(bytes4 interfaceId)
    public
    view
    override(AccessControl, ERC1155Holder)
    returns (bool)
  {
    return super.supportsInterface(interfaceId);
  }
}
