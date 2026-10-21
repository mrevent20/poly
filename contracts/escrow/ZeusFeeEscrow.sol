// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import {ReferralRegistry} from "./ReferralRegistry.sol";
import {ZeusMarketRegistry} from "../core/ZeusMarketRegistry.sol";
import {ZeusDepositWalletFactory} from "../accounts/ZeusDepositWalletFactory.sol";

/// @title Zeus Fee Escrow
/// @notice 统一托管撮合服务费，直到市场结算才进行分配。
/// @dev 有效市场按 45% reserve / 35% ecosystem / 20% operations 分账；单级推荐佣金
///      从 ecosystem 份额中支付。Invalid 市场则退还给各 payer。
///      该合约是付款与收益结算的缓冲层，避免在结算前提前释放资金。
contract ZeusFeeEscrow is AccessControlUpgradeable, ReentrancyGuard {
  using SafeERC20 for IERC20;

  bytes32 public constant FEE_DEPOSITOR_ROLE = keccak256("FEE_DEPOSITOR_ROLE");
  uint256 public constant BASIS_POINTS = 10_000;
  uint256 public constant RESERVE_SHARE_BPS = 4_500;
  uint256 public constant ECOSYSTEM_SHARE_BPS = 3_500;
  uint256 public constant OPERATIONS_SHARE_BPS = 2_000;
  uint256 public constant REFERRAL_SHARE_BPS = 1_000;

  error InvalidAddress();
  error InvalidFeeRecipients();
  error ZeroAmount();
  error NoFeeBalance();
  error MarketIsNotInvalid();
  error MarketIsNotResolved();
  error DepositWalletFactoryAlreadyConfigured(address factory);

  event FeeDeposited(bytes32 indexed conditionId, address indexed payer, uint256 amount);
  event FeeRefunded(bytes32 indexed conditionId, address indexed payer, uint256 amount);
  event FeeReleased(
    bytes32 indexed conditionId,
    address indexed payer,
    address indexed referrer,
    uint256 reserveAmount,
    uint256 referralAmount,
    uint256 ecosystemAmount,
    uint256 operationsAmount
  );
  event ReferralFeeClaimed(address indexed referrer, uint256 amount);
  event DepositWalletFactoryConfigured(address indexed factory);

  IERC20 public collateralToken;
  ZeusMarketRegistry public marketRegistry;
  ReferralRegistry public referralRegistry;
  address public reserve;
  address public ecosystem;
  address public treasury;
  ZeusDepositWalletFactory public depositWalletFactory;

  mapping(bytes32 conditionId => mapping(address payer => uint256 amount)) public feesByPayer;
  mapping(bytes32 conditionId => mapping(address payer => address referrer)) public feeReferrer;
  mapping(bytes32 conditionId => mapping(address payer => uint256 amount)) public referralEligibleFees;
  mapping(address referrer => uint256 amount) public claimableReferralFees;
  mapping(bytes32 conditionId => address[]) private _payersByCondition;
  mapping(bytes32 conditionId => mapping(address payer => bool)) private _isPayerRecorded;

  /// @custom:oz-upgrades-unsafe-allow constructor
  constructor(
    address collateralToken_,
    address marketRegistry_,
    address referralRegistry_,
    address reserve_,
    address ecosystem_,
    address treasury_,
    address initialAdmin
  ) {
    initialize(collateralToken_, marketRegistry_, referralRegistry_, reserve_, ecosystem_, treasury_, initialAdmin);
    _disableInitializers();
  }

  function initialize(
    address collateralToken_,
    address marketRegistry_,
    address referralRegistry_,
    address reserve_,
    address ecosystem_,
    address treasury_,
    address initialAdmin
  ) public initializer {
    if (
      collateralToken_ == address(0) || marketRegistry_ == address(0) || referralRegistry_ == address(0)
        || reserve_ == address(0) || ecosystem_ == address(0) || treasury_ == address(0)
        || initialAdmin == address(0)
    ) {
      revert InvalidAddress();
    }
    if (reserve_ == ecosystem_ || reserve_ == treasury_ || ecosystem_ == treasury_) {
      revert InvalidFeeRecipients();
    }

    __AccessControl_init();
    collateralToken = IERC20(collateralToken_);
    marketRegistry = ZeusMarketRegistry(marketRegistry_);
    referralRegistry = ReferralRegistry(referralRegistry_);
    reserve = reserve_;
    ecosystem = ecosystem_;
    treasury = treasury_;
    _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);
  }

  function setDepositWalletFactory(address factory) external onlyRole(DEFAULT_ADMIN_ROLE) {
    if (factory == address(0)) revert InvalidAddress();
    address configuredFactory = address(depositWalletFactory);
    if (configuredFactory != address(0)) {
      revert DepositWalletFactoryAlreadyConfigured(configuredFactory);
    }
    depositWalletFactory = ZeusDepositWalletFactory(factory);
    emit DepositWalletFactoryConfigured(factory);
  }

  function depositFee(bytes32 conditionId, address payer, uint256 amount)
    external
    onlyRole(FEE_DEPOSITOR_ROLE)
    nonReentrant
  {
    if (payer == address(0)) revert InvalidAddress();
    if (amount == 0) revert ZeroAmount();

    collateralToken.safeTransferFrom(msg.sender, address(this), amount);
    feesByPayer[conditionId][payer] += amount;
    if (!_isPayerRecorded[conditionId][payer]) {
      _isPayerRecorded[conditionId][payer] = true;
      _payersByCondition[conditionId].push(payer);
    }
    address referrer = _resolveReferrer(payer);
    if (referrer != address(0)) {
      feeReferrer[conditionId][payer] = referrer;
      referralEligibleFees[conditionId][payer] += amount;
    }
    emit FeeDeposited(conditionId, payer, amount);
  }

  function claimInvalidRefund(bytes32 conditionId) external nonReentrant {
    _claimInvalidRefund(conditionId, msg.sender);
  }

  /// @notice 支持 EOA 提取其资金钱包 (DepositWallet) 托管的 Invalid 手续费退款
  function claimInvalidRefundFor(bytes32 conditionId, address payer) external nonReentrant {
    if (payer != msg.sender) {
      ZeusDepositWalletFactory factory = depositWalletFactory;
      if (address(factory) == address(0) || factory.ownerOfWallet(payer) != msg.sender) {
        revert InvalidAddress();
      }
    }
    _claimInvalidRefund(conditionId, payer);
  }

  function _claimInvalidRefund(bytes32 conditionId, address payer) internal {
    if (marketRegistry.getResolution(conditionId) != ZeusMarketRegistry.Resolution.Invalid) {
      revert MarketIsNotInvalid();
    }

    uint256 amount = feesByPayer[conditionId][payer];
    if (amount == 0) revert NoFeeBalance();

    feesByPayer[conditionId][payer] = 0;
    delete feeReferrer[conditionId][payer];
    delete referralEligibleFees[conditionId][payer];
    collateralToken.safeTransfer(msg.sender, amount);
    emit FeeRefunded(conditionId, payer, amount);
  }

  /// @notice 查询某盘口所有付款人地址列表
  function getPayers(bytes32 conditionId) external view returns (address[] memory) {
    return _payersByCondition[conditionId];
  }

  /// @notice 查询某盘口付款人总数
  function getPayersCount(bytes32 conditionId) external view returns (uint256) {
    return _payersByCondition[conditionId].length;
  }

  /// @notice 查询某盘口当前未释放的总手续费余额
  function unreleasedFeeBalance(bytes32 conditionId) external view returns (uint256 total) {
    address[] storage payers = _payersByCondition[conditionId];
    uint256 len = payers.length;
    for (uint256 i; i < len; ++i) {
      total += feesByPayer[conditionId][payers[i]];
    }
  }

  /// @notice 自动释放某盘口记录的所有付款人手续费并执行分账与返佣（无需外部传入付款人列表）
  function releaseAllFees(bytes32 conditionId) external nonReentrant {
    _releaseFees(conditionId, _payersByCondition[conditionId]);
  }

  /// @notice 按指定付款人列表分批释放手续费（保留分批处理能力，防止超长循环）
  function releaseFees(bytes32 conditionId, address[] calldata payers) external nonReentrant {
    _releaseFees(conditionId, payers);
  }

  function _releaseFees(bytes32 conditionId, address[] memory payers) internal {
    ZeusMarketRegistry.Resolution resolution = marketRegistry.getResolution(conditionId);
    if (resolution != ZeusMarketRegistry.Resolution.Yes && resolution != ZeusMarketRegistry.Resolution.No) {
      revert MarketIsNotResolved();
    }

    uint256 totalReserveAmount;
    uint256 totalEcosystemAmount;
    uint256 totalOperationsAmount;
    uint256 payerCount = payers.length;
    for (uint256 i; i < payerCount; ++i) {
      address payer = payers[i];
      uint256 amount = feesByPayer[conditionId][payer];
      if (amount == 0) continue;

      feesByPayer[conditionId][payer] = 0;
      uint256 reserveAmount = amount * RESERVE_SHARE_BPS / BASIS_POINTS;
      uint256 ecosystemGrossAmount = amount * ECOSYSTEM_SHARE_BPS / BASIS_POINTS;
      address referrer = feeReferrer[conditionId][payer];
      uint256 referralAmount = referralEligibleFees[conditionId][payer]
        * REFERRAL_SHARE_BPS / BASIS_POINTS;
      delete feeReferrer[conditionId][payer];
      delete referralEligibleFees[conditionId][payer];
      if (referralAmount != 0) {
        claimableReferralFees[referrer] += referralAmount;
      }
      uint256 ecosystemAmount = ecosystemGrossAmount - referralAmount;
      uint256 operationsAmount = amount - reserveAmount - ecosystemAmount - referralAmount;
      totalReserveAmount += reserveAmount;
      totalEcosystemAmount += ecosystemAmount;
      totalOperationsAmount += operationsAmount;

      emit FeeReleased(
        conditionId,
        payer,
        referrer,
        reserveAmount,
        referralAmount,
        ecosystemAmount,
        operationsAmount
      );
    }

    if (totalReserveAmount != 0) collateralToken.safeTransfer(reserve, totalReserveAmount);
    if (totalEcosystemAmount != 0) collateralToken.safeTransfer(ecosystem, totalEcosystemAmount);
    if (totalOperationsAmount != 0) collateralToken.safeTransfer(treasury, totalOperationsAmount);
  }

  /// @notice 推荐人主动提取累积的推荐返佣（支持 EOA 或其 DepositWallet 调用，Pull 模式杜绝 DoS）
  function claimReferralFee() external nonReentrant {
    address recipient = msg.sender;
    address account = _canonicalAccount(recipient);
    uint256 amount = claimableReferralFees[account];
    if (amount == 0 && account != recipient) {
      amount = claimableReferralFees[recipient];
      account = recipient;
    }
    if (amount == 0) revert NoFeeBalance();

    claimableReferralFees[account] = 0;
    collateralToken.safeTransfer(recipient, amount);
    emit ReferralFeeClaimed(account, amount);
  }

  /// @notice 查询指定账户的可提取返佣（支持 DepositWallet 或 EOA 双向穿透）
  function claimableReferralFeesOf(address account) external view returns (uint256) {
    address canonical = _canonicalAccount(account);
    uint256 amount = claimableReferralFees[canonical];
    if (amount == 0 && canonical != account) {
      amount = claimableReferralFees[account];
    }
    return amount;
  }

  function _resolveReferrer(address payer) internal view returns (address referrer) {
    address canonicalPayer = _canonicalAccount(payer);
    referrer = referralRegistry.referrerOf(canonicalPayer);
    if (referrer == address(0) && payer != canonicalPayer) {
      referrer = referralRegistry.referrerOf(payer);
    }
    if (referrer == address(0)) return address(0);
    referrer = _canonicalAccount(referrer);
    if (referrer == canonicalPayer) return address(0);
  }

  function _canonicalAccount(address account) internal view returns (address canonicalAccount) {
    ZeusDepositWalletFactory factory = depositWalletFactory;
    if (address(factory) != address(0)) {
      canonicalAccount = factory.ownerOfWallet(account);
    }
    return canonicalAccount == address(0) ? account : canonicalAccount;
  }
}
