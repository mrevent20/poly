// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";

import {IConditionalTokens} from "../interfaces/IConditionalTokens.sol";
import {IPriceMarketOracle} from "../interfaces/IPriceMarketOracle.sol";

/// @title Zeus Market Registry
/// @notice 注册并维护二元预测市场的条件 ID、token ID 与结算状态。
/// @dev 这个合约本身不处理交易；它负责把事件/价格市场写入 Gnosis CTF，并提供
///      Open / Locked / Resolved 的查询入口，供订单簿和清算适配器统一读取结果。
contract ZeusMarketRegistry is AccessControlUpgradeable {
  bytes32 public constant MARKET_CREATOR_ROLE = keccak256("MARKET_CREATOR_ROLE");

  enum MarketType {
    Event,
    Price
  }

  enum MarketState {
    Open,
    Locked,
    Resolved
  }

  enum Resolution {
    Unresolved,
    Yes,
    No,
    Invalid
  }

  struct Market {
    bytes32 questionId;
    address oracle;
    uint64 cutoffTime;
    bytes32 metadataHash;
    uint256 yesTokenId;
    uint256 noTokenId;
    MarketType marketType;
    bool exists;
  }

  error InvalidAddress();
  error InvalidCutoffTime();
  error UnknownMarket(bytes32 conditionId);
  error MarketAlreadyRegistered(bytes32 conditionId);
  error InvalidOutcomeSlotCount(uint256 outcomeSlotCount);
  error InvalidOracleConfiguration();

  event MarketRegistered(
    bytes32 indexed conditionId,
    bytes32 indexed questionId,
    address indexed oracle,
    uint256 yesTokenId,
    uint256 noTokenId,
    uint64 cutoffTime,
    bytes32 metadataHash,
    MarketType marketType
  );

  IConditionalTokens public conditionalTokens;
  address public collateralToken;

  mapping(bytes32 conditionId => Market market) private markets;

  /// @custom:oz-upgrades-unsafe-allow constructor
  constructor(address conditionalTokens_, address collateralToken_, address initialAdmin) {
    initialize(conditionalTokens_, collateralToken_, initialAdmin);
    _disableInitializers();
  }

  function initialize(address conditionalTokens_, address collateralToken_, address initialAdmin)
    public
    initializer
  {
    if (conditionalTokens_ == address(0) || collateralToken_ == address(0) || initialAdmin == address(0)) {
      revert InvalidAddress();
    }

    __AccessControl_init();
    conditionalTokens = IConditionalTokens(conditionalTokens_);
    collateralToken = collateralToken_;
    _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);
    _grantRole(MARKET_CREATOR_ROLE, initialAdmin);
  }

  function registerMarket(
    bytes32 questionId,
    address oracle,
    uint64 cutoffTime,
    bytes32 metadataHash,
    MarketType marketType
  ) external onlyRole(MARKET_CREATOR_ROLE) returns (bytes32 conditionId) {
    if (oracle == address(0)) revert InvalidAddress();
    if (cutoffTime <= block.timestamp) revert InvalidCutoffTime();
    if (marketType == MarketType.Price) {
      try IPriceMarketOracle(oracle).validateMarketRegistration(
        questionId, cutoffTime, metadataHash
      ) returns (bool valid) {
        if (!valid) revert InvalidOracleConfiguration();
      } catch {
        revert InvalidOracleConfiguration();
      }
    }

    conditionId = conditionalTokens.getConditionId(oracle, questionId, 2);
    if (markets[conditionId].exists) revert MarketAlreadyRegistered(conditionId);

    uint256 outcomeSlotCount = conditionalTokens.getOutcomeSlotCount(conditionId);
    if (outcomeSlotCount == 0) {
      conditionalTokens.prepareCondition(oracle, questionId, 2);
    } else if (outcomeSlotCount != 2) {
      revert InvalidOutcomeSlotCount(outcomeSlotCount);
    }

    bytes32 yesCollectionId = conditionalTokens.getCollectionId(bytes32(0), conditionId, 1);
    bytes32 noCollectionId = conditionalTokens.getCollectionId(bytes32(0), conditionId, 2);
    uint256 yesTokenId = conditionalTokens.getPositionId(collateralToken, yesCollectionId);
    uint256 noTokenId = conditionalTokens.getPositionId(collateralToken, noCollectionId);

    markets[conditionId] = Market({
      questionId: questionId,
      oracle: oracle,
      cutoffTime: cutoffTime,
      metadataHash: metadataHash,
      yesTokenId: yesTokenId,
      noTokenId: noTokenId,
      marketType: marketType,
      exists: true
    });

    emit MarketRegistered(
      conditionId,
      questionId,
      oracle,
      yesTokenId,
      noTokenId,
      cutoffTime,
      metadataHash,
      marketType
    );
  }

  function getMarket(bytes32 conditionId) external view returns (Market memory) {
    return markets[conditionId];
  }

  function getMarketState(bytes32 conditionId) external view returns (MarketState) {
    Market storage market = markets[conditionId];
    if (!market.exists) revert UnknownMarket(conditionId);

    if (conditionalTokens.payoutDenominator(conditionId) != 0) return MarketState.Resolved;
    if (block.timestamp >= market.cutoffTime) return MarketState.Locked;
    return MarketState.Open;
  }

  function getResolution(bytes32 conditionId) external view returns (Resolution) {
    if (!markets[conditionId].exists) revert UnknownMarket(conditionId);

    uint256 denominator = conditionalTokens.payoutDenominator(conditionId);
    if (denominator == 0) return Resolution.Unresolved;

    uint256 yesPayout = conditionalTokens.payoutNumerators(conditionId, 0);
    uint256 noPayout = conditionalTokens.payoutNumerators(conditionId, 1);
    if (yesPayout == denominator) return Resolution.Yes;
    if (noPayout == denominator) return Resolution.No;
    return Resolution.Invalid;
  }
}
