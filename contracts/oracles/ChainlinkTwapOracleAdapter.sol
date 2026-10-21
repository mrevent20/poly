// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import {IAggregatorV3} from "../interfaces/IAggregatorV3.sol";
import {IConditionalTokens} from "../interfaces/IConditionalTokens.sol";
import {IPriceMarketOracle} from "../interfaces/IPriceMarketOracle.sol";

/// @title Chainlink TWAP Oracle Adapter
/// @notice 处理价格型预测市场的 TWAP 自动清算。
/// @dev 适配器验证连续的 Chainlink round，计算价格区间窗口的 TWAP，并把 YES / NO / INVALID
///      的结论写回 CTF，避免由单一后台直接裁决结果。
contract ChainlinkTwapOracleAdapter is AccessControlUpgradeable, ReentrancyGuard, IPriceMarketOracle {
  bytes32 public constant ORACLE_ADMIN_ROLE = keccak256("ORACLE_ADMIN_ROLE");
  uint256 public constant MAX_ROUNDS = 256;

  struct MarketConfig {
    IAggregatorV3 feed;
    uint64 windowStart;
    uint64 windowEnd;
    uint256 threshold;
    bytes32 metadataHash;
    bool resolveAbove;
    bool configured;
    bool resolved;
  }

  struct TwapAccumulator {
    uint256 currentAnswer;
    uint256 cursor;
    uint256 weightedPrice;
    uint256 previousUpdatedAt;
    uint80 previousRoundId;
    bool covered;
  }

  error InvalidAddress();
  error InvalidConfiguration();
  error InvalidRound();
  error InvalidRoundCount();
  error NonContiguousRounds();
  error MarketAlreadyConfigured();
  error MarketAlreadyResolved();
  error MarketNotConfigured();
  error ResolutionTooEarly();
  error WindowNotCovered();

  event MarketConfigured(
    bytes32 indexed questionId,
    address indexed feed,
    uint64 windowStart,
    uint64 windowEnd,
    uint256 threshold,
    bool resolveAbove,
    bytes32 metadataHash
  );
  event MarketResolved(bytes32 indexed questionId, uint256 twap, uint256 yesPayout, uint256 noPayout);

  IConditionalTokens public conditionalTokens;
  mapping(bytes32 questionId => MarketConfig config) public marketConfigs;

  /// @custom:oz-upgrades-unsafe-allow constructor
  constructor(address conditionalTokens_, address initialAdmin) {
    initialize(conditionalTokens_, initialAdmin);
    _disableInitializers();
  }

  function initialize(address conditionalTokens_, address initialAdmin) public initializer {
    if (conditionalTokens_ == address(0) || initialAdmin == address(0)) revert InvalidAddress();

    __AccessControl_init();
    conditionalTokens = IConditionalTokens(conditionalTokens_);
    _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);
    _grantRole(ORACLE_ADMIN_ROLE, initialAdmin);
  }

  function configureMarket(
    bytes32 questionId,
    address feed,
    uint64 windowStart,
    uint64 windowEnd,
    uint256 threshold,
    bool resolveAbove,
    bytes32 rulesHash
  ) external onlyRole(ORACLE_ADMIN_ROLE) {
    if (feed == address(0)) revert InvalidAddress();
    if (windowStart >= windowEnd || windowEnd <= block.timestamp || threshold == 0) {
      revert InvalidConfiguration();
    }
    if (marketConfigs[questionId].configured) revert MarketAlreadyConfigured();

    bytes32 metadataHash = configurationHash(
      feed, windowStart, windowEnd, threshold, resolveAbove, rulesHash
    );

    marketConfigs[questionId] = MarketConfig({
      feed: IAggregatorV3(feed),
      windowStart: windowStart,
      windowEnd: windowEnd,
      threshold: threshold,
      metadataHash: metadataHash,
      resolveAbove: resolveAbove,
      configured: true,
      resolved: false
    });
    emit MarketConfigured(
      questionId, feed, windowStart, windowEnd, threshold, resolveAbove, metadataHash
    );
  }

  function configurationHash(
    address feed,
    uint64 windowStart,
    uint64 windowEnd,
    uint256 threshold,
    bool resolveAbove,
    bytes32 rulesHash
  ) public pure returns (bytes32) {
    return keccak256(abi.encode(feed, windowStart, windowEnd, threshold, resolveAbove, rulesHash));
  }

  function validateMarketRegistration(bytes32 questionId, uint64 cutoffTime, bytes32 metadataHash)
    external
    view
    returns (bool)
  {
    MarketConfig storage config = marketConfigs[questionId];
    return config.configured && config.windowEnd == cutoffTime && config.metadataHash == metadataHash;
  }

  function calculateTwap(bytes32 questionId, uint80[] calldata roundIds) external view returns (uint256) {
    MarketConfig storage config = marketConfigs[questionId];
    if (!config.configured) revert MarketNotConfigured();
    (uint256 weightedPrice, uint256 windowDuration) = _calculateTwap(config, roundIds);
    return weightedPrice / windowDuration;
  }

  function resolveMarket(bytes32 questionId, uint80[] calldata roundIds) external nonReentrant {
    MarketConfig storage config = marketConfigs[questionId];
    if (!config.configured) revert MarketNotConfigured();
    if (config.resolved) revert MarketAlreadyResolved();
    if (block.timestamp < config.windowEnd) revert ResolutionTooEarly();

    (uint256 weightedPrice, uint256 windowDuration) = _calculateTwap(config, roundIds);
    uint256 twap = weightedPrice / windowDuration;
    uint256 thresholdWeighted = config.threshold * windowDuration;
    uint256[] memory payouts = new uint256[](2);
    bool yes = config.resolveAbove
      ? weightedPrice >= thresholdWeighted
      : weightedPrice <= thresholdWeighted;
    payouts[yes ? 0 : 1] = 1;

    config.resolved = true;
    conditionalTokens.reportPayouts(questionId, payouts);
    emit MarketResolved(questionId, twap, payouts[0], payouts[1]);
  }

  /// @notice 7大流盘场景（如赛事取消、数据源失效、价格异常）下的管理员应急中止接口
  function emergencyAbortMarket(bytes32 questionId) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
    MarketConfig storage config = marketConfigs[questionId];
    if (!config.configured) revert MarketNotConfigured();
    if (config.resolved) revert MarketAlreadyResolved();

    config.resolved = true;
    uint256[] memory payouts = new uint256[](2);
    payouts[0] = 1;
    payouts[1] = 1;

    conditionalTokens.reportPayouts(questionId, payouts);
    emit MarketResolved(questionId, 0, 1, 1);
  }

  function _calculateTwap(MarketConfig storage config, uint80[] calldata roundIds)
    internal
    view
    returns (uint256 weightedPrice, uint256 windowDuration)
  {
    uint256 roundCount = roundIds.length;
    if (roundCount < 2 || roundCount > MAX_ROUNDS) revert InvalidRoundCount();

    (uint256 firstAnswer, uint256 firstUpdatedAt) = _readRound(config.feed, roundIds[0]);
    if (firstUpdatedAt > config.windowStart) revert WindowNotCovered();

    TwapAccumulator memory accumulator = TwapAccumulator({
      currentAnswer: firstAnswer,
      cursor: config.windowStart,
      weightedPrice: 0,
      previousUpdatedAt: firstUpdatedAt,
      previousRoundId: roundIds[0],
      covered: false
    });

    for (uint256 i = 1; i < roundCount; ++i) {
      uint80 roundId = roundIds[i];
      uint16 currentPhase = uint16(roundId >> 64);
      uint64 currentAggRound = uint64(roundId);
      uint16 prevPhase = uint16(accumulator.previousRoundId >> 64);
      uint64 prevAggRound = uint64(accumulator.previousRoundId);

      // AggregatorV3 does not expose the final round number of a completed
      // phase. Accepting phase N round X -> phase N+1 round 1 would therefore
      // let a caller omit later rounds from phase N and manipulate the TWAP.
      // Until a phase-aware boundary source is configured, only sequences
      // whose contiguity can be proven inside one phase are accepted.
      bool isContiguous = currentPhase == prevPhase && currentAggRound == prevAggRound + 1;
      if (!isContiguous) revert NonContiguousRounds();

      (uint256 answer, uint256 updatedAt) = _readRound(config.feed, roundId);
      if (updatedAt <= accumulator.previousUpdatedAt) revert InvalidRound();

      if (updatedAt <= config.windowStart) {
        accumulator.currentAnswer = answer;
      } else if (updatedAt < config.windowEnd) {
        accumulator.weightedPrice += accumulator.currentAnswer * (updatedAt - accumulator.cursor);
        accumulator.cursor = updatedAt;
        accumulator.currentAnswer = answer;
      } else {
        if (i != roundCount - 1) revert InvalidRoundCount();
        accumulator.weightedPrice +=
          accumulator.currentAnswer * (config.windowEnd - accumulator.cursor);
        accumulator.covered = true;
      }

      accumulator.previousUpdatedAt = updatedAt;
      accumulator.previousRoundId = roundId;
    }

    if (!accumulator.covered) revert WindowNotCovered();
    return (accumulator.weightedPrice, config.windowEnd - config.windowStart);
  }

  function _readRound(IAggregatorV3 feed, uint80 roundId)
    internal
    view
    returns (uint256 answer, uint256 updatedAt)
  {
    (uint80 returnedRoundId, int256 signedAnswer,, uint256 roundUpdatedAt, uint80 answeredInRound) =
      feed.getRoundData(roundId);
    if (
      returnedRoundId != roundId || signedAnswer <= 0 || roundUpdatedAt == 0
        || answeredInRound < roundId
    ) {
      revert InvalidRound();
    }
    return (uint256(signedAnswer), roundUpdatedAt);
  }
}
