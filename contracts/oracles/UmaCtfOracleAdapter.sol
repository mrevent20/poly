// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

import {IConditionalTokens} from "../interfaces/IConditionalTokens.sol";
import {
  IOptimisticOracleV3,
  IOptimisticOracleV3CallbackRecipient
} from "../interfaces/IOptimisticOracleV3.sol";
import {ZeusMarketRegistry} from "../core/ZeusMarketRegistry.sol";

/// @title UMA CTF Oracle Adapter
/// @notice 处理事件型预测市场的 UMA 清算接入。
/// @dev 该适配器负责注册事件市场，并在 UMA OOv3 产出最终断言后，将 YES / NO / INVALID
///      的结果回写到 Gnosis CTF；争议复核保留公开异议和证据规则。
///      镜像市场使用单独绑定的 Polymarket 来源和授权中继，不验证跨链证明。
contract UmaCtfOracleAdapter is
  AccessControlUpgradeable,
  ReentrancyGuard,
  IOptimisticOracleV3CallbackRecipient
{
  using SafeERC20 for IERC20;

  bytes32 public constant MARKET_CONFIG_ROLE = keccak256("MARKET_CONFIG_ROLE");
  uint64 public constant MIN_LIVENESS = 1 days;
  uint64 public constant REVIEW_PERIOD = 48 hours;
  uint256 public constant DISPUTE_BOND = 100 ether;
  uint8 public constant REVIEWER_COUNT = 3;
  uint256 public constant MAX_EVIDENCE_BYTES = 512;

  enum Outcome {
    Unset,
    Yes,
    No,
    Invalid
  }

  struct MarketConfig {
    IERC20 currency;
    uint64 cutoffTime;
    uint64 liveness;
    uint256 bond;
    bool configured;
    bool resolved;
    bytes rules;
    address[3] reviewers;
    bytes32 conflictDisclosureHash;
  }

  struct AssertionData {
    bytes32 questionId;
    Outcome outcome;
    address asserter;
    uint256 bond;
    bool exists;
    bool aborted;
    uint64 assertedAt;
  }

  struct ReviewCase {
    Outcome proposedOutcome;
    Outcome finalOutcome;
    address challenger;
    bytes32 challengeEvidenceHash;
    uint64 challengedAt;
    uint64 deadline;
    uint8 validVotes;
    uint8 yesVotes;
    uint8 noVotes;
    uint8 invalidVotes;
    uint8 recusedCount;
    bool active;
    bool finalized;
    uint256 disputeBond;
  }

  error ActiveAssertionExists(bytes32 assertionId);
  error AssertionTooEarly();
  error ChallengeWindowClosed();
  error ChallengeWindowOpen();
  error InvalidAddress();
  error InvalidConfiguration();
  error InvalidEvidence();
  error InvalidOutcome();
  error InvalidReviewCommittee();
  error MarketAlreadyConfigured();
  error MarketAlreadyResolved();
  error MarketNotConfigured();
  error MarketRegistrationMismatch();
  error NativeDisputeBondExceedsLimit(uint256 requiredBond, uint256 disputeBondLimit);
  error NoActiveAssertion();
  error NoClaimableBond();
  error NotSelectedReviewer();
  error OnlyOptimisticOracle();
  error ReviewAlreadyActive();
  error ReviewDeadlineNotReached();
  error ReviewDeadlinePassed();
  error ReviewNotActive();
  error ReviewerAlreadyVoted();
  error ReviewerRecusedFromCase();
  error UnknownAssertion();

  event MarketConfigured(
    bytes32 indexed questionId,
    uint64 cutoffTime,
    address indexed currency,
    uint256 bond,
    uint64 liveness,
    bytes32 rulesHash
  );
  event ReviewerQualificationUpdated(
    address indexed reviewer,
    bool qualified,
    bytes32 qualificationHash
  );
  event ReviewCommitteeConfigured(
    bytes32 indexed questionId,
    address indexed reviewer1,
    address indexed reviewer2,
    address reviewer3,
    bytes32 conflictDisclosureHash
  );
  event OutcomeAsserted(
    bytes32 indexed questionId,
    bytes32 indexed assertionId,
    address indexed asserter,
    Outcome outcome,
    uint256 bond
  );
  event AssertionDisputed(bytes32 indexed questionId, bytes32 indexed assertionId);
  event AssertionRejected(bytes32 indexed questionId, bytes32 indexed assertionId);
  event OutcomeChallenged(
    bytes32 indexed questionId,
    bytes32 indexed assertionId,
    address indexed challenger,
    bytes evidence,
    bytes32 evidenceHash,
    uint256 disputeBond,
    uint64 reviewDeadline
  );
  event ReviewVoteCast(
    bytes32 indexed questionId,
    address indexed reviewer,
    Outcome outcome,
    bytes evidence,
    bytes32 evidenceHash,
    uint8 validVotes
  );
  event ReviewerRecused(
    bytes32 indexed questionId,
    address indexed reviewer,
    bytes evidence,
    bytes32 evidenceHash
  );
  event ReviewFinalized(
    bytes32 indexed questionId,
    Outcome outcome,
    uint8 validVotes,
    uint8 yesVotes,
    uint8 noVotes,
    uint8 invalidVotes
  );
  event MarketResolved(
    bytes32 indexed questionId,
    bytes32 indexed assertionId,
    Outcome outcome
  );
  event ReviewBondAccrued(address indexed recipient, uint256 amount);
  event ReviewBondClaimed(address indexed recipient, uint256 amount);

  IConditionalTokens public conditionalTokens;
  ZeusMarketRegistry public marketRegistry;
  IOptimisticOracleV3 public optimisticOracle;
  address public riskReserve;

  mapping(bytes32 questionId => MarketConfig config) private marketConfigs;
  mapping(bytes32 questionId => bytes32 assertionId) public activeAssertionId;
  mapping(bytes32 assertionId => AssertionData data) public assertions;
  mapping(address reviewer => bool qualified) public qualifiedReviewers;
  mapping(address reviewer => bytes32 qualificationHash) public reviewerQualificationHash;
  mapping(bytes32 questionId => ReviewCase reviewCase) public reviewCases;
  mapping(bytes32 questionId => mapping(address reviewer => bool voted)) public reviewerHasVoted;
  mapping(bytes32 questionId => mapping(address reviewer => bool recused)) public reviewerRecused;
  mapping(bytes32 questionId => mapping(address reviewer => Outcome outcome)) public reviewerVotes;
  mapping(bytes32 questionId => mapping(address reviewer => bytes32 evidenceHash))
    public reviewerEvidenceHash;
  mapping(address recipient => uint256 amount) public claimableReviewBonds;
  mapping(bytes32 questionId => uint256 deadline) public reviewChallengeDeadlines;

  // Append-only storage: existing markets, assertions and bonds keep their layout.
  struct PolymarketMirrorConfig {
    address sourceOracle;
    bytes32 sourceQuestionId;
    bytes32 sourceConditionId;
    bytes32 sourceTermsHash;
    uint8 sourceYesIndex;
  }
  mapping(bytes32 questionId => PolymarketMirrorConfig config) public polymarketMirrorConfigs;
  bytes32 public constant POLYMARKET_RELAY_ROLE = keccak256("POLYMARKET_RELAY_ROLE");
  uint256 public constant POLYMARKET_SOURCE_CHAIN_ID = 137;
  address public constant POLYMARKET_SOURCE_CTF = 0x4D97DCd97eC945f40cF65F87097ACe5EA0476045;
  error MirrorModeRequired();
  error MirrorModeDisallowsLocalChallenge();
  error InvalidSourceBinding();
  event PolymarketSourceConfigured(bytes32 indexed questionId, bytes32 indexed sourceConditionId, bytes32 sourceTermsHash, uint8 sourceYesIndex);
  event PolymarketSourceResolved(bytes32 indexed questionId, bytes32 indexed sourceConditionId, uint64 sourceBlock, bytes32 sourceBlockHash, bytes32 evidenceHash, Outcome outcome);


  modifier validOracleConfiguration() {
    _checkOracleConfiguration();
    _;
  }

  function _checkOracleConfiguration() internal view {
    if (address(optimisticOracle) == address(0)) {
      revert InvalidConfiguration();
    }
  }

  /// @custom:oz-upgrades-unsafe-allow constructor
  constructor(
    address conditionalTokens_,
    address marketRegistry_,
    address optimisticOracle_,
    address riskReserve_,
    address initialAdmin
  ) {
    initialize(conditionalTokens_, marketRegistry_, optimisticOracle_, riskReserve_, initialAdmin);
    _disableInitializers();
  }

  function initialize(
    address conditionalTokens_,
    address marketRegistry_,
    address optimisticOracle_,
    address riskReserve_,
    address initialAdmin
  ) public initializer {
    if (
      conditionalTokens_ == address(0) || marketRegistry_ == address(0)
        || riskReserve_ == address(0) || optimisticOracle_ == address(0)
        || initialAdmin == address(0)
    ) {
      revert InvalidAddress();
    }

    __AccessControl_init();
    conditionalTokens = IConditionalTokens(conditionalTokens_);
    marketRegistry = ZeusMarketRegistry(marketRegistry_);
    optimisticOracle = IOptimisticOracleV3(optimisticOracle_);
    riskReserve = riskReserve_;
    _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);
    _grantRole(MARKET_CONFIG_ROLE, initialAdmin);
  }

  function setReviewerQualification(
    address reviewer,
    bool qualified,
    bytes32 qualificationHash
  ) external onlyRole(DEFAULT_ADMIN_ROLE) {
    if (reviewer == address(0)) revert InvalidAddress();
    if (qualified && qualificationHash == bytes32(0)) revert InvalidEvidence();

    qualifiedReviewers[reviewer] = qualified;
    reviewerQualificationHash[reviewer] = qualificationHash;
    emit ReviewerQualificationUpdated(reviewer, qualified, qualificationHash);
  }

  function configureMarket(
    bytes32 questionId,
    uint64 cutoffTime,
    address currency,
    uint256 bond,
    uint64 liveness,
    bytes calldata rules,
    address[3] calldata reviewers,
    bytes32 conflictDisclosureHash
  ) external onlyRole(MARKET_CONFIG_ROLE) validOracleConfiguration {
    if (
      currency == address(0) || currency != marketRegistry.collateralToken()
        || cutoffTime <= block.timestamp || liveness < MIN_LIVENESS || rules.length == 0
    ) {
      revert InvalidConfiguration();
    }
    if (!_validReviewCommittee(reviewers, conflictDisclosureHash)) {
      revert InvalidReviewCommittee();
    }
    if (marketConfigs[questionId].configured) revert MarketAlreadyConfigured();
    uint256 minimumBond = optimisticOracle.getMinimumBond(currency);
    uint256 configuredBond = bond > minimumBond ? bond : minimumBond;
    if (configuredBond > DISPUTE_BOND) {
      revert NativeDisputeBondExceedsLimit(configuredBond, DISPUTE_BOND);
    }

    bytes32 conditionId = conditionalTokens.getConditionId(address(this), questionId, 2);
    ZeusMarketRegistry.Market memory market = marketRegistry.getMarket(conditionId);
    if (
      !market.exists || market.oracle != address(this) || market.questionId != questionId
        || market.cutoffTime != cutoffTime || market.marketType != ZeusMarketRegistry.MarketType.Event
        || market.metadataHash != keccak256(rules)
        || conditionalTokens.getOutcomeSlotCount(conditionId) != 2
    ) {
      revert MarketRegistrationMismatch();
    }

    marketConfigs[questionId] = MarketConfig({
      currency: IERC20(currency),
      cutoffTime: cutoffTime,
      liveness: liveness,
      bond: bond,
      configured: true,
      resolved: false,
      rules: rules,
      reviewers: reviewers,
      conflictDisclosureHash: conflictDisclosureHash
    });
    emit MarketConfigured(questionId, cutoffTime, currency, bond, liveness, keccak256(rules));
    emit ReviewCommitteeConfigured(
      questionId,
      reviewers[0],
      reviewers[1],
      reviewers[2],
      conflictDisclosureHash
    );
  }

  function getPolymarketMirrorConfig(bytes32 questionId) external view returns (PolymarketMirrorConfig memory) { return polymarketMirrorConfigs[questionId]; }

  function polymarketMirrorVersion() external pure returns (uint256) { return 1; }

  /// @notice New automatic markets follow the source final payout with no local
  /// challenge. An authorized relay verifies Polygon; this is NOT a chain proof.
  /// Existing configured conditions cannot switch to this mode.
  function configurePolymarketMarket(
    bytes32 questionId, uint64 cutoffTime, address sourceOracle, bytes32 sourceQuestionId,
    bytes32 sourceConditionId, bytes32 sourceTermsHash, uint8 sourceYesIndex, bytes calldata rules
  ) external onlyRole(MARKET_CONFIG_ROLE) validOracleConfiguration {
    if (marketConfigs[questionId].configured) revert MarketAlreadyConfigured();
    if (cutoffTime <= block.timestamp || sourceQuestionId == bytes32(0) || sourceTermsHash == bytes32(0)
      || rules.length == 0 || sourceYesIndex > 1 || !_allowedPolymarketOracle(sourceOracle)
      || keccak256(abi.encodePacked(sourceOracle, sourceQuestionId, uint256(2))) != sourceConditionId) revert InvalidSourceBinding();
    bytes32 conditionId = conditionalTokens.getConditionId(address(this), questionId, 2);
    ZeusMarketRegistry.Market memory market = marketRegistry.getMarket(conditionId);
    if (!market.exists || market.oracle != address(this) || market.questionId != questionId
      || market.cutoffTime != cutoffTime || market.marketType != ZeusMarketRegistry.MarketType.Event
      || market.metadataHash != keccak256(rules) || conditionalTokens.getOutcomeSlotCount(conditionId) != 2
      || conditionalTokens.payoutDenominator(conditionId) != 0) revert MarketRegistrationMismatch();
    MarketConfig storage config = marketConfigs[questionId];
    config.cutoffTime = cutoffTime;
    config.configured = true;
    config.rules = rules;
    polymarketMirrorConfigs[questionId] = PolymarketMirrorConfig(sourceOracle, sourceQuestionId, sourceConditionId, sourceTermsHash, sourceYesIndex);
    emit PolymarketSourceConfigured(questionId, sourceConditionId, sourceTermsHash, sourceYesIndex);
  }

  function resolvePolymarketMarket(
    bytes32 questionId, bytes32 sourceConditionId, bytes32 sourceTermsHash, Outcome outcome,
    uint64 sourceBlock, bytes32 sourceBlockHash, bytes32 evidenceHash
  ) external onlyRole(POLYMARKET_RELAY_ROLE) nonReentrant validOracleConfiguration {
    PolymarketMirrorConfig storage mirror = polymarketMirrorConfigs[questionId];
    if (mirror.sourceConditionId == bytes32(0)) revert MirrorModeRequired();
    if (mirror.sourceConditionId != sourceConditionId || mirror.sourceTermsHash != sourceTermsHash
      || sourceBlock == 0 || sourceBlockHash == bytes32(0) || evidenceHash == bytes32(0)) revert InvalidSourceBinding();
    if (outcome == Outcome.Unset || uint8(outcome) > uint8(Outcome.Invalid)) revert InvalidOutcome();
    // Source finality may precede the fixed trading deadline. Registry derives
    // Resolved from CTF payouts first, immediately preventing further matching.
    _resolveMarket(questionId, bytes32(0), outcome);
    emit PolymarketSourceResolved(questionId, sourceConditionId, sourceBlock, sourceBlockHash, evidenceHash, outcome);
  }

  function _allowedPolymarketOracle(address oracle) private pure returns (bool) {
    return oracle == 0x65070BE91477460D8A7AeEb94ef92fe056C2f2A7
      || oracle == 0x157Ce2d672854c848c9b79C49a8Cc6cc89176a49
      || oracle == 0x6A9D222616C90FcA5754cd1333cFD9b7fb6a4F74
      || oracle == 0xCB1822859cEF82Cd2Eb4E6276C7916e692995130;
  }

  function getMarketConfig(bytes32 questionId) external view returns (MarketConfig memory) {
    return marketConfigs[questionId];
  }

  function requiredBond(bytes32 questionId) public view validOracleConfiguration returns (uint256) {
    if (polymarketMirrorConfigs[questionId].sourceConditionId != bytes32(0)) return 0;
    MarketConfig storage config = marketConfigs[questionId];
    if (!config.configured) revert MarketNotConfigured();

    uint256 minimumBond = optimisticOracle.getMinimumBond(address(config.currency));
    return config.bond > minimumBond ? config.bond : minimumBond;
  }

  function buildClaim(bytes32 questionId, Outcome outcome) external view returns (bytes memory) {
    MarketConfig storage config = marketConfigs[questionId];
    if (!config.configured) revert MarketNotConfigured();
    if (outcome == Outcome.Unset || uint8(outcome) > uint8(Outcome.Invalid)) revert InvalidOutcome();
    return _buildClaim(questionId, outcome, config.rules);
  }

  function assertOutcome(bytes32 questionId, Outcome outcome)
    external
    nonReentrant
    validOracleConfiguration
    returns (bytes32 assertionId)
  {
    if (polymarketMirrorConfigs[questionId].sourceConditionId != bytes32(0)) revert MirrorModeDisallowsLocalChallenge();
    MarketConfig storage config = marketConfigs[questionId];
    if (!config.configured) revert MarketNotConfigured();
    if (config.resolved) revert MarketAlreadyResolved();
    if (reviewCases[questionId].active || reviewCases[questionId].finalized) {
      revert ReviewAlreadyActive();
    }
    if (block.timestamp < config.cutoffTime) revert AssertionTooEarly();
    if (outcome == Outcome.Unset || uint8(outcome) > uint8(Outcome.Invalid)) revert InvalidOutcome();

    bytes32 currentAssertionId = activeAssertionId[questionId];
    if (currentAssertionId != bytes32(0)) revert ActiveAssertionExists(currentAssertionId);

    uint256 assertionBond = requiredBond(questionId);
    if (assertionBond > DISPUTE_BOND) {
      revert NativeDisputeBondExceedsLimit(assertionBond, DISPUTE_BOND);
    }
    if (assertionBond != 0) {
      config.currency.safeTransferFrom(msg.sender, address(this), assertionBond);
      config.currency.forceApprove(address(optimisticOracle), assertionBond);
    }

    assertionId = optimisticOracle.assertTruth(
      _buildClaim(questionId, outcome, config.rules),
      msg.sender,
      address(this),
      address(0),
      config.liveness,
      config.currency,
      assertionBond,
      optimisticOracle.defaultIdentifier(),
      questionId
    );
    activeAssertionId[questionId] = assertionId;
    assertions[assertionId] =
      AssertionData({
        questionId: questionId,
        outcome: outcome,
        asserter: msg.sender,
        bond: assertionBond,
        exists: true,
        aborted: false,
        assertedAt: uint64(block.timestamp)
      });

    emit OutcomeAsserted(questionId, assertionId, msg.sender, outcome, assertionBond);
  }

  function challengeOutcome(bytes32 questionId, bytes calldata evidence) external nonReentrant validOracleConfiguration {
    if (polymarketMirrorConfigs[questionId].sourceConditionId != bytes32(0)) revert MirrorModeDisallowsLocalChallenge();
    MarketConfig storage config = marketConfigs[questionId];
    if (!config.configured) revert MarketNotConfigured();
    if (config.resolved) revert MarketAlreadyResolved();
    if (evidence.length == 0 || evidence.length > MAX_EVIDENCE_BYTES) revert InvalidEvidence();
    bytes32 evidenceHash = keccak256(evidence);

    bytes32 assertionId = activeAssertionId[questionId];
    if (assertionId == bytes32(0)) revert NoActiveAssertion();
    AssertionData storage assertion = assertions[assertionId];
    if (block.timestamp >= uint256(assertion.assertedAt) + config.liveness) {
      revert ChallengeWindowClosed();
    }
    if (reviewCases[questionId].active || reviewCases[questionId].finalized) {
      revert ReviewAlreadyActive();
    }

    uint256 nativeDisputeBond = assertion.bond;
    if (nativeDisputeBond > DISPUTE_BOND) {
      revert NativeDisputeBondExceedsLimit(nativeDisputeBond, DISPUTE_BOND);
    }
    config.currency.safeTransferFrom(msg.sender, address(this), DISPUTE_BOND);
    _activateReview(
      questionId,
      assertionId,
      assertion.outcome,
      msg.sender,
      evidenceHash,
      DISPUTE_BOND - nativeDisputeBond
    );
    if (nativeDisputeBond != 0) {
      config.currency.forceApprove(address(optimisticOracle), nativeDisputeBond);
    }
    optimisticOracle.disputeAssertion(assertionId, msg.sender);
    emit OutcomeChallenged(
      questionId,
      assertionId,
      msg.sender,
      evidence,
      evidenceHash,
      DISPUTE_BOND,
      reviewCases[questionId].deadline
    );
  }

  function challengeDeadline(bytes32 questionId) external view returns (uint256) {
    bytes32 assertionId = activeAssertionId[questionId];
    if (assertionId == bytes32(0)) revert NoActiveAssertion();
    AssertionData storage assertion = assertions[assertionId];
    return uint256(assertion.assertedAt) + marketConfigs[questionId].liveness;
  }

  function activeAssertionOutcome(bytes32 questionId) external view returns (Outcome) {
    bytes32 assertionId = activeAssertionId[questionId];
    if (assertionId == bytes32(0)) revert NoActiveAssertion();
    return assertions[assertionId].outcome;
  }

  function castReviewVote(bytes32 questionId, Outcome outcome, bytes calldata evidence)
    external
    nonReentrant
    validOracleConfiguration
  {
    ReviewCase storage reviewCase = reviewCases[questionId];
    if (!reviewCase.active || reviewCase.finalized) revert ReviewNotActive();
    if (block.timestamp >= reviewCase.deadline) revert ReviewDeadlinePassed();
    if (outcome == Outcome.Unset || uint8(outcome) > uint8(Outcome.Invalid)) {
      revert InvalidOutcome();
    }
    if (evidence.length == 0 || evidence.length > MAX_EVIDENCE_BYTES) revert InvalidEvidence();
    bytes32 evidenceHash = keccak256(evidence);
    if (!_isSelectedReviewer(questionId, msg.sender)) revert NotSelectedReviewer();
    if (reviewerRecused[questionId][msg.sender]) revert ReviewerRecusedFromCase();
    if (reviewerHasVoted[questionId][msg.sender]) revert ReviewerAlreadyVoted();

    reviewerHasVoted[questionId][msg.sender] = true;
    reviewerVotes[questionId][msg.sender] = outcome;
    reviewerEvidenceHash[questionId][msg.sender] = evidenceHash;
    reviewCase.validVotes += 1;
    if (outcome == Outcome.Yes) reviewCase.yesVotes += 1;
    else if (outcome == Outcome.No) reviewCase.noVotes += 1;
    else reviewCase.invalidVotes += 1;
    emit ReviewVoteCast(
      questionId,
      msg.sender,
      outcome,
      evidence,
      evidenceHash,
      reviewCase.validVotes
    );

    _checkReviewQuorumAndFinalize(questionId);
  }

  function recuseFromReview(bytes32 questionId, bytes calldata evidence) external validOracleConfiguration {
    ReviewCase storage reviewCase = reviewCases[questionId];
    if (!reviewCase.active || reviewCase.finalized) revert ReviewNotActive();
    if (block.timestamp >= reviewCase.deadline) revert ReviewDeadlinePassed();
    if (evidence.length == 0 || evidence.length > MAX_EVIDENCE_BYTES) revert InvalidEvidence();
    if (!_isSelectedReviewer(questionId, msg.sender)) revert NotSelectedReviewer();
    if (reviewerHasVoted[questionId][msg.sender]) revert ReviewerAlreadyVoted();
    if (reviewerRecused[questionId][msg.sender]) revert ReviewerRecusedFromCase();

    bytes32 evidenceHash = keccak256(evidence);
    reviewerRecused[questionId][msg.sender] = true;
    reviewCase.recusedCount += 1;
    emit ReviewerRecused(questionId, msg.sender, evidence, evidenceHash);

    _checkReviewQuorumAndFinalize(questionId);
  }

  function _checkReviewQuorumAndFinalize(bytes32 questionId) internal {
    uint256 challengeEnd = reviewChallengeDeadlines[questionId];
    if (challengeEnd == 0 || block.timestamp < challengeEnd) return;
    ReviewCase storage reviewCase = reviewCases[questionId];
    uint8 recused = reviewCase.recusedCount;
    if (recused >= 2) {
      return;
    }
    uint8 requiredVotes = REVIEWER_COUNT - recused;
    if (reviewCase.validVotes < requiredVotes) return;

    if (uint256(reviewCase.yesVotes) * 3 >= uint256(reviewCase.validVotes) * 2) {
      _finalizeReview(questionId, Outcome.Yes, false);
    } else if (uint256(reviewCase.noVotes) * 3 >= uint256(reviewCase.validVotes) * 2) {
      _finalizeReview(questionId, Outcome.No, false);
    } else if (
      uint256(reviewCase.invalidVotes) * 3 >= uint256(reviewCase.validVotes) * 2
    ) {
      _finalizeReview(questionId, Outcome.Invalid, false);
    }
  }

  function finalizeReviewTimeout(bytes32 questionId) external nonReentrant validOracleConfiguration {
    ReviewCase storage reviewCase = reviewCases[questionId];
    if (!reviewCase.active || reviewCase.finalized) revert ReviewNotActive();
    uint256 challengeEnd = reviewChallengeDeadlines[questionId];
    if (challengeEnd == 0 || block.timestamp < challengeEnd) revert ChallengeWindowOpen();
    _checkReviewQuorumAndFinalize(questionId);
    if (!reviewCase.active) return;
    if (block.timestamp < reviewCase.deadline) revert ReviewDeadlineNotReached();
    _finalizeReview(questionId, Outcome.Invalid, true);
  }

  function claimReviewBond() external nonReentrant {
    _claimReviewBond(msg.sender);
  }

  /// @notice Anyone may deliver a credit to its owner, including a reserve vault.
  /// @dev The caller cannot choose another destination or claim another owner's credit.
  function claimReviewBondFor(address recipient) external nonReentrant {
    _claimReviewBond(recipient);
  }

  function _claimReviewBond(address recipient) internal {
    uint256 amount = claimableReviewBonds[recipient];
    if (amount == 0) revert NoClaimableBond();
    claimableReviewBonds[recipient] = 0;
    IERC20(marketRegistry.collateralToken()).safeTransfer(recipient, amount);
    emit ReviewBondClaimed(recipient, amount);
  }

  function settleMarket(bytes32 questionId) external nonReentrant validOracleConfiguration {
    if (polymarketMirrorConfigs[questionId].sourceConditionId != bytes32(0)) revert MirrorModeDisallowsLocalChallenge();
    MarketConfig storage config = marketConfigs[questionId];
    if (!config.configured) revert MarketNotConfigured();
    bytes32 assertionId = activeAssertionId[questionId];
    if (assertionId == bytes32(0)) revert NoActiveAssertion();
    AssertionData storage assertion = assertions[assertionId];
    if (
      !assertion.aborted && !config.resolved && !reviewCases[questionId].active
        && block.timestamp < uint256(assertion.assertedAt) + config.liveness
    ) {
      revert ChallengeWindowOpen();
    }

    optimisticOracle.settleAndGetAssertionResult(assertionId);
  }

  /// @notice 7大流盘场景（如赛事取消超时、数据源失效、预言机卡死）下的管理员应急中止接口
  function emergencyAbortMarket(bytes32 questionId) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant validOracleConfiguration {
    MarketConfig storage config = marketConfigs[questionId];
    if (!config.configured) revert MarketNotConfigured();
    if (config.resolved) revert MarketAlreadyResolved();

    bytes32 assertionId = activeAssertionId[questionId];
    if (assertionId != bytes32(0)) {
      assertions[assertionId].aborted = true;
    }
    ReviewCase storage reviewCase = reviewCases[questionId];
    if (reviewCase.active && !reviewCase.finalized) {
      _finalizeReview(questionId, Outcome.Invalid, true);
    } else {
      _resolveMarket(questionId, assertionId, Outcome.Invalid);
    }
  }

  function assertionResolvedCallback(bytes32 assertionId, bool assertedTruthfully) external validOracleConfiguration {
    _checkOracle();
    AssertionData memory assertion = assertions[assertionId];
    if (!assertion.exists || activeAssertionId[assertion.questionId] != assertionId) {
      revert UnknownAssertion();
    }
    MarketConfig storage config = marketConfigs[assertion.questionId];
    if (
      !assertion.aborted && !config.resolved && !reviewCases[assertion.questionId].active
        && block.timestamp < uint256(assertion.assertedAt) + config.liveness
    ) {
      revert ChallengeWindowOpen();
    }

    delete assertions[assertionId];
    delete activeAssertionId[assertion.questionId];
    if (assertion.aborted) {
      return;
    }
    if (config.resolved) return;
    if (reviewCases[assertion.questionId].active) {
      if (!assertedTruthfully) {
        emit AssertionRejected(assertion.questionId, assertionId);
      }
      return;
    }
    if (!assertedTruthfully) {
      emit AssertionRejected(assertion.questionId, assertionId);
      return;
    }
    _resolveMarket(assertion.questionId, assertionId, assertion.outcome);
  }

  function assertionDisputedCallback(bytes32 assertionId) external validOracleConfiguration {
    _checkOracle();
    AssertionData memory assertion = assertions[assertionId];
    if (!assertion.exists) revert UnknownAssertion();
    MarketConfig storage config = marketConfigs[assertion.questionId];
    if (block.timestamp >= uint256(assertion.assertedAt) + config.liveness) {
      revert ChallengeWindowClosed();
    }
    // challengeOutcome activates the review before calling the oracle. A direct
    // oracle dispute must not bypass the public evidence and 100 Zeusv bond.
    ReviewCase storage reviewCase = reviewCases[assertion.questionId];
    if (!reviewCase.active || reviewCase.challenger == address(0)) revert ReviewNotActive();
    emit AssertionDisputed(assertion.questionId, assertionId);
  }

  function _activateReview(
    bytes32 questionId,
    bytes32 assertionId,
    Outcome proposedOutcome,
    address challenger,
    bytes32 evidenceHash,
    uint256 disputeBond
  ) internal {
    uint64 challengedAt = uint64(block.timestamp);
    uint64 deadline = challengedAt + REVIEW_PERIOD;
    AssertionData storage assertion = assertions[assertionId];
    reviewChallengeDeadlines[questionId] =
      uint256(assertion.assertedAt) + marketConfigs[questionId].liveness;
    reviewCases[questionId] = ReviewCase({
      proposedOutcome: proposedOutcome,
      finalOutcome: Outcome.Unset,
      challenger: challenger,
      challengeEvidenceHash: evidenceHash,
      challengedAt: challengedAt,
      deadline: deadline,
      validVotes: 0,
      yesVotes: 0,
      noVotes: 0,
      invalidVotes: 0,
      recusedCount: 0,
      active: true,
      finalized: false,
      disputeBond: disputeBond
    });
  }

  function _finalizeReview(bytes32 questionId, Outcome outcome, bool refundDisputeBond) internal {
    ReviewCase storage reviewCase = reviewCases[questionId];
    reviewCase.active = false;
    reviewCase.finalized = true;
    reviewCase.finalOutcome = outcome;

    _resolveMarket(questionId, activeAssertionId[questionId], outcome);

    uint256 disputeBond = reviewCase.disputeBond;
    if (disputeBond != 0) {
      reviewCase.disputeBond = 0;
      address recipient = !refundDisputeBond && outcome == reviewCase.proposedOutcome
        ? riskReserve
        : reviewCase.challenger;
      claimableReviewBonds[recipient] += disputeBond;
      emit ReviewBondAccrued(recipient, disputeBond);
    }

    emit ReviewFinalized(
      questionId,
      outcome,
      reviewCase.validVotes,
      reviewCase.yesVotes,
      reviewCase.noVotes,
      reviewCase.invalidVotes
    );
  }

  function _resolveMarket(bytes32 questionId, bytes32 assertionId, Outcome outcome) internal {
    _checkOracleConfiguration();
    MarketConfig storage config = marketConfigs[questionId];
    if (config.resolved) revert MarketAlreadyResolved();
    config.resolved = true;

    uint256[] memory payouts = new uint256[](2);
    if (outcome == Outcome.Yes) {
      payouts[0] = 1;
    } else if (outcome == Outcome.No) {
      payouts[1] = 1;
    } else {
      payouts[0] = 1;
      payouts[1] = 1;
    }
    conditionalTokens.reportPayouts(questionId, payouts);
    emit MarketResolved(questionId, assertionId, outcome);
  }

  function _validReviewCommittee(
    address[3] calldata reviewers,
    bytes32 conflictDisclosureHash
  ) internal view returns (bool) {
    if (conflictDisclosureHash == bytes32(0)) return false;
    for (uint256 i; i < REVIEWER_COUNT; ++i) {
      address reviewer = reviewers[i];
      if (
        reviewer == address(0) || !qualifiedReviewers[reviewer]
          || hasRole(MARKET_CONFIG_ROLE, reviewer) || hasRole(DEFAULT_ADMIN_ROLE, reviewer)
      ) {
        return false;
      }
      for (uint256 j; j < i; ++j) {
        if (reviewers[j] == reviewer) return false;
      }
    }
    return true;
  }

  function _isSelectedReviewer(bytes32 questionId, address reviewer)
    internal
    view
    returns (bool)
  {
    address[3] storage reviewers = marketConfigs[questionId].reviewers;
    for (uint256 i; i < REVIEWER_COUNT; ++i) {
      if (reviewers[i] == reviewer) return true;
    }
    return false;
  }

  function _checkOracle() internal view {
    if (msg.sender != address(optimisticOracle)) revert OnlyOptimisticOracle();
  }

  function _buildClaim(bytes32 questionId, Outcome outcome, bytes storage rules)
    internal
    view
    returns (bytes memory)
  {
    return abi.encodePacked(
      rules,
      "\nassertedOutcome:",
      _outcomeName(outcome),
      "\nquestionId:",
      Strings.toHexString(uint256(questionId), 32),
      "\nchainId:",
      Strings.toString(block.chainid),
      "\nadapter:",
      Strings.toHexString(uint160(address(this)), 20)
    );
  }

  function _outcomeName(Outcome outcome) internal pure returns (string memory) {
    if (outcome == Outcome.Yes) return "YES";
    if (outcome == Outcome.No) return "NO";
    return "INVALID";
  }
}
