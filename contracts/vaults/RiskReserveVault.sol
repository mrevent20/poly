// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title Risk Reserve Vault
/// @notice 预测市场的风险准备金金库。
/// @dev 该合约保管协议准备金，限制 24 小时支出上限，并要求在保留最低储备后才允许提取，
///      用于支撑极端市场亏损兜底和异常事件的资金垫付。
contract RiskReserveVault is AccessControlUpgradeable, PausableUpgradeable, ReentrancyGuard {
  using SafeERC20 for IERC20;

  bytes32 public constant SPENDER_ROLE = keccak256("SPENDER_ROLE");
  uint256 public constant WINDOW_DURATION = 1 days;

  error InvalidAddress();
  error ZeroAmount();
  error DailyLimitExceeded();
  error MinimumReserveViolated();

  event Withdrawal(address indexed recipient, uint256 amount);
  event LimitsUpdated(uint256 minimumReserve, uint256 dailyLimit);

  struct WithdrawalCheckpoint {
    uint64 timestamp;
    uint256 cumulativeAmount;
  }

  IERC20 public collateralToken;
  uint256 public minimumReserve;
  uint256 public dailyLimit;
  uint64 public windowStart;
  uint256 public totalWithdrawn;
  WithdrawalCheckpoint[] private withdrawalCheckpoints;

  /// @custom:oz-upgrades-unsafe-allow constructor
  constructor(address collateralToken_, uint256 minimumReserve_, uint256 dailyLimit_, address initialAdmin) {
    initialize(collateralToken_, minimumReserve_, dailyLimit_, initialAdmin);
    _disableInitializers();
  }

  function initialize(address collateralToken_, uint256 minimumReserve_, uint256 dailyLimit_, address initialAdmin)
    public initializer
  {
    if (collateralToken_ == address(0) || initialAdmin == address(0)) revert InvalidAddress();

    __AccessControl_init();
    __Pausable_init();
    collateralToken = IERC20(collateralToken_);
    minimumReserve = minimumReserve_;
    dailyLimit = dailyLimit_;
    windowStart = uint64(block.timestamp);
    _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);
  }

  function withdraw(address recipient, uint256 amount)
    external
    onlyRole(SPENDER_ROLE)
    whenNotPaused
    nonReentrant
  {
    if (recipient == address(0)) revert InvalidAddress();
    if (amount == 0) revert ZeroAmount();

    (uint256 rollingSpent, uint256 firstActiveIndex) = _rollingSpentAt(block.timestamp);
    if (rollingSpent + amount > dailyLimit) revert DailyLimitExceeded();

    uint256 balance = collateralToken.balanceOf(address(this));
    if (amount > balance || balance - amount < minimumReserve) revert MinimumReserveViolated();

    totalWithdrawn += amount;
    uint256 checkpointCount = withdrawalCheckpoints.length;
    if (
      checkpointCount != 0
        && withdrawalCheckpoints[checkpointCount - 1].timestamp == uint64(block.timestamp)
    ) {
      withdrawalCheckpoints[checkpointCount - 1].cumulativeAmount = totalWithdrawn;
    } else {
      withdrawalCheckpoints.push(
        WithdrawalCheckpoint({timestamp: uint64(block.timestamp), cumulativeAmount: totalWithdrawn})
      );
    }
    windowStart = firstActiveIndex < checkpointCount
      ? withdrawalCheckpoints[firstActiveIndex].timestamp
      : uint64(block.timestamp);
    collateralToken.safeTransfer(recipient, amount);
    emit Withdrawal(recipient, amount);
  }

  function spentInWindow() external view returns (uint256 rollingSpent) {
    (rollingSpent,) = _rollingSpentAt(block.timestamp);
  }

  function _rollingSpentAt(uint256 timestamp)
    internal
    view
    returns (uint256 rollingSpent, uint256 firstActiveIndex)
  {
    uint256 checkpointCount = withdrawalCheckpoints.length;
    if (checkpointCount == 0) return (0, 0);

    uint256 cutoff = timestamp > WINDOW_DURATION ? timestamp - WINDOW_DURATION : 0;
    uint256 low;
    uint256 high = checkpointCount;
    while (low < high) {
      uint256 mid = (low + high) / 2;
      if (withdrawalCheckpoints[mid].timestamp <= cutoff) {
        low = mid + 1;
      } else {
        high = mid;
      }
    }

    firstActiveIndex = low;
    uint256 expiredCumulative = low == 0 ? 0 : withdrawalCheckpoints[low - 1].cumulativeAmount;
    rollingSpent = totalWithdrawn - expiredCumulative;
  }

  function setLimits(uint256 minimumReserve_, uint256 dailyLimit_)
    external
    onlyRole(DEFAULT_ADMIN_ROLE)
  {
    minimumReserve = minimumReserve_;
    dailyLimit = dailyLimit_;
    emit LimitsUpdated(minimumReserve_, dailyLimit_);
  }

  function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
    _pause();
  }

  function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
    _unpause();
  }
}
