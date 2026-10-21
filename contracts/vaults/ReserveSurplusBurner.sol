// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import {RiskReserveVault} from "./RiskReserveVault.sol";

/// @title Reserve Surplus Burner
/// @notice 授权执行者将超过保留门槛的 MONO 准备金转入黑洞地址。
/// @dev 转账仍受准备金金库的最低储备、滚动日限额和暂停约束。
///      本操作不调用 ERC20 burn，不减少 totalSupply，也不进行 DEX 回购。
contract ReserveSurplusBurner is AccessControlUpgradeable, ReentrancyGuard {
  using SafeERC20 for IERC20;

  bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");
  address public constant DEAD_ADDRESS = 0x000000000000000000000000000000000000dEaD;

  error InvalidAddress();
  error CollateralTokenMismatch();
  error ZeroAmount();
  error ReserveThresholdNotMet(uint256 currentBalance, uint256 threshold);

  event SurplusTransferredToDead(
    address indexed token,
    uint256 amount,
    uint256 timestamp
  );
  event BurnThresholdUpdated(uint256 oldThreshold, uint256 newThreshold);

  RiskReserveVault public reserveVault;
  IERC20 public collateralToken;
  uint256 public burnThreshold;

  /// @custom:oz-upgrades-unsafe-allow constructor
  constructor(
    address reserveVault_,
    address collateralToken_,
    uint256 burnThreshold_,
    address initialAdmin
  ) {
    initialize(reserveVault_, collateralToken_, burnThreshold_, initialAdmin);
    _disableInitializers();
  }

  function initialize(
    address reserveVault_,
    address collateralToken_,
    uint256 burnThreshold_,
    address initialAdmin
  ) public initializer {
    if (reserveVault_.code.length == 0 || collateralToken_.code.length == 0 || initialAdmin == address(0)) {
      revert InvalidAddress();
    }
    if (address(RiskReserveVault(reserveVault_).collateralToken()) != collateralToken_) {
      revert CollateralTokenMismatch();
    }

    __AccessControl_init();
    reserveVault = RiskReserveVault(reserveVault_);
    collateralToken = IERC20(collateralToken_);
    burnThreshold = burnThreshold_;

    _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);
    _grantRole(BURNER_ROLE, initialAdmin);
  }

  /// @notice 将超额准备金转入 DEAD_ADDRESS。
  /// @param amount 本次从准备金金库提取并转入黑洞地址的 MONO 数量。
  function executeBurn(uint256 amount) external onlyRole(BURNER_ROLE) nonReentrant {
    if (amount == 0) revert ZeroAmount();

    uint256 vaultBalance = collateralToken.balanceOf(address(reserveVault));
    if (vaultBalance < burnThreshold || amount > vaultBalance - burnThreshold) {
      revert ReserveThresholdNotMet(vaultBalance, burnThreshold);
    }

    // 从准备金金库提取资金 (需金库赋予本合约 SPENDER_ROLE)
    reserveVault.withdraw(address(this), amount);

    // 白皮书 7.3：将直接收取的 MONO 转入销毁地址。
    collateralToken.safeTransfer(DEAD_ADDRESS, amount);
    emit SurplusTransferredToDead(address(collateralToken), amount, block.timestamp);
  }

  function setBurnThreshold(uint256 newThreshold) external onlyRole(DEFAULT_ADMIN_ROLE) {
    uint256 oldThreshold = burnThreshold;
    burnThreshold = newThreshold;
    emit BurnThresholdUpdated(oldThreshold, newThreshold);
  }
}
