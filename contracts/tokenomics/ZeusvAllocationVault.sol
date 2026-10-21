// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title Zeusv Allocation Vault
/// @notice Custodies a non-circulating allocation and records evidence for each approved release.
/// @dev The evidence hash anchors the applicable public campaign, liquidity rule, or milestone record.
contract ZeusvAllocationVault is AccessControl, ReentrancyGuard {
  using SafeERC20 for IERC20;

  bytes32 public constant RELEASER_ROLE = keccak256("RELEASER_ROLE");

  error InvalidAddress();
  error ZeroAmount();
  error AllocationLocked(uint64 unlockTimestamp);
  error MissingEvidence();

  event AllocationReleased(
    address indexed recipient, uint256 amount, bytes32 indexed evidenceHash
  );

  IERC20 public immutable token;
  uint64 public immutable unlockTimestamp;
  uint256 public releasedAmount;

  constructor(address token_, address controller, uint64 unlockTimestamp_) {
    if (token_ == address(0) || controller == address(0)) revert InvalidAddress();
    token = IERC20(token_);
    unlockTimestamp = unlockTimestamp_;
    _grantRole(DEFAULT_ADMIN_ROLE, controller);
    _grantRole(RELEASER_ROLE, controller);
  }

  function release(address recipient, uint256 amount, bytes32 evidenceHash)
    external
    onlyRole(RELEASER_ROLE)
    nonReentrant
  {
    if (recipient == address(0)) revert InvalidAddress();
    if (amount == 0) revert ZeroAmount();
    if (block.timestamp < unlockTimestamp) revert AllocationLocked(unlockTimestamp);
    if (evidenceHash == bytes32(0)) revert MissingEvidence();

    releasedAmount += amount;
    token.safeTransfer(recipient, amount);
    emit AllocationReleased(recipient, amount, evidenceHash);
  }
}
