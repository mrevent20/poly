// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";

/// @title Compliance Registry
/// @notice 链上 AML / KYC 合规门控。
/// @dev 通过黑名单和高额交易 KYC 有效期控制账户是否可以继续交易，交易前会检查
///      账户是否处于 block state 或是否已过高价值阈值的校验窗口。
contract ComplianceRegistry is AccessControlUpgradeable {
  bytes32 public constant COMPLIANCE_ROLE = keccak256("COMPLIANCE_ROLE");

  error InvalidAddress();

  event AccountBlocked(address indexed account, bool blocked);
  event KycValidityUpdated(address indexed account, uint64 validUntil);
  event HighValueThresholdUpdated(uint256 oldThreshold, uint256 newThreshold);

  uint256 public highValueThreshold;
  mapping(address account => bool isBlocked) public blocked;
  mapping(address account => uint64 validUntil) public kycValidUntil;

  /// @custom:oz-upgrades-unsafe-allow constructor
  constructor(uint256 highValueThreshold_, address initialAdmin) {
    initialize(highValueThreshold_, initialAdmin);
    _disableInitializers();
  }

  function initialize(uint256 highValueThreshold_, address initialAdmin) public initializer {
    if (initialAdmin == address(0)) revert InvalidAddress();

    __AccessControl_init();
    highValueThreshold = highValueThreshold_;
    _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);
    _grantRole(COMPLIANCE_ROLE, initialAdmin);
  }

  function setBlocked(address account, bool isBlocked) external onlyRole(COMPLIANCE_ROLE) {
    if (account == address(0)) revert InvalidAddress();

    blocked[account] = isBlocked;
    emit AccountBlocked(account, isBlocked);
  }

  function setKycValidUntil(address account, uint64 validUntil) external onlyRole(COMPLIANCE_ROLE) {
    if (account == address(0)) revert InvalidAddress();

    kycValidUntil[account] = validUntil;
    emit KycValidityUpdated(account, validUntil);
  }

  function setHighValueThreshold(uint256 newThreshold) external onlyRole(DEFAULT_ADMIN_ROLE) {
    uint256 oldThreshold = highValueThreshold;
    highValueThreshold = newThreshold;
    emit HighValueThresholdUpdated(oldThreshold, newThreshold);
  }

  function canTrade(address account, uint256 tradeValue) external view returns (bool) {
    if (blocked[account]) return false;
    if (tradeValue < highValueThreshold) return true;
    return kycValidUntil[account] >= block.timestamp;
  }
}
