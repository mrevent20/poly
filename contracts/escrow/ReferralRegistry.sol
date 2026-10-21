// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";

/// @title Referral Registry
/// @notice 单级推荐关系登记。
/// @dev 用户只能绑定一个直接推荐人，后续费率分成逻辑可读取该关系，避免多级分销结构。
contract ReferralRegistry is Initializable {
  /// @custom:oz-upgrades-unsafe-allow constructor
  constructor() {
    _disableInitializers();
  }

  function initialize() external initializer {}
  error InvalidReferrer();
  error ReferrerAlreadyBound(address user);

  event ReferrerBound(address indexed user, address indexed referrer);

  mapping(address user => address referrer) public referrerOf;

  function bindReferrer(address referrer) external {
    if (referrer == address(0) || referrer == msg.sender) revert InvalidReferrer();
    if (referrerOf[msg.sender] != address(0)) revert ReferrerAlreadyBound(msg.sender);

    referrerOf[msg.sender] = referrer;
    emit ReferrerBound(msg.sender, referrer);
  }
}
