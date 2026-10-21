// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface IOptimisticOracleV3 {
  function assertTruth(
    bytes memory claim,
    address asserter,
    address callbackRecipient,
    address escalationManager,
    uint64 liveness,
    IERC20 currency,
    uint256 bond,
    bytes32 identifier,
    bytes32 domainId
  ) external returns (bytes32 assertionId);

  function defaultIdentifier() external view returns (bytes32);

  function disputeAssertion(bytes32 assertionId, address disputer) external;

  function getMinimumBond(address currency) external view returns (uint256);

  function settleAndGetAssertionResult(bytes32 assertionId) external returns (bool);
}

interface IOptimisticOracleV3CallbackRecipient {
  function assertionResolvedCallback(bytes32 assertionId, bool assertedTruthfully) external;

  function assertionDisputedCallback(bytes32 assertionId) external;
}
