// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

/// @notice Price-market oracle hook used by the registry to ensure that a
///         market cannot open before its immutable resolution terms exist.
interface IPriceMarketOracle {
  function validateMarketRegistration(bytes32 questionId, uint64 cutoffTime, bytes32 metadataHash)
    external
    view
    returns (bool);
}
