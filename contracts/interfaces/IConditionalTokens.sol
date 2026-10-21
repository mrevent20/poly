// SPDX-License-Identifier: LGPL-3.0-or-later
pragma solidity ^0.8.34;

interface IConditionalTokens {
  function prepareCondition(address oracle, bytes32 questionId, uint256 outcomeSlotCount) external;

  function getConditionId(address oracle, bytes32 questionId, uint256 outcomeSlotCount)
    external
    pure
    returns (bytes32);

  function getCollectionId(bytes32 parentCollectionId, bytes32 conditionId, uint256 indexSet)
    external
    view
    returns (bytes32);

  function getPositionId(address collateralToken, bytes32 collectionId) external pure returns (uint256);

  function getOutcomeSlotCount(bytes32 conditionId) external view returns (uint256);

  function payoutNumerators(bytes32 conditionId, uint256 outcomeIndex) external view returns (uint256);

  function payoutDenominator(bytes32 conditionId) external view returns (uint256);

  function safeTransferFrom(address from, address to, uint256 id, uint256 value, bytes calldata data) external;

  function splitPosition(
    address collateralToken,
    bytes32 parentCollectionId,
    bytes32 conditionId,
    uint256[] calldata partition,
    uint256 amount
  ) external;

  function mergePositions(
    address collateralToken,
    bytes32 parentCollectionId,
    bytes32 conditionId,
    uint256[] calldata partition,
    uint256 amount
  ) external;

  function reportPayouts(bytes32 questionId, uint256[] calldata payouts) external;
}