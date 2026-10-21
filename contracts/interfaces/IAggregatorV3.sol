// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

interface IAggregatorV3 {
  function getRoundData(uint80 roundId)
    external
    view
    returns (uint80, int256, uint256, uint256, uint80);
}