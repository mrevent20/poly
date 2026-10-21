// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {VestingWallet} from "@openzeppelin/contracts/finance/VestingWallet.sol";
import {VestingWalletCliff} from "@openzeppelin/contracts/finance/VestingWalletCliff.sol";

/// @title Zeusv Vesting Wallet
/// @notice 继承 OpenZeppelin VestingWalletCliff 的锁仓释放金库。
/// @dev Cliff 期间释放量为 0，Cliff 结束后才在剩余时长内线性释放。
contract ZeusvVestingWallet is VestingWalletCliff {
    /// @param beneficiary 代币接收受益人
    /// @param startTimestamp 锁仓起始时间戳（通常为 TGE 时间）
    /// @param durationSeconds 释放总时长（包含 Cliff 时间）
    /// @param cliffSeconds 锁定期时长（在此期间释放量为 0）
    constructor(
        address beneficiary,
        uint64 startTimestamp,
        uint64 durationSeconds,
        uint64 cliffSeconds
    )
        payable
        VestingWallet(beneficiary, startTimestamp, durationSeconds)
        VestingWalletCliff(cliffSeconds)
    {}

    /// @dev OpenZeppelin 的默认 Cliff 只是在断崖前隐藏已累计的线性释放量，
    /// 断崖时会一次性释放前段份额。白皮书要求“锁定期结束后开始线性释放”，
    /// 因此这里将线性曲线的起点移到 cliff()，终点仍为 end()。
    function _vestingSchedule(
        uint256 totalAllocation,
        uint64 timestamp
    ) internal view virtual override returns (uint256) {
        uint256 releaseStart = cliff();
        if (timestamp <= releaseStart) {
            return 0;
        }

        uint256 releaseEnd = end();
        if (timestamp >= releaseEnd) {
            return totalAllocation;
        }

        uint256 releaseDuration = releaseEnd - releaseStart;
        return (totalAllocation * (timestamp - releaseStart)) / releaseDuration;
    }
}
