// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {ZeusvAllocationVault} from "./ZeusvAllocationVault.sol";
import {ZeusvVestingWallet} from "./ZeusvVestingWallet.sol";

/// @title Zeusv Token Distributor
/// @notice 依照 MONOPOLY Protocol 白皮书第 6.2 节将 10 亿 Zeusv 分发至 9 大指定资金池与锁仓金库。
/// @dev 采用 OpenZeppelin 安全标准，固化白皮书第 11-13 页全部锁仓时间表与配额，杜绝超发或篡改。
contract ZeusvDistributor is Ownable2Step {
    using SafeERC20 for IERC20;

    IERC20 public immutable token;
    uint64 public immutable startTimestamp; // 最早可执行分发的时间
    uint64 public tgeTimestamp; // 实际分发交易时间，所有锁仓曲线从此刻起算
    bool public distributed;

    // --- 白皮书第 6.2 节 9 大池配额常量（总计严格等于 10 亿） ---
    uint256 public constant USER_INCENTIVES_ALLOCATION = 280_000_000 * 10 ** 18; // 28.0%
    uint256 public constant RWA_ECOSYSTEM_ALLOCATION   = 150_000_000 * 10 ** 18; // 15.0%
    uint256 public constant BUILDERS_ALLOCATION        = 120_000_000 * 10 ** 18; // 12.0%
    uint256 public constant TREASURY_ALLOCATION        = 118_000_000 * 10 ** 18; // 11.8%
    uint256 public constant STRATEGIC_ALLOCATION       = 100_000_000 * 10 ** 18; // 10.0%
    uint256 public constant LIQUIDITY_ALLOCATION       = 100_000_000 * 10 ** 18; // 10.0%
    uint256 public constant RISK_RESERVE_ALLOCATION    =  80_000_000 * 10 ** 18; //  8.0%
    uint256 public constant PARTNERS_ALLOCATION        =  40_000_000 * 10 ** 18; //  4.0%
    uint256 public constant PARTNERS_TGE_ALLOCATION    =   4_000_000 * 10 ** 18; //  0.4%
    uint256 public constant PARTNERS_VESTING_ALLOCATION = PARTNERS_ALLOCATION - PARTNERS_TGE_ALLOCATION; // 3.6%
    uint256 public constant LAUNCH_ALLOCATION          =  12_000_000 * 10 ** 18; //  1.2%
    uint256 public constant TOTAL_SUPPLY               = 1_000_000_000 * 10 ** 18; // 100.0%

    // --- 锁仓周期常量（白皮书第 13 页标准时间） ---
    uint64 public constant MONTH = 30 days;
    uint64 public constant CLIFF_6_MONTHS      = 6 * MONTH;   // 180 天
    uint64 public constant CLIFF_12_MONTHS     = 12 * MONTH;  // 360 天
    uint64 public constant DURATION_24_MONTHS  = 24 * MONTH;  // 720 天
    uint64 public constant DURATION_30_MONTHS  = 30 * MONTH;  // 6 个月锁仓 + 24 个月释放
    uint64 public constant DURATION_48_MONTHS  = 48 * MONTH;  // 12 个月锁仓 + 36 个月释放
    uint64 public constant DURATION_60_MONTHS  = 60 * MONTH;  // 12 个月锁仓 + 48 个月释放

    // 部署生成的独立锁仓金库合约地址
    ZeusvVestingWallet public strategicVestingWallet;
    ZeusvVestingWallet public buildersVestingWallet;
    ZeusvVestingWallet public rwaVestingWallet;
    ZeusvVestingWallet public treasuryVestingWallet;
    ZeusvVestingWallet public partnersVestingWallet;
    ZeusvAllocationVault public liquidityVault;
    ZeusvAllocationVault public userIncentivesVault;

    struct DistributionRecipients {
        address launchRecipient;         // 生态启动 1.2% (12M, TGE 100%)
        address riskReserveVault;        // 风险准备金 8% (80M 存入专项金库)
        address liquidityController;     // 交易流动性规则执行方（资金进入专用金库）
        address userIncentivesController;// 用户激励规则执行方（资金进入专用金库）
        address strategicBeneficiary;    // 战略协同 10% (100M, 锁6月放24月)
        address buildersBeneficiary;     // 建设者 12% (120M, 锁12月放36月)
        address rwaBeneficiary;          // RWA生态 15% (150M, 锁12月放36月)
        address treasuryBeneficiary;     // 国库发展 11.8% (118M, 锁12月放48月)
        address partnersController;      // 合作伙伴 0.4% TGE 接收人及剩余 3.6% 锁仓受益人
    }

    event TokenDistributed(
        address strategicVesting,
        address buildersVesting,
        address rwaVesting,
        address treasuryVesting,
        address liquidityAllocationVault,
        address userIncentivesAllocationVault,
        address partnersVesting
    );

    error AlreadyDistributed();
    error ZeroAddress();
    error InsufficientBalance();
    error InvalidStartTimestamp();
    error DistributionBeforeStart();
    error InvalidReserveVault();

    /// @param token_ ZeusvToken 合约地址
    /// @param startTimestamp_ 最早可执行分发的时间；实际 TGE 为成功分发交易的区块时间
    /// @param initialOwner 管理员多签地址
    constructor(
        address token_,
        uint64 startTimestamp_,
        address initialOwner
    ) Ownable(initialOwner) {
        if (token_ == address(0)) revert ZeroAddress();
        if (startTimestamp_ < block.timestamp) revert InvalidStartTimestamp();
        token = IERC20(token_);
        startTimestamp = startTimestamp_;
    }

    /// @notice 一键将 10 亿代币按白皮书精确划分并注入各独立锁仓与分配金库
    function distribute(DistributionRecipients calldata recipients) external onlyOwner {
        if (distributed) revert AlreadyDistributed();
        if (block.timestamp < startTimestamp) revert DistributionBeforeStart();
        if (
            recipients.launchRecipient == address(0) ||
            recipients.riskReserveVault == address(0) ||
            recipients.liquidityController == address(0) ||
            recipients.userIncentivesController == address(0) ||
            recipients.strategicBeneficiary == address(0) ||
            recipients.buildersBeneficiary == address(0) ||
            recipients.rwaBeneficiary == address(0) ||
            recipients.treasuryBeneficiary == address(0) ||
            recipients.partnersController == address(0)
        ) {
            revert ZeroAddress();
        }
        if (recipients.riskReserveVault.code.length == 0) revert InvalidReserveVault();

        if (token.balanceOf(address(this)) < TOTAL_SUPPLY) {
            revert InsufficientBalance();
        }

        distributed = true;
        uint64 actualTgeTimestamp = uint64(block.timestamp);
        tgeTimestamp = actualTgeTimestamp;

        // 1. TGE 直接划转生态启动 1.2% 与合作伙伴 0.4%；风险准备金进入受限专项金库。
        token.safeTransfer(recipients.launchRecipient, LAUNCH_ALLOCATION);
        token.safeTransfer(recipients.partnersController, PARTNERS_TGE_ALLOCATION);
        token.safeTransfer(recipients.riskReserveVault, RISK_RESERVE_ALLOCATION);

        // 2. 无固定线性计划的额度进入带证据哈希的专用分配金库。
        liquidityVault = new ZeusvAllocationVault(
            address(token), recipients.liquidityController, actualTgeTimestamp
        );
        userIncentivesVault = new ZeusvAllocationVault(
            address(token), recipients.userIncentivesController, actualTgeTimestamp
        );
        token.safeTransfer(address(liquidityVault), LIQUIDITY_ALLOCATION);
        token.safeTransfer(address(userIncentivesVault), USER_INCENTIVES_ALLOCATION);

        // 3. 部署 OpenZeppelin VestingWalletCliff 锁仓金库并注资
        // 3.1 战略协同：6个月Cliff，总时长30个月，100,000,000 Zeusv
        strategicVestingWallet = new ZeusvVestingWallet(
            recipients.strategicBeneficiary,
            actualTgeTimestamp,
            DURATION_30_MONTHS,
            CLIFF_6_MONTHS
        );
        token.safeTransfer(address(strategicVestingWallet), STRATEGIC_ALLOCATION);

        // 3.2 建设者：12个月Cliff，总时长48个月，120,000,000 Zeusv
        buildersVestingWallet = new ZeusvVestingWallet(
            recipients.buildersBeneficiary,
            actualTgeTimestamp,
            DURATION_48_MONTHS,
            CLIFF_12_MONTHS
        );
        token.safeTransfer(address(buildersVestingWallet), BUILDERS_ALLOCATION);

        // 3.3 RWA生态：12个月Cliff，总时长48个月，150,000,000 Zeusv
        rwaVestingWallet = new ZeusvVestingWallet(
            recipients.rwaBeneficiary,
            actualTgeTimestamp,
            DURATION_48_MONTHS,
            CLIFF_12_MONTHS
        );
        token.safeTransfer(address(rwaVestingWallet), RWA_ECOSYSTEM_ALLOCATION);

        // 3.4 国库发展：12个月Cliff，总时长60个月，118,000,000 Zeusv
        treasuryVestingWallet = new ZeusvVestingWallet(
            recipients.treasuryBeneficiary,
            actualTgeTimestamp,
            DURATION_60_MONTHS,
            CLIFF_12_MONTHS
        );
        token.safeTransfer(address(treasuryVestingWallet), TREASURY_ALLOCATION);

        // 3.5 合作伙伴：4,000,000 Zeusv 已直接划转，剩余 36,000,000 Zeusv 自实际 TGE 起 24 个月线性释放。
        partnersVestingWallet = new ZeusvVestingWallet(
            recipients.partnersController,
            actualTgeTimestamp,
            DURATION_24_MONTHS,
            0
        );
        token.safeTransfer(address(partnersVestingWallet), PARTNERS_VESTING_ALLOCATION);

        emit TokenDistributed(
            address(strategicVestingWallet),
            address(buildersVestingWallet),
            address(rwaVestingWallet),
            address(treasuryVestingWallet),
            address(liquidityVault),
            address(userIncentivesVault),
            address(partnersVestingWallet)
        );
    }
}
