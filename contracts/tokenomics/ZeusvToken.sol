// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Burnable} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import {ERC20Pausable} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Pausable.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {ERC20Votes} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Votes.sol";
import {Nonces} from "@openzeppelin/contracts/utils/Nonces.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";

/// @title MonoPoly (MONO) Token
/// @notice MONOPOLY Protocol 唯一价值结算与功能代币。
/// @dev 严格依照白皮书第 6、7、9、10 节设计，采用 OpenZeppelin 工业级标准模块：
///      1. 固定最大总量 10 亿枚（白皮书 6.2 节），构造时一次性铸造，永久关闭增发接口；
///      2. 链上治理投票权（白皮书 6.1/9 节）：支持区块快照检查点（Checkpoints）与免 Gas 签名委托（ERC20Votes）；
///      3. 安全熔断与紧急暂停（白皮书 9/10 节）：遭遇严重安全事件或异常波动时支持多签暂停（ERC20Pausable）；
///      4. 费用回流与代币销毁（白皮书 7.3 节）：支持直接打入黑洞与销毁扣减（ERC20Burnable）；
///      5. 离线免 Gas 签名授权（白皮书 4.2 节）：原生支持 EIP-2612 Permit，与自托管钱包深度集成；
///      6. 两步多签所有权移交（白皮书 10 节）：Ownable2Step 防误操作安全机制。
contract ZeusvToken is ERC20, ERC20Burnable, ERC20Pausable, ERC20Permit, ERC20Votes, Ownable2Step {
    /// @notice 最大供应量：严格限定 10 亿枚 (18 位精度)
    uint256 public constant MAX_SUPPLY = 1_000_000_000 * 10 ** 18;

    error InvalidRecipient();

    /// @param initialRecipient 初始 10 亿枚代币接收地址（通常为锁仓分发金库或多签冷钱包）
    /// @param initialOwner 管理员地址（通常为社区多签安全委员会）
    constructor(address initialRecipient, address initialOwner)
        ERC20("MonoPoly", "MONO")
        ERC20Permit("MonoPoly")
        Ownable(initialOwner)
    {
        if (initialRecipient == address(0)) revert InvalidRecipient();
        _mint(initialRecipient, MAX_SUPPLY);
    }

    /// @notice 紧急安全暂停全网转账（白皮书第 9/10 节应急安全风控）
    function pause() external onlyOwner {
        _pause();
    }

    /// @notice 风险排除后恢复全网转账
    function unpause() external onlyOwner {
        _unpause();
    }

    // --- OpenZeppelin 内部状态多继承覆写 ---

    function _update(address from, address to, uint256 value)
        internal
        override(ERC20, ERC20Pausable, ERC20Votes)
    {
        super._update(from, to, value);
    }

    function nonces(address owner)
        public
        view
        override(ERC20Permit, Nonces)
        returns (uint256)
    {
        return super.nonces(owner);
    }
}
