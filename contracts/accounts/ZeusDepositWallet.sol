// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC1155} from "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import {ERC1155Holder} from "@openzeppelin/contracts/token/ERC1155/utils/ERC1155Holder.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title Zeus Deposit Wallet
/// @notice User-owned funding account whose transactions can be submitted by a gas-paying relayer.
/// @dev The relayer has no authority of its own. Every execution is bound to this wallet, chain,
///      nonce, deadline, target, value and calldata by the owner's EIP-712 signature.
contract ZeusDepositWallet is IERC1271, ERC1155Holder, EIP712, ReentrancyGuard {
  using SafeERC20 for IERC20;

  bytes32 public constant EXECUTION_TYPEHASH = keccak256(
    "Execution(address target,uint256 value,bytes data,uint256 nonce,uint64 deadline)"
  );

  error InvalidAddress();
  error InvalidDeadline(uint64 deadline);
  error InvalidNonce(uint256 expected, uint256 supplied);
  error InvalidSignature();
  error InsufficientPermitAllowance(uint256 allowance, uint256 required);
  error ExecutionFailed();
  error ZeroAmount();

  event Executed(
    uint256 indexed nonce,
    address indexed relayer,
    address indexed target,
    uint256 value,
    bytes data
  );
  event PermitDeposit(address indexed owner, uint256 amount);

  address public immutable owner;
  IERC20 public immutable collateralToken;
  IERC1155 public immutable conditionalTokens;
  address public immutable exchange;
  uint256 public nonce;

  constructor(address owner_, address collateralToken_, address conditionalTokens_, address exchange_)
    EIP712("Zeus Deposit Wallet", "1")
  {
    if (
      owner_ == address(0) || collateralToken_ == address(0) || conditionalTokens_ == address(0)
        || exchange_ == address(0)
    ) revert InvalidAddress();

    owner = owner_;
    collateralToken = IERC20(collateralToken_);
    conditionalTokens = IERC1155(conditionalTokens_);
    exchange = exchange_;

    collateralToken.forceApprove(exchange_, type(uint256).max);
    conditionalTokens.setApprovalForAll(exchange_, true);
  }

  receive() external payable {}

  function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
    return SignatureChecker.isValidSignatureNow(owner, hash, signature)
      ? IERC1271.isValidSignature.selector
      : bytes4(0xffffffff);
  }

  function execute(
    address target,
    uint256 value,
    bytes calldata data,
    uint256 suppliedNonce,
    uint64 deadline,
    bytes calldata signature
  ) external nonReentrant returns (bytes memory result) {
    if (target == address(0)) revert InvalidAddress();
    if (block.timestamp > deadline) revert InvalidDeadline(deadline);
    uint256 expectedNonce = nonce;
    if (suppliedNonce != expectedNonce) revert InvalidNonce(expectedNonce, suppliedNonce);

    bytes32 digest = _hashTypedDataV4(
      keccak256(
        abi.encode(EXECUTION_TYPEHASH, target, value, keccak256(data), suppliedNonce, deadline)
      )
    );
    if (!SignatureChecker.isValidSignatureNow(owner, digest, signature)) revert InvalidSignature();

    nonce = expectedNonce + 1;
    (bool success, bytes memory returnData) = target.call{value: value}(data);
    if (!success) {
      if (returnData.length == 0) revert ExecutionFailed();
      assembly ("memory-safe") {
        revert(add(returnData, 0x20), mload(returnData))
      }
    }

    emit Executed(suppliedNonce, msg.sender, target, value, data);
    return returnData;
  }

  /// @notice Deposits a permit-enabled collateral token without an on-chain approve transaction.
  /// @dev Any relayer may submit the owner's token permit; the permit itself grants the authority.
  function depositWithPermit(
    uint256 amount,
    uint256 deadline,
    uint8 v,
    bytes32 r,
    bytes32 s
  ) external nonReentrant {
    if (amount == 0) revert ZeroAmount();
    try IERC20Permit(address(collateralToken)).permit(
      owner,
      address(this),
      amount,
      deadline,
      v,
      r,
      s
    ) {} catch {
      uint256 allowance = collateralToken.allowance(owner, address(this));
      if (allowance < amount) revert InsufficientPermitAllowance(allowance, amount);
    }
    collateralToken.safeTransferFrom(owner, address(this), amount);
    emit PermitDeposit(owner, amount);
  }
}
