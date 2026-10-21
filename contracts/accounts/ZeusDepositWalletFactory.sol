// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

import {ZeusDepositWallet} from "./ZeusDepositWallet.sol";

/// @title Zeus Deposit Wallet Factory
/// @notice Deploys one deterministic, user-owned funding account per wallet owner.
contract ZeusDepositWalletFactory is AccessControl, EIP712 {
  bytes32 public constant WALLET_CREATION_TYPEHASH =
    keccak256("WalletCreation(address owner,uint64 deadline)");

  error ExchangeAlreadyConfigured(address exchange);
  error ExchangeNotConfigured();
  error InvalidAddress();
  error InvalidDeadline(uint64 deadline);
  error InvalidSignature();
  error UnauthorizedWalletCreation(address owner, address caller);
  error WalletAlreadyExists(address owner, address wallet);

  event ExchangeConfigured(address indexed exchange);
  event WalletCreated(address indexed owner, address indexed wallet, address indexed creator);

  address public immutable collateralToken;
  address public immutable conditionalTokens;
  address public exchange;
  mapping(address owner => address wallet) public walletOf;
  mapping(address wallet => address owner) public ownerOfWallet;

  constructor(address collateralToken_, address conditionalTokens_, address initialAdmin)
    EIP712("Zeus Deposit Wallet Factory", "1")
  {
    if (collateralToken_ == address(0) || conditionalTokens_ == address(0) || initialAdmin == address(0)) {
      revert InvalidAddress();
    }
    collateralToken = collateralToken_;
    conditionalTokens = conditionalTokens_;
    _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);
  }

  function setExchange(address exchange_) external onlyRole(DEFAULT_ADMIN_ROLE) {
    if (exchange_ == address(0)) revert InvalidAddress();
    if (exchange != address(0)) revert ExchangeAlreadyConfigured(exchange);
    exchange = exchange_;
    emit ExchangeConfigured(exchange_);
  }

  function createWallet(address owner) external returns (address wallet) {
    if (owner == address(0)) revert InvalidAddress();
    if (msg.sender != owner) revert UnauthorizedWalletCreation(owner, msg.sender);
    return _createWallet(owner);
  }

  function createWalletFor(address owner, uint64 deadline, bytes calldata signature)
    external
    returns (address wallet)
  {
    if (owner == address(0)) revert InvalidAddress();
    if (block.timestamp > deadline) revert InvalidDeadline(deadline);
    bytes32 digest = _hashTypedDataV4(
      keccak256(abi.encode(WALLET_CREATION_TYPEHASH, owner, deadline))
    );
    if (!SignatureChecker.isValidSignatureNow(owner, digest, signature)) revert InvalidSignature();
    return _createWallet(owner);
  }

  function _createWallet(address owner) private returns (address wallet) {
    address configuredExchange = exchange;
    if (configuredExchange == address(0)) revert ExchangeNotConfigured();
    address existing = walletOf[owner];
    if (existing != address(0)) revert WalletAlreadyExists(owner, existing);

    wallet = address(
      new ZeusDepositWallet{salt: _salt(owner)}(
        owner,
        collateralToken,
        conditionalTokens,
        configuredExchange
      )
    );
    walletOf[owner] = wallet;
    ownerOfWallet[wallet] = owner;
    emit WalletCreated(owner, wallet, msg.sender);
  }

  function predictWallet(address owner) external view returns (address predicted) {
    if (owner == address(0)) revert InvalidAddress();
    address configuredExchange = exchange;
    if (configuredExchange == address(0)) revert ExchangeNotConfigured();
    bytes32 initCodeHash = keccak256(
      abi.encodePacked(
        type(ZeusDepositWallet).creationCode,
        abi.encode(owner, collateralToken, conditionalTokens, configuredExchange)
      )
    );
    predicted = address(
      uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), address(this), _salt(owner), initCodeHash))))
    );
  }

  function _salt(address owner) private pure returns (bytes32) {
    return keccak256(abi.encode(owner));
  }
}
