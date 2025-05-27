// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {IERC7579Module} from "../erc7579/IERC7579Module.sol";
import {ISigner} from "../erc7579/ISigner.sol";
import {ModuleTypeIds} from "../erc7579/ModuleTypeIds.sol";

import {PackedUserOperation} from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "lib/account-abstraction/contracts/core/Helpers.sol";

import {MessageHashUtils} from "lib/openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {IERC1271} from "lib/openzeppelin-contracts/contracts/interfaces/IERC1271.sol";

/// @notice ERC-7780 Signer module for owner‐based validation
contract OwnershipManagement is IERC7579Module, ISigner {
    using ECDSA for bytes32;

    /// @dev wallet → owner address
    mapping(address => address) private ownerOf;

    /// @notice Only modules of type SIGNER (6)
    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == ModuleTypeIds.SIGNER;
    }

    /// @notice Called by the wallet on install. Expect initData = abi.encode(owner)
    function onInstall(bytes calldata initData) external override {
        address owner = abi.decode(initData, (address));
        ownerOf[msg.sender] = owner; // msg.sender here is the ModularWallet
    }

    function onUninstall(bytes calldata) external override {
        delete ownerOf[msg.sender];
    }

    /// @inheritdoc ISigner
    function checkUserOpSignature(
        bytes32, // id (ignored here)
        PackedUserOperation calldata op, // the op
        bytes32 userOpHash
    ) external payable override returns (uint256 validationData) {
        address owner = ownerOf[msg.sender];
        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(userOpHash);
        address signer = ethHash.recover(op.signature);
        if (signer == owner) {
            return SIG_VALIDATION_SUCCESS;
        }
        return SIG_VALIDATION_FAILED;
    }

    /// @inheritdoc ISigner
    function checkSignature(
        bytes32, // id (ignored)
        address sender,
        bytes32 hash,
        bytes calldata sig
    ) external view override returns (bytes4) {
        address owner = ownerOf[sender];
        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(hash);
        address signer = ethHash.recover(sig);
        if (signer == owner) {
            return IERC1271.isValidSignature.selector;
        }
        return bytes4(0xffffffff);
    }
}
