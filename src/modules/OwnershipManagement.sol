// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {IERC7579Module} from "../erc7579/IERC7579Module.sol";
import {ISigner} from "../erc7579/ISigner.sol";
import {ModuleTypeIds} from "../erc7579/ModuleTypeIds.sol";

import {PackedUserOperation} from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "lib/account-abstraction/contracts/core/Helpers.sol";

import {P256Verifier} from "lib/p256-verifier/src/P256Verifier.sol";
import {WebAuthn} from "lib/p256-verifier/src/WebAuthn.sol";
import {P256} from "lib/p256-verifier/src/P256.sol";
import {IERC1271} from "lib/openzeppelin-contracts/contracts/interfaces/IERC1271.sol";

/// @notice WebAuthn / passkey signer module (ERC-7579/7780 type = 6)
contract OwnershipManagement is IERC7579Module, ISigner {
    // ERRORS
    error OnlyWalletCanCall();

    struct PubKey {
        bytes32 x;
        bytes32 y;
    } // uncompressed EC point

    mapping(address wallet => PubKey) internal publicKeyOf; //  wallet → key

    /// @dev wallet → owner address
    mapping(address => address) private ownerOf;

    /// @notice Only modules of type SIGNER (6)
    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == ModuleTypeIds.SIGNER;
    }

    /// @notice Called by the wallet on install. Expect initData = abi.encode(owner)
    /// initData = abi.encode(bytes32 x, bytes32 y)
    function onInstall(bytes calldata initData) external override {
        (bytes32 x, bytes32 y) = abi.decode(initData, (bytes32, bytes32));
        publicKeyOf[msg.sender] = PubKey(x, y);
    }

    function onUninstall(bytes calldata) external override {
        delete publicKeyOf[msg.sender];
    }

    // SIGNATURE VERIFICATION

    /// `op.signature` or standalone `sig` are encoded as:
    /// abi.encode(authenticatorData, clientDataJSON, r, s)
    struct PasskeySig {
        bytes authenticatorData;
        bytes clientDataJSON;
        bytes32 r;
        bytes32 s;
    }

    /// internal helper reused by both 4337 & ERC-1271 paths
    function _verify(PubKey storage pubKey, PasskeySig memory pkSig) private view returns (bool) {
        // hash the raw clientDataJSON bytes
        bytes32 clientDataHash = sha256(pkSig.clientDataJSON);
        // hash(concatenate(authData, clientDataHash))
        bytes32 h = sha256(abi.encodePacked(pkSig.authenticatorData, clientDataHash));

        return P256.verifySignature(h, uint256(pkSig.r), uint256(pkSig.s), uint256(pubKey.x), uint256(pubKey.y));
    }

    /// @inheritdoc ISigner
    function checkUserOpSignature(
        bytes32, // id (ignored here)
        PackedUserOperation calldata op, // full op
        bytes32 // userOpHash – already inside clientDataJSON.challenge
    ) external payable override returns (uint256 validationData) {
        PasskeySig memory pkSig = abi.decode(op.signature, (PasskeySig));
        if (_verify(publicKeyOf[msg.sender], pkSig)) {
            return SIG_VALIDATION_SUCCESS;
        }
        return SIG_VALIDATION_FAILED;
    }

    /// @inheritdoc ISigner
    // ERC-1271
    function checkSignature(
        bytes32, // id (ignored)
        address sender,
        bytes32, // hash – echoed inside clientDataJSON
        bytes calldata sig
    ) external view override returns (bytes4) {
        PasskeySig memory ps = abi.decode(sig, (PasskeySig));
        if (_verify(publicKeyOf[sender], ps)) {
            return IERC1271.isValidSignature.selector;
        }
        return bytes4(0xffffffff);
    }

    // function rotateKey(bytes32 newPubKey) external {
    //     require(msg.sender == wallet, "only wallet");
    //     // TODO: guardian / timelock checks
    //     pubKey = newPubKey;
    // }

    /// @notice Rotate to a new P-256 public key; must be called by the wallet itself
    function rotateKey(bytes32 newX, bytes32 newY) external {
        // only a wallet that ran onInstall (and so has a non-zero x) may call
        require(publicKeyOf[msg.sender].x != bytes32(0), OnlyWalletCanCall());
        // fix
        publicKeyOf[msg.sender] = PubKey(newX, newY);
    }

    // remove later
    /// @notice For testing: read the stored P-256 public key for a wallet
    function getPublicKey(address wallet) external view returns (bytes32 x, bytes32 y) {
        PubKey storage pk = publicKeyOf[wallet];
        return (pk.x, pk.y);
    }
}
