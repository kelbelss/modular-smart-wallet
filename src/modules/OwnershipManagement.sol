// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

// ERC-7579 (Modular Smart Account)
import {IERC7579Module} from "../erc7579/IERC7579Module.sol";
import {ISigner} from "../erc7579/ISigner.sol";
import {ModuleTypeIds} from "../erc7579/ModuleTypeIds.sol";

// ERC-4337 (UserOp Utils)
import {PackedUserOperation} from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "lib/account-abstraction/contracts/core/Helpers.sol";

// P-256 WebAuthn Verification Libraries
import {P256Verifier} from "lib/p256-verifier/src/P256Verifier.sol";
import {WebAuthn} from "lib/p256-verifier/src/WebAuthn.sol";
import {P256} from "lib/p256-verifier/src/P256.sol";

// ERC-1271 Smart Contract Sig
import {IERC1271} from "lib/openzeppelin-contracts/contracts/interfaces/IERC1271.sol";

/**
 * @title OwnershipManagement
 * @notice ERC-7579 "signer" (ERC-7780) module for passkey-based signature validation using WebAuthn P-256, with
 *         built-in emergency fallback recovery.
 * @dev Stores a P-256 public key per wallet and supports rotating it via both normal
 *      UserOp flows and a time-locked fallback mechanism.
 * @author Kelly Smulian
 */
contract OwnershipManagement is IERC7579Module, ISigner {
    // --- Events ---
    /// @notice Emitted when a new fallback admin is set
    event FallbackAdminChanged(address indexed newAdmin);
    /// @notice Emitted when an emergency key rotation is requested
    event EmergencyRotateRequested(address indexed wallet, bytes32 newX, bytes32 newY, uint256 unlockTime);
    /// @notice Emitted when an emergency key rotation is executed
    event EmergencyRotateExecuted(address indexed wallet, bytes32 newX, bytes32 newY);

    // --- Errors ---
    error OnlyWalletCanCall();
    error NotFallbackAdmin();
    error TooEarly();
    // error NoSignerModule();

    // --- Types ---
    /// @notice Uncompressed P-256 public key coordinates
    struct PubKey {
        bytes32 x;
        bytes32 y;
    }

    /// @notice Encoded passkey signature payload
    struct PasskeySig {
        bytes authenticatorData;
        bytes clientDataJSON;
        bytes32 r;
        bytes32 s;
    }

    // --- State ---
    /// @notice wallet address => its P-256 public key
    mapping(address wallet => PubKey) internal publicKeyOf; //  wallet → key
    // /// @notice wallet address => owner EOA (optional future use)
    // mapping(address => address) private ownerOf;

    /// @notice Fallback admin allowed to perform emergency recovery
    address public fallbackAdmin;
    /// @notice Timestamp after which the emergency rotation can be executed
    uint256 public emergencyUnlock;
    /// @notice Pending fallback key coordinates
    bytes32 private pendingX;
    bytes32 private pendingY;

    // --- Module Identification ---
    /**
     * @inheritdoc IERC7579Module
     * @dev Only modules of type SIGNER (6) are supported by this contract
     */
    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == ModuleTypeIds.SIGNER;
    }

    // --- Installation ---
    /**
     * @inheritdoc IERC7579Module
     * @dev Called by the wallet during `installModule`. Expects `initData = abi.encode(x, y)`.
     * @param initData ABI-encoded initial public key (x, y) and fallback admin encoded as abi.encode(x, y, fallbackAdmin)
     */
    function onInstall(bytes calldata initData) external override {
        (bytes32 x, bytes32 y, address fbAdmin) = abi.decode(initData, (bytes32, bytes32, address));
        publicKeyOf[msg.sender] = PubKey(x, y);
        fallbackAdmin = fbAdmin; // emergencyUnlock and pending keys default to zero
    }

    /**
     * @inheritdoc IERC7579Module
     * @dev Clears stored public key on uninstall.
     */
    function onUninstall(bytes calldata) external override {
        delete publicKeyOf[msg.sender];
        delete fallbackAdmin;
        delete emergencyUnlock;
        delete pendingX;
        delete pendingY;
    }

    // --- Signature Verification ---
    /// @dev Internal helper to hash and verify a passkey signature via P-256 library
    function _verify(PubKey storage pubKey, PasskeySig memory pkSig) private view returns (bool) {
        // 1) Hash the clientDataJSON
        bytes32 clientDataHash = sha256(pkSig.clientDataJSON);
        // 2) Compute message hash = sha256(authData || clientDataHash)
        bytes32 h = sha256(abi.encodePacked(pkSig.authenticatorData, clientDataHash));
        // 3) Delegate to on-chain P256 verifier (precompile or library)
        return P256.verifySignature(h, uint256(pkSig.r), uint256(pkSig.s), uint256(pubKey.x), uint256(pubKey.y));
    }

    /**
     * @inheritdoc ISigner
     * @dev Validates a UserOperation by decoding its `signature` field as `PasskeySig`.
     *      Called by the wallet in its `_validateSignature` override.
     */
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

    /**
     * @inheritdoc ISigner
     * @dev Implements the ERC-1271 contract signature scheme for arbitrary hashes.
     */
    function checkSignature(
        bytes32, // config ID (ignored)
        address sender,
        bytes32, // hash (already checked off-chain)
        bytes calldata sig
    ) external view override returns (bytes4) {
        PasskeySig memory ps = abi.decode(sig, (PasskeySig));
        if (_verify(publicKeyOf[sender], ps)) {
            return IERC1271.isValidSignature.selector;
        }
        return bytes4(0xffffffff);
    }

    // --- Key Rotation ---
    /**
     * @notice Rotate the on-chain P-256 public key for a wallet
     * @dev Must be called by the wallet itself via `execute` (not by an EOA)
     * @dev Must be routed through wallet.execute() so msg.sender==wallet
     * @param newX New public key X coordinate
     * @param newY New public key Y coordinate
     */
    function rotateKey(bytes32 newX, bytes32 newY) external {
        // only a wallet that ran onInstall (has a non-zero x) may call
        require(publicKeyOf[msg.sender].x != bytes32(0), OnlyWalletCanCall());
        publicKeyOf[msg.sender] = PubKey(newX, newY);
    }

    // --- Emergency Recovery ---
    /**
     * @notice Initiate a time-locked emergency key swap by fallback admin
     * @param newX X-coordinate for replacement key
     * @param newY Y-coordinate for replacement key
     * @dev Called by fallbackAdmin to schedule emergency rotation
     */
    function requestEmergencyRotate(bytes32 newX, bytes32 newY) external {
        if (msg.sender != fallbackAdmin) revert NotFallbackAdmin();
        emergencyUnlock = block.timestamp + 1 days;
        pendingX = newX;
        pendingY = newY;
        emit EmergencyRotateRequested(msg.sender, newX, newY, emergencyUnlock);
    }

    /**
     * @notice Execute the scheduled emergency rotation after unlock time
     * @dev Only fallbackAdmin can call, and only after emergencyUnlock
     */
    function executeEmergencyRotate() external {
        if (msg.sender != fallbackAdmin) revert NotFallbackAdmin();
        if (block.timestamp < emergencyUnlock) revert TooEarly();
        publicKeyOf[msg.sender] = PubKey(pendingX, pendingY);
        emit EmergencyRotateExecuted(msg.sender, pendingX, pendingY);
        // clean up
        emergencyUnlock = 0;
        pendingX = bytes32(0);
        pendingY = bytes32(0);
    }

    /**
     * @notice Update the fallback admin to a new address
     * @dev Can only be called by the wallet itself (via primary key)
     * @param newAdmin Address of new fallback admin
     */
    function updateFallbackAdmin(address newAdmin) external {
        if (msg.sender != address(this)) revert OnlyWalletCanCall();
        fallbackAdmin = newAdmin;
        emit FallbackAdminChanged(newAdmin);
    }

    // --- Test Helpers --- // remove later
    /**
     * @notice Read stored public key for a wallet (test-only)
     * @param wallet Address of the wallet
     * @return x X coordinate
     * @return y Y coordinate
     */
    function getPublicKey(address wallet) external view returns (bytes32 x, bytes32 y) {
        PubKey storage pk = publicKeyOf[wallet];
        return (pk.x, pk.y);
    }
}
