// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {BaseAccount} from "lib/account-abstraction/contracts/core/BaseAccount.sol";
import {IAccount} from "lib/account-abstraction/contracts/interfaces/IAccount.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "lib/account-abstraction/contracts/core/Helpers.sol";

// ERC7579
import {IERC7579Module} from "./erc7579/IERC7579Module.sol";
import {IERC7579AccountConfig} from "./erc7579/IERC7579AccountConfig.sol";
import {ModuleTypeIds} from "./erc7579/ModuleTypeIds.sol";
import {ISigner} from "./erc7579/ISigner.sol";

// ERC165
import {ERC165} from "lib/openzeppelin-contracts/contracts/utils/introspection/ERC165.sol";
import {IERC165} from "lib/openzeppelin-contracts/contracts/utils/introspection/IERC165.sol";

// ERC1271
import {IERC1271} from "lib/openzeppelin-contracts/contracts/interfaces/IERC1271.sol";

import {Ownable} from "lib/openzeppelin-contracts/contracts/access/Ownable.sol"; // remove later on
import {ECDSA} from "lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol"; // remove later on
import {MessageHashUtils} from "lib/openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol"; // remove later on

contract ModularWallet is BaseAccount, Ownable, ERC165, IERC1271, IERC7579AccountConfig {
    using ECDSA for bytes32;

    // EVENTS
    event ModuleInstalled(uint256 indexed moduleTypeId, address indexed module);
    event ModuleUninstalled(uint256 indexed moduleTypeId, address indexed module);

    // ERRORS
    error ModuleAlreadyInstalled();
    error InvalidModuleTypeId();
    error ModuleNotInstalled();

    /// @dev The 4337 EntryPoint singleton
    IEntryPoint public immutable i_entryPoint;
    /// @dev moduleTypeId => module address => installed?
    mapping(uint256 => mapping(address => bool)) private modules;
    /// @dev the one-and-only ERC-7780 signer module
    address public signerModule;

    /// @param _entryPoint The 4337 EntryPoint singleton
    /// @param _owner The initial owner (or passkey module)
    constructor(address _entryPoint, address _owner) Ownable(_owner) {
        i_entryPoint = IEntryPoint(_entryPoint);
    }

    /// @notice Install a module of a given type
    function installModule(uint256 moduleTypeId, address module, bytes calldata initData) external onlyOwner {
        require(!modules[moduleTypeId][module], ModuleAlreadyInstalled());
        require(IERC7579Module(module).isModuleType(moduleTypeId), InvalidModuleTypeId());
        modules[moduleTypeId][module] = true;

        if (moduleTypeId == ModuleTypeIds.SIGNER) {
            signerModule = module;
        }
        IERC7579Module(module).onInstall(initData);
        emit ModuleInstalled(moduleTypeId, module);
    }

    /// @notice Uninstall a module of a given type
    function uninstallModule(uint256 moduleTypeId, address module, bytes calldata deInitData) external onlyOwner {
        require(modules[moduleTypeId][module], ModuleNotInstalled());
        modules[moduleTypeId][module] = false;

        if (moduleTypeId == ModuleTypeIds.SIGNER && signerModule == module) {
            signerModule = address(0);
        }
        IERC7579Module(module).onUninstall(deInitData);
        emit ModuleUninstalled(moduleTypeId, module);
    }

    /// @notice Check if a given module of a given type is currently installed
    function isModuleInstalled(uint256 moduleTypeId, address module) external view returns (bool) {
        return modules[moduleTypeId][module];
    }

    // OVERRIDES
    /// @inheritdoc BaseAccount
    function entryPoint() public view override returns (IEntryPoint) {
        return i_entryPoint;
    }

    /// @inheritdoc BaseAccount
    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        override
        returns (uint256 validationData)
    {
        address moduleAddress = signerModule;
        require(moduleAddress != address(0), "no signer installed"); // custom

        // derive an opaque config-ID
        bytes32 moduleId = bytes32(uint256(uint160(moduleAddress)));

        // call into your ERC-7780 Signer module
        return ISigner(moduleAddress).checkUserOpSignature(moduleId, userOp, userOpHash);
    }

    //  with _validateNonce left empty, EntryPoint’s internal check will still catch replays, but wallet won’t auto-increment??
    // @inheritdoc BaseAccount
    function _validateNonce(uint256 nonce) internal view override {
        require(nonce == i_entryPoint.getNonce(address(this), 0), "bad nonce");
    }

    /// @inheritdoc IERC7579AccountConfig
    function accountId() external pure override returns (string memory) {
        return "myorg.modularwallet.v1";
    }

    /// @inheritdoc IERC7579AccountConfig
    function supportsExecutionMode(bytes32 mode) external pure override returns (bool) {
        // for now we support only mode=0 meaning “single call”
        // in future you can decode the mode and check batch/static/delegate
        return mode == bytes32(0);
    }

    /// @inheritdoc IERC7579AccountConfig
    function supportsModule(uint256 moduleTypeId) external pure override returns (bool) {
        // we allow validation & execution modules
        return (moduleTypeId == ModuleTypeIds.VALIDATION) || (moduleTypeId == ModuleTypeIds.EXECUTION)
            || (moduleTypeId == ModuleTypeIds.SIGNER);
    }

    /// @inheritdoc IERC1271
    function isValidSignature(bytes32 hash, bytes calldata signature) external view override returns (bytes4) {
        // delegate to ERC-7780 OwnershipManagement validation module
        address moduleAddress = signerModule;
        require(moduleAddress != address(0), "no signer installed"); // custom

        // derive a 32-byte "id" from the module address
        bytes32 moduleId = bytes32(uint256(uint160(moduleAddress)));

        // delegate to the ERC-7780 Signer module
        return ISigner(moduleAddress).checkSignature(moduleId, address(this), hash, signature);
    }

    /// @notice ERC-165: support for all interfaces
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165) returns (bool) {
        return
        // ERC-165 support for interfaces
        interfaceId == type(IERC165).interfaceId
        // ERC-4337 account interface
        || interfaceId == type(IAccount).interfaceId
        // ERC-1271 standard signature callback
        || interfaceId == type(IERC1271).interfaceId
        // ERC-7579 account configuration
        || interfaceId == type(IERC7579AccountConfig).interfaceId || super.supportsInterface(interfaceId);
    }

    receive() external payable {}
}
