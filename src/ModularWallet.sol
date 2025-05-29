// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

// ERC-4337 (Account Abstraction)
import {BaseAccount} from "account-abstraction/contracts/core/BaseAccount.sol";
import {IAccount} from "account-abstraction/contracts/interfaces/IAccount.sol";
import {IEntryPoint} from "account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "account-abstraction/contracts/core/Helpers.sol";

// ERC-7579 (Modular Smart Account)
import {IERC7579Module} from "./erc7579/IERC7579Module.sol";
import {IERC7579AccountConfig} from "./erc7579/IERC7579AccountConfig.sol";
import {IERC7579Execution} from "./erc7579/IERC7579Execution.sol";
import {ModuleTypeIds} from "./erc7579/ModuleTypeIds.sol";
import {ISigner} from "./erc7579/ISigner.sol";

// ERC-165
import {ERC165} from "openzeppelin-contracts/contracts/utils/introspection/ERC165.sol";
import {IERC165} from "openzeppelin-contracts/contracts/utils/introspection/IERC165.sol";

// ERC-1271 (Smart Contract Signatures)
import {IERC1271} from "openzeppelin-contracts/contracts/interfaces/IERC1271.sol";

/**
 * @title ModularWallet
 * @notice A modular ERC-4337 smart contract wallet with pluggable modules for validation and execution.
 *         Core logic is split across modules (e.g. OwnershipManagement for signature checks).
 * @author Kelly Smulian
 */
contract ModularWallet is BaseAccount, ERC165, IERC1271, IERC7579AccountConfig, IERC7579Execution {
    // --- Events ---
    event ModuleInstalled(uint256 indexed moduleTypeId, address indexed module);
    event ModuleUninstalled(uint256 indexed moduleTypeId, address indexed module);

    // --- Errors ---
    error NotAModule();
    error ModuleAlreadyInstalled();
    error CannotUninstall_UseRotateKeysInstead();
    error InvalidModuleTypeId();
    error ModuleNotInstalled();
    error NoOwnershipModule();

    // --- State ---
    /// @notice ERC-4337 EntryPoint singleton
    IEntryPoint public immutable i_entryPoint;
    /// @notice mapping: moduleTypeId => module address => installed bool
    mapping(uint256 => mapping(address => bool)) private modules;
    /// @notice currently active ERC-7780 Ownership Management module
    address public ownershipModule;

    // --- Modifiers ---
    /// @dev Restrict caller to the configured EntryPoint
    modifier onlyEntryPoint() {
        _requireFromEntryPoint();
        _;
    }

    /// @dev Restrict caller to a module of type EXECUTION
    modifier onlyExecutionModule() {
        require(modules[ModuleTypeIds.EXECUTION][msg.sender], NotAModule());
        _;
    }

    // --- Constructor ---
    /**
     * @param _entryPoint The 4337 EntryPoint Address
     * @param _ownershipModule The OwnershipManagement module
     * @param initData ABI-encoded init data for the ownership module (e.g. public key)
     */
    constructor(address _entryPoint, address _ownershipModule, bytes memory initData) {
        i_entryPoint = IEntryPoint(_entryPoint);

        // bootstrap the ownership module
        modules[ModuleTypeIds.SIGNER][_ownershipModule] = true;
        ownershipModule = _ownershipModule;
        IERC7579Module(_ownershipModule).onInstall(initData);
        emit ModuleInstalled(ModuleTypeIds.SIGNER, _ownershipModule);
    }

    // --- Module Management ---
    /**
     * @notice Install a module for validation or execution
     * @param moduleTypeId The ERC-7579 module type identifier
     * @param module Address of the module to install
     * @param initData ABI-encoded data for module initialisation
     */
    function installModule(uint256 moduleTypeId, address module, bytes calldata initData) external onlyEntryPoint {
        require(!modules[moduleTypeId][module], ModuleAlreadyInstalled());
        require(IERC7579Module(module).isModuleType(moduleTypeId), InvalidModuleTypeId());

        modules[moduleTypeId][module] = true;

        // track signer modules specially
        if (moduleTypeId == ModuleTypeIds.SIGNER) {
            ownershipModule = module;
        }
        IERC7579Module(module).onInstall(initData);
        emit ModuleInstalled(moduleTypeId, module);
    }

    /**
     * @notice Uninstall a previously installed module
     * @param moduleTypeId The ERC-7579 module type identifier
     * @param module Address of the module to uninstall
     * @param deInitData ABI-encoded data for module de-initialisation
     */
    function uninstallModule(uint256 moduleTypeId, address module, bytes calldata deInitData) external onlyEntryPoint {
        require(moduleTypeId != ModuleTypeIds.SIGNER, CannotUninstall_UseRotateKeysInstead());
        require(modules[moduleTypeId][module], ModuleNotInstalled());
        modules[moduleTypeId][module] = false;

        IERC7579Module(module).onUninstall(deInitData);
        emit ModuleUninstalled(moduleTypeId, module);
    }

    /// @notice Check if a given module of a given type is currently installed
    function isModuleInstalled(uint256 moduleTypeId, address module) external view returns (bool) {
        return modules[moduleTypeId][module];
    }

    // --- ERC-4337 Overrides ---
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
        address moduleAddress = ownershipModule;
        require(moduleAddress != address(0), NoOwnershipModule());

        // derive an opaque config-ID
        bytes32 moduleId = bytes32(uint256(uint160(moduleAddress)));

        // call into ERC-7780 Signer
        return ISigner(moduleAddress).checkUserOpSignature(moduleId, userOp, userOpHash);
    }

    // --- ERC-7579 Account Config ---
    /// @inheritdoc IERC7579AccountConfig
    function accountId() external pure override returns (string memory) {
        return "myorg.modularwallet.v1";
    }

    /// @inheritdoc IERC7579AccountConfig
    function supportsExecutionMode(bytes32 mode) external pure override returns (bool) {
        // For MVP: only support single-call mode
        return mode == bytes32(0);
    }

    /// @inheritdoc IERC7579AccountConfig
    function supportsModule(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == ModuleTypeIds.EXECUTION || moduleTypeId == ModuleTypeIds.SIGNER;
    }

    // --- ERC-1271 Override ---
    /// @inheritdoc IERC1271
    function isValidSignature(bytes32 hash, bytes calldata signature) external view override returns (bytes4) {
        // delegate to ERC-7780 OwnershipManagement validation module
        address moduleAddress = ownershipModule;
        require(moduleAddress != address(0), NoOwnershipModule());

        // derive a 32-byte "id" from the module address
        bytes32 moduleId = bytes32(uint256(uint160(moduleAddress)));

        // delegate to the ERC-7780 Signer module
        return ISigner(moduleAddress).checkSignature(moduleId, address(this), hash, signature);
    }

    // --- ERC-7579 Execution ---
    /// @inheritdoc IERC7579Execution
    function execute(bytes32 mode, bytes calldata callData) external override onlyEntryPoint {
        _dispatch(mode, callData);
    }

    /// @inheritdoc IERC7579Execution
    function executeFromExecutor(bytes32 mode, bytes calldata callData)
        external
        override
        onlyExecutionModule
        returns (bytes[] memory returnData)
    {
        _dispatch(mode, callData);
        // For MVP: single-call - no per-call return data, so return empty array
        return new bytes[](0);
    }

    /// @dev Internal router for single-call execution
    function _dispatch(bytes32 mode, bytes calldata callData) internal {
        // For MVP: accept only single-call mode
        require(mode == bytes32(0), "unsupported mode");
        // decode a single call:  (to, value, callData)
        (address to, uint256 value, bytes memory data) = abi.decode(callData, (address, uint256, bytes));
        _call(to, value, data);
    }

    /// @dev Low-level call helper with revert bubbling
    function _call(address to, uint256 value, bytes memory data) internal {
        (bool success, bytes memory ret) = to.call{value: value}(data);

        if (!success) {
            // if there’s a revert reason, bubble it up
            if (ret.length > 0) {
                /// @solidity memory-safe-assembly
                assembly {
                    let sz := mload(ret)
                    revert(add(ret, 0x20), sz)
                }
            }
            revert("ModularWallet: call failed");
        }
    }

    // --- ERC-165 Support ---
    /// @inheritdoc ERC165
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165) returns (bool) {
        return
        // ERC-4337 account interface
        interfaceId == type(IAccount).interfaceId
        // ERC-1271 standard signature callback
        || interfaceId == type(IERC1271).interfaceId
        // ERC-7579 execution interface
        || interfaceId == type(IERC7579Execution).interfaceId
        // ERC-7579 account configuration
        || interfaceId == type(IERC7579AccountConfig).interfaceId || super.supportsInterface(interfaceId);
    }

    /// @notice Receive Ether (needed for execute calls that send ETH)
    receive() external payable {}
}
