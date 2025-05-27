// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {BaseAccount} from "lib/account-abstraction/contracts/core/BaseAccount.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "lib/account-abstraction/contracts/core/Helpers.sol";

// ERC7579
import {IERC7579Module} from "./erc7579/IERC7579Module.sol";
import {IERC7579AccountConfig} from "./erc7579/IERC7579AccountConfig.sol";
import {ModuleTypeIds} from "./erc7579/ModuleTypeIds.sol";

import {Ownable} from "lib/openzeppelin-contracts/contracts/access/Ownable.sol"; // remove later on
import {ECDSA} from "lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol"; // remove later on
import {MessageHashUtils} from "lib/openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol"; // remove later on

contract ModularWallet is BaseAccount, Ownable, IERC7579AccountConfig {
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

    /// @param _entryPoint  The 4337 EntryPoint singleton
    /// @param _owner       The initial owner (or passkey module)
    constructor(address _entryPoint, address _owner) Ownable(_owner) {
        i_entryPoint = IEntryPoint(_entryPoint);
    }

    /// @notice Install a module of a given type
    function installModule(uint256 moduleTypeId, address module, bytes calldata initData) external onlyOwner {
        require(!modules[moduleTypeId][module], ModuleAlreadyInstalled());
        require(IERC7579Module(module).isModuleType(moduleTypeId), InvalidModuleTypeId());
        modules[moduleTypeId][module] = true;
        IERC7579Module(module).onInstall(initData);
        emit ModuleInstalled(moduleTypeId, module);
    }

    /// @notice Uninstall a module of a given type
    function uninstallModule(uint256 moduleTypeId, address module, bytes calldata deInitData) external onlyOwner {
        require(modules[moduleTypeId][module], ModuleNotInstalled());
        modules[moduleTypeId][module] = false;
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
        view
        override
        returns (uint256 validationData)
    {
        bytes32 ethSignedMessageHash = MessageHashUtils.toEthSignedMessageHash(userOpHash);
        address signer = ECDSA.recover(ethSignedMessageHash, userOp.signature);
        if (signer != owner()) {
            return SIG_VALIDATION_FAILED;
        }
        return SIG_VALIDATION_SUCCESS;
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
        return (moduleTypeId == ModuleTypeIds.VALIDATION) || (moduleTypeId == ModuleTypeIds.EXECUTION);
    }

    receive() external payable {}
}
