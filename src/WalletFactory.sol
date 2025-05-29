// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {ModularWallet} from "./ModularWallet.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {Create2} from "lib/openzeppelin-contracts/contracts/utils/Create2.sol"; // audited, well-tested code for the low-level CREATE2 operations

/**
 * @title WalletFactory
 * @notice Deterministic factory for deploying ModularWallets using CREATE2,
 *         enabling counterfactual addresses and one-time initialisation.
 * @dev Embeds EntryPoint and OwnershipManagement init data into the creation code.
 * @author Kelly Smulian
 */
contract WalletFactory {
    // --- Events ---
    event AccountCreated(address wallet, address owner, bytes32 salt);

    // --- State ---
    /// @notice ERC-4337 EntryPoint singleton
    IEntryPoint public immutable i_entryPoint;
    /// @notice The OwnershipManagement signer module to bootstrap into each wallet
    address public immutable i_ownershipModule;

    // --- Constructor ---
    /**
     * @param _entryPoint Address of the ERC-4337 EntryPoint
     * @param _ownershipModule  Address of the OwnershipManagement module to install
     */
    constructor(IEntryPoint _entryPoint, address _ownershipModule) {
        i_entryPoint = _entryPoint;
        i_ownershipModule = _ownershipModule;
    }

    // --- External Functions ---
    /**
     * @notice Deploys a new ModularWallet contract at a counterfactual address.
     * @param salt A unique salt for CREATE2.
     * @param ownershipInitData ABI-encoded init data for the ownership module (e.g public key).
     *        abi.encode(x, y, fallbackAdmin)
     * @return wallet The address of the newly created account instance.
     */
    function createWallet(bytes32 salt, bytes calldata ownershipInitData) external returns (ModularWallet wallet) {
        // 1. Pack the creation code + constructor args
        bytes memory code = abi.encodePacked(
            type(ModularWallet).creationCode,
            abi.encode(address(i_entryPoint), address(i_ownershipModule), ownershipInitData)
        );

        // 2. Deploy via CREATE2 for deterministic address
        address addr = Create2.deploy(0, salt, code);

        // 3. Cast to ModularWallet and emit event
        wallet = ModularWallet(payable(addr));
        emit AccountCreated(addr, msg.sender, salt);
    }

    /**
     * @notice Returns the address where a wallet would be deployed for a given salt.
     * @param salt  The CREATE2 salt to compute.
     * @return The counterfactually computed address.
     */
    function getAddress(bytes32 salt, bytes calldata ownershipInitData) external view returns (address) {
        bytes memory code = abi.encodePacked(
            type(ModularWallet).creationCode, abi.encode(address(i_entryPoint), i_ownershipModule, ownershipInitData)
        );
        return Create2.computeAddress(salt, keccak256(code));
    }
}
