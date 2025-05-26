// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {Create2} from "lib/openzeppelin-contracts/contracts/utils/Create2.sol"; // audited, well-tested code for the low-level CREATE2 operations

import {ModularWallet} from "./ModularWallet.sol";
import "forge-std/console.sol";

// Factory - a helper contract that performs a deployment for a new sender contract if necessary.

// Factory Contract - When using a wallet for the first time, the initCode field of the UserOperation is used to specify creation of the smart contract wallet. This is used concurrently with the first actual operation of the wallet (in the same UserOperation). Therefore, wallet developers also need to implement the account factory contract (for example: BLSAccountFactory.sol(opens in a new tab)). Creating new wallets should use the CREATE2 method to ensure the determinacy of generated addresses. CREATE2

contract WalletFactory {
    IEntryPoint public immutable i_entryPoint;

    event AccountCreated(address wallet, address owner, bytes32 salt);

    constructor(IEntryPoint _entryPoint) {
        i_entryPoint = _entryPoint;
    }

    /**
     * @notice Creates a new ModularWallet account.
     * @param owner The initial owner of the new account.
     * @param salt A unique salt for CREATE2.
     * @return wallet The address of the newly created account.
     */
    function createWallet(address owner, bytes32 salt) external returns (ModularWallet wallet) {
        console.log("Gas before packing code in factory:", gasleft());
        bytes memory code = abi.encodePacked(type(ModularWallet).creationCode, abi.encode(address(i_entryPoint), owner));
        console.log("Gas after packing code, before deploy in factory:", gasleft());
        address addr = Create2.deploy(0, salt, code);
        console.log("Gas after deploy in factory:", gasleft());
        wallet = ModularWallet(payable(addr));
        emit AccountCreated(addr, owner, salt);
    }

    /// helper for dApps to pre-compute the address
    function getAddress(address owner, bytes32 salt) external view returns (address) {
        bytes memory code = abi.encodePacked(type(ModularWallet).creationCode, abi.encode(address(i_entryPoint), owner));
        return Create2.computeAddress(salt, keccak256(code));
    }
}
