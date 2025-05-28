// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {ModularWallet} from "./ModularWallet.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {Create2} from "lib/openzeppelin-contracts/contracts/utils/Create2.sol"; // audited, well-tested code for the low-level CREATE2 operations

// Factory Contract - When using a wallet for the first time, the initCode field of the UserOperation is used to specify creation of the smart contract wallet. This is used concurrently with the first actual operation of the wallet (in the same UserOperation). Therefore, wallet developers also need to implement the account factory contract (for example: BLSAccountFactory.sol(opens in a new tab)). Creating new wallets should use the CREATE2 method to ensure the determinacy of generated addresses. CREATE2

// Deterministic CREATE2 factory

contract WalletFactory {
    IEntryPoint public immutable i_entryPoint;
    address public immutable i_ownershipModule;

    event AccountCreated(address wallet, address owner, bytes32 salt);

    constructor(IEntryPoint _entryPoint, address _ownershipModule) {
        i_entryPoint = _entryPoint;
        i_ownershipModule = _ownershipModule;
    }

    /**
     * @notice Creates a new ModularWallet account.
     * @param salt A unique salt for CREATE2.
     * @return wallet The address of the newly created account.
     */
    function createWallet(bytes32 salt, bytes calldata ownershipInitData) external returns (ModularWallet wallet) {
        bytes memory code = abi.encodePacked(
            type(ModularWallet).creationCode,
            abi.encode(address(i_entryPoint), address(i_ownershipModule), ownershipInitData)
        );

        address addr = Create2.deploy(0, salt, code);

        wallet = ModularWallet(payable(addr));
        emit AccountCreated(addr, msg.sender, salt);
    }

    /// helper to pre-compute the address
    function getAddress(bytes32 salt) external view returns (address) {
        bytes memory code = abi.encodePacked(
            type(ModularWallet).creationCode,
            abi.encode(address(i_entryPoint), i_ownershipModule, abi.encode(msg.sender))
        );
        return Create2.computeAddress(salt, keccak256(code));
    }
}
