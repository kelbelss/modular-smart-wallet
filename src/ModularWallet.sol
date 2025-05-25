// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {IAccount} from "lib/account-abstraction/contracts/interfaces/IAccount.sol";
import {PackedUserOperation} from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";

contract ModularWallet is IAccount {
    // All components of ERC-4337 revolve around a pseudo-transaction object called a UserOperation which is used to execute actions through a smart contract account. This isn't to be mistaken for a regular transaction type.

    // Wallets should be able to translate regular transactions into UserOperations.

    // Account Contract is the smart contract wallet of a user. Wallet developers are required to implement at least two custom functions - one to verify signatures, and another to process transactions.

    // validateUserOp, which takes a UserOperation as input. This function is supposed to verify the signature and nonce on the UserOperation, pay the fee and increment the nonce if verification succeeds, and throw an exception if verification fails.

    // An op execution function, that interprets calldata as an instruction for the wallet to take actions. How this function interprets the calldata and what it does consequently is completely open-ended. However, we expect the most common behavior would be to parse the calldata as an instruction for the wallet to make one or more calls.

    // STATE VARIABLES
    IEntryPoint private immutable i_entryPoint;

    constructor(address entryPoint) Ownable(msg.sender) {
        i_entryPoint = IEntryPoint(entryPoint);
    }

    receive() external payable {}
}
