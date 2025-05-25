// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

// Factory - a helper contract that performs a deployment for a new sender contract if necessary.

// Factory Contract - When using a wallet for the first time, the initCode field of the UserOperation is used to specify creation of the smart contract wallet. This is used concurrently with the first actual operation of the wallet (in the same UserOperation). Therefore, wallet developers also need to implement the account factory contract (for example: BLSAccountFactory.sol(opens in a new tab)). Creating new wallets should use the CREATE2 method to ensure the determinacy of generated addresses. CREATE2

contract WalletFactory {}
