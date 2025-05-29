// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

/**
 * @title DCA_ModuleTest
 * @notice Happy path test: create an ETH plan, wait a day, run it once.
 */
import {Test, console} from "lib/forge-std/src/Test.sol";

// ERC-4337 (Account Abstraction - EntryPoint simulations)
import {EntryPointSimulations} from "lib/account-abstraction/contracts/core/EntryPointSimulations.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";

// Contracts being tested
import {ModularWallet} from "../src/ModularWallet.sol";
import {WalletFactory} from "../src/WalletFactory.sol";
import {OwnershipManagement} from "../src/modules/OwnershipManagement.sol";
import {DCA} from "../src/modules/DCA.sol";

// ERC-7579 (Modular Smart Wallet)
import {ModuleTypeIds} from "../src/erc7579/ModuleTypeIds.sol";

contract DCA_ModuleTest is Test {
    EntryPointSimulations private entryPoint;
    WalletFactory private factory;
    OwnershipManagement private ownershipModule;
    DCA private dca;
    ModularWallet private wallet;

    address beneficiary = makeAddr("BENEFICIARY");
    address fallbackAdmin = makeAddr("FALLBACK_ADMIN");

    function setUp() public {
        entryPoint = new EntryPointSimulations();
        ownershipModule = new OwnershipManagement();
        factory = new WalletFactory(IEntryPoint(address(entryPoint)), address(ownershipModule));
        dca = new DCA();

        // create wallet (fake key: x=1,y=2, fallbackAdmin)
        bytes32 salt = keccak256("dca-test");
        wallet = factory.createWallet(salt, abi.encode(bytes32(uint256(1)), bytes32(uint256(2)), fallbackAdmin));

        /// install DCA module (EntryPoint calls the wallet)
        vm.prank(address(entryPoint));
        wallet.installModule(ModuleTypeIds.EXECUTION, address(dca), "");

        // fund wallet with 1 ether
        vm.deal(address(wallet), 1 ether);
    }

    function test_ethDcaPlan() public {
        // A) create a plan
        vm.prank(address(wallet)); // simulate call THROUGH the wallet
        dca.createPlan(address(0), beneficiary, 0.1 ether, 1 days);

        // B warp forward 1 day
        vm.warp(block.timestamp + 1 days);

        uint256 before = beneficiary.balance;

        // C) run the plan
        vm.prank(address(wallet)); // run() must see msg.sender == wallet
        dca.run(0);

        // D) assertions
        assertEq(beneficiary.balance, before + 0.1 ether, "transfer failed");

        // nextExec should now be > block.timestamp
        DCA.Plan memory fetchedPlan = dca.getPlan(address(wallet), 0);
        uint64 nextExec = fetchedPlan.nextExec;
        assertGt(nextExec, uint64(block.timestamp), "nextExec not updated");
    }
}
