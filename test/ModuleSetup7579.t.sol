// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {Test, console} from "lib/forge-std/src/Test.sol";

// ERC-4337 EntryPoint simulation
import {EntryPointSimulations} from "lib/account-abstraction/contracts/core/EntryPointSimulations.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";

// Contracts being tested
import {ModularWallet} from "../src/ModularWallet.sol";
import {WalletFactory} from "../src/WalletFactory.sol";
import {OwnershipManagement} from "../src/modules/OwnershipManagement.sol";

// ERC-7579 Modular SCs code
import {MockModule} from "./mocks/MockModule.sol";
import {IERC7579Module} from "../src/erc7579/IERC7579Module.sol";
import {ModuleTypeIds} from "../src/erc7579/ModuleTypeIds.sol";

contract ModuleSetup7579 is Test {
    EntryPointSimulations entryPoint;
    WalletFactory factory;
    OwnershipManagement ownershipModule;

    function setUp() public {
        // deploy EntryPoint
        entryPoint = new EntryPointSimulations();
        // deploy the ownership management module
        ownershipModule = new OwnershipManagement();
        // deploy factory, wiring in the EntryPoint & signer module
        factory = new WalletFactory(IEntryPoint(address(entryPoint)), address(ownershipModule));
    }

    function testInstallUninstallValidationModule() public {
        // A) Deploy a wallet for ownerEOA via CREATE2
        address ownerEOA = vm.addr(1);
        bytes32 salt = keccak256("test");
        bytes32 testX = bytes32(uint256(0x123));
        bytes32 testY = bytes32(uint256(0x456));
        vm.prank(ownerEOA);
        ModularWallet wallet = factory.createWallet(salt, abi.encode(testX, testY));

        assertTrue(
            wallet.isModuleInstalled(ModuleTypeIds.SIGNER, address(ownershipModule)),
            "ownership module must be auto-installed"
        );

        // B) Deploy the fake validation module
        MockModule mock = new MockModule();

        // C) Before installing, supportsModule should be false
        assertFalse(wallet.isModuleInstalled(ModuleTypeIds.VALIDATION, address(mock)));

        // uninstalling before install must revert
        vm.startPrank(address(entryPoint));
        vm.expectRevert(ModularWallet.ModuleNotInstalled.selector);
        wallet.uninstallModule(ModuleTypeIds.VALIDATION, address(mock), hex"");

        // D) Install it
        wallet.installModule(ModuleTypeIds.VALIDATION, address(mock), hex"");
        // module’s onInstall must have run
        assertTrue(mock.installed());
        // wallet should now report it
        assertTrue(wallet.isModuleInstalled(ModuleTypeIds.VALIDATION, address(mock)));

        // E) Uninstall it
        wallet.uninstallModule(ModuleTypeIds.VALIDATION, address(mock), hex"");
        // module’s onUninstall must have run
        assertFalse(mock.installed());
        // wallet should now report it gone
        assertFalse(wallet.isModuleInstalled(ModuleTypeIds.VALIDATION, address(mock)));
    }
}
