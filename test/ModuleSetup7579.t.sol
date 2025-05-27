// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {Test, console} from "lib/forge-std/src/Test.sol";
import {EntryPoint} from "lib/account-abstraction/contracts/core/EntryPoint.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";

import {MockModule} from "./mocks/MockModule.sol";
import {ModularWallet} from "../src/ModularWallet.sol";
import {WalletFactory} from "../src/WalletFactory.sol";

import {IERC7579Module} from "../src/erc7579/IERC7579Module.sol";
import {ModuleTypeIds} from "../src/erc7579/ModuleTypeIds.sol";

contract ModuleSetup7579 is Test {
    EntryPoint entryPoint;
    WalletFactory factory;

    function setUp() public {
        // deploy real EntryPoint singleton
        entryPoint = new EntryPoint();
        // wire it into factory
        factory = new WalletFactory(IEntryPoint(address(entryPoint)));
    }

    function testInstallUninstallValidationModule() public {
        // 1) Deploy a wallet for ownerEOA via CREATE2
        address ownerEOA = vm.addr(1);
        bytes32 salt = keccak256("test");
        ModularWallet wallet = factory.createWallet(ownerEOA, salt);

        // 2) Deploy the fake validation module
        MockModule mock = new MockModule();

        // 3) Before installing, supportsModule should be false
        assertFalse(wallet.isModuleInstalled(ModuleTypeIds.VALIDATION, address(mock)));

        // uninstalling before install must revert
        vm.startPrank(ownerEOA);
        vm.expectRevert(ModularWallet.ModuleNotInstalled.selector);
        wallet.uninstallModule(ModuleTypeIds.VALIDATION, address(mock), hex"");

        // 4) Install it
        wallet.installModule(ModuleTypeIds.VALIDATION, address(mock), hex"");
        // module’s onInstall must have run
        assertTrue(mock.installed());
        // wallet should now report it
        assertTrue(wallet.isModuleInstalled(ModuleTypeIds.VALIDATION, address(mock)));

        // 5) Uninstall it
        wallet.uninstallModule(ModuleTypeIds.VALIDATION, address(mock), hex"");
        // module’s onUninstall must have run
        assertFalse(mock.installed());
        // wallet should now report it gone
        assertFalse(wallet.isModuleInstalled(ModuleTypeIds.VALIDATION, address(mock)));
    }
}
