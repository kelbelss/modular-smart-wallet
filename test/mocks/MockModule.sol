// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {IERC7579Module} from "../../src/erc7579/IERC7579Module.sol";

contract MockModule is IERC7579Module {
    bool public installed;

    function onInstall(bytes calldata) external override {
        installed = true;
    }

    function onUninstall(bytes calldata) external override {
        installed = false;
    }

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == 1; // validation module
    }
}
