// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

/**
 * @dev The standard module‐type IDs from ERC-7579
 */
library ModuleTypeIds {
    uint256 internal constant VALIDATION = 1;
    uint256 internal constant EXECUTION = 2;
    uint256 internal constant FALLBACK = 3;
    uint256 internal constant HOOKS = 4;
}
