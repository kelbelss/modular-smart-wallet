// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {IERC7579Module} from "./IERC7579Module.sol";
import {PackedUserOperation} from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";

/// @notice ERC-7780 “signer” module API (typeId = 6)
interface ISigner is IERC7579Module {
    /**
     * @param id the module-config ID
     * @param userOp the full UserOperation
     * @param userOpHash the 4337 hash of the UserOp
     * @return validationData – SIG_VALIDATION_SUCCESS or SIG_VALIDATION_FAILED
     */
    function checkUserOpSignature(bytes32 id, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        payable
        returns (uint256 validationData);

    /**
     * @param id config ID
     * @param sender the account contract
     * @param hash any hash to verify
     * @param sig signature bytes
     * @return magic ERC-1271 magic value on success, or any other 4-byte on failure
     */
    function checkSignature(bytes32 id, address sender, bytes32 hash, bytes calldata sig)
        external
        view
        returns (bytes4 magic);
}
