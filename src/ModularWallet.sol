// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

// import {IAccount} from "lib/account-abstraction/contracts/interfaces/IAccount.sol"; // imported in base account
import {PackedUserOperation} from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {BaseAccount} from "lib/account-abstraction/contracts/core/BaseAccount.sol";
import {Ownable} from "lib/openzeppelin-contracts/contracts/access/Ownable.sol"; // remove later on
import {ECDSA} from "lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol"; // remove later on
import {MessageHashUtils} from "lib/openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "lib/account-abstraction/contracts/core/Helpers.sol";

// Put new capabilities in modules (ERC-6900 style).

contract ModularWallet is BaseAccount, Ownable {
    using ECDSA for bytes32;

    // STATE VARIABLES
    IEntryPoint public immutable i_entryPoint;

    constructor(address _entryPoint, address _owner) Ownable(_owner) {
        i_entryPoint = IEntryPoint(_entryPoint);
    }

    // OVERRIDES
    function entryPoint() public view override returns (IEntryPoint) {
        return i_entryPoint;
    }

    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        view
        override
        returns (uint256 validationData)
    {
        bytes32 ethSignedMessageHash = MessageHashUtils.toEthSignedMessageHash(userOpHash);
        address signer = ECDSA.recover(ethSignedMessageHash, userOp.signature);
        if (signer != owner()) {
            return SIG_VALIDATION_FAILED;
        }
        return SIG_VALIDATION_SUCCESS;
    }

    // NOTE: with _validateNonce left empty, EntryPoint’s internal check will still catch replays, but wallet won’t auto-increment??
    function _validateNonce(uint256 nonce) internal view override {
        require(nonce == i_entryPoint.getNonce(address(this), 0), "bad nonce");
    }

    receive() external payable {}
}
