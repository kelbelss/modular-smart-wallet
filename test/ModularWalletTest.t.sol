// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {Test, console} from "lib/forge-std/src/Test.sol";
import {ModularWallet} from "../src/ModularWallet.sol";
import {WalletFactory} from "../src/WalletFactory.sol";

import {EntryPoint} from "lib/account-abstraction/contracts/core/EntryPoint.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {UserOperationLib} from "lib/account-abstraction/contracts/core/UserOperationLib.sol";
import {ECDSA} from "lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "lib/openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol"; // remove later on

contract ModularWalletTest is Test {
    using UserOperationLib for PackedUserOperation;
    using MessageHashUtils for bytes32;

    address ownerEOA;
    uint256 ownerPK;
    EntryPoint entryPoint;
    WalletFactory factory;

    function setUp() public {
        entryPoint = new EntryPoint();
        factory = new WalletFactory(IEntryPoint(address(entryPoint)));

        (ownerEOA, ownerPK) = makeAddrAndKey("OWNER");
    }

    // quick signer helper (ECDSA for now) - placeholder
    function _sign(bytes32 hash, uint256 pk) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, hash.toEthSignedMessageHash());
        return abi.encodePacked(r, s, v);
    }

    function _pack(uint256 high, uint256 low) internal pure returns (bytes32) {
        require(high <= type(uint128).max && low <= type(uint128).max, "uint128 overflow");
        return bytes32((high << 128) | low);
    }

    function testFullHandleOps() public {
        bytes32 salt = keccak256("test");
        address predicted = factory.getAddress(ownerEOA, salt);

        // 1. pre-fund deposit so wallet can pay gas on first tx (or use Bundler attaches msg.value to handleOps method)
        entryPoint.depositTo{value: 1 ether}(predicted);

        // 2. initCode for first time deploy
        bytes memory initCode =
            abi.encodePacked(address(factory), abi.encodeCall(factory.createWallet, (ownerEOA, salt)));

        // 3. build minimal UserOperation
        PackedUserOperation memory userOp;
        userOp.sender = predicted;
        userOp.nonce = 0;
        userOp.initCode = initCode;
        userOp.callData = ""; // no action, just deploy + validate
        uint128 verificationGasLimit = 1500_000;
        uint128 callGasLimit = 150_000;
        userOp.accountGasLimits = _pack(verificationGasLimit, callGasLimit);
        uint128 maxPriorityFeePerGas = 1 gwei;
        uint128 maxFeePerGas = 1 gwei;
        userOp.gasFees = _pack(maxFeePerGas, maxPriorityFeePerGas);
        userOp.preVerificationGas = 25_000;
        userOp.paymasterAndData = "";

        // 4. sign
        bytes32 opHash = entryPoint.getUserOpHash(userOp);
        userOp.signature = _sign(opHash, ownerPK);

        // 5. simulateValidation off-chain
        // entryPoint.simulateValidation(userOp); // removed

        // 6. bundle and execute
        PackedUserOperation[] memory bundle = new PackedUserOperation[](1);
        bundle[0] = userOp;

        address beneficiary = vm.addr(100); // bundler’s fee receiver
        uint256 balBefore = beneficiary.balance;

        entryPoint.handleOps(bundle, payable(beneficiary));

        // 7. assertions

        // wallet should now be deployed
        assertGt(predicted.code.length, 0, "wallet not deployed");

        // beneficiary (bundler) got paid some ETH
        assertGt(beneficiary.balance, balBefore, "bundler not reimbursed");

        // nonce consumed
        assertEq(entryPoint.getNonce(predicted, 0), 1, "nonce not bumped");
    }
}
