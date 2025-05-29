// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {Test, console} from "lib/forge-std/src/Test.sol";

import {ModularWallet} from "../src/ModularWallet.sol";
import {WalletFactory} from "../src/WalletFactory.sol";
import {OwnershipManagement} from "../src/modules/OwnershipManagement.sol";

import {P256} from "lib/p256-verifier/src/P256.sol";

import {EntryPoint} from "lib/account-abstraction/contracts/core/EntryPoint.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {UserOperationLib} from "lib/account-abstraction/contracts/core/UserOperationLib.sol";

contract ModularWalletTest is Test {
    using UserOperationLib for PackedUserOperation;

    address ownerEOA;
    uint256 ownerPK;
    address fallbackAdmin;
    EntryPoint entryPoint;
    WalletFactory factory;
    OwnershipManagement ownershipModule;

    function setUp() public {
        entryPoint = new EntryPoint();
        ownershipModule = new OwnershipManagement();
        factory = new WalletFactory(IEntryPoint(address(entryPoint)), address(ownershipModule));

        (ownerEOA, ownerPK) = makeAddrAndKey("OWNER");
        fallbackAdmin = makeAddr("FALLBACK_ADMIN");
    }

    function _pack(uint256 high, uint256 low) internal pure returns (bytes32) {
        require(high <= type(uint128).max && low <= type(uint128).max, "uint128 overflow");
        return bytes32((high << 128) | low);
    }

    function testFullHandleOps() public {
        // 0) Define the ownership init data before computing the counterfactual address
        bytes32 testX = bytes32(uint256(0x123));
        bytes32 testY = bytes32(uint256(0x456));
        bytes memory ownershipInitData = abi.encode(testX, testY, fallbackAdmin);

        bytes32 salt = keccak256("test");
        address predicted = factory.getAddress(salt, ownershipInitData);

        // 1. pre-fund deposit so wallet can pay gas on first tx (or use Bundler attaches msg.value to handleOps method)
        entryPoint.depositTo{value: 1 ether}(predicted);

        // 2. initCode for first time deploy
        bytes memory initCode = abi.encodePacked(
            address(factory), abi.encodeCall(factory.createWallet, (salt, abi.encode(testX, testY, fallbackAdmin)))
        );

        // 3. build minimal UserOperation
        PackedUserOperation memory userOp;
        userOp.sender = predicted;
        userOp.nonce = 0;
        userOp.initCode = initCode;
        userOp.callData = ""; // no action, just deploy + validate
        // uint128 verificationGasLimit = 5000_000;
        // uint128 callGasLimit = 150_000;
        // userOp.accountGasLimits = _pack(verificationGasLimit, callGasLimit);
        // uint128 maxPriorityFeePerGas = 1 gwei;
        // uint128 maxFeePerGas = 1 gwei;
        // userOp.gasFees = _pack(maxFeePerGas, maxPriorityFeePerGas);
        // userOp.preVerificationGas = 25_000;
        // userOp.paymasterAndData = "";

        // 4. sign
        // bytes32 opHash = entryPoint.getUserOpHash(userOp);
        // userOp.signature = _sign(opHash, ownerPK);

        // 4. stub the on‐chain P-256 verifier so it always returns true
        // OwnershipManagement._verify() calls P256.verifySignature under the hood
        // address P256_ADDR = address(P256);
        // vm.mockCall(
        //     P256_ADDR,
        //     abi.encodeWithSelector(
        //         P256.verifySignature.selector,
        //         vm.matchCalldata(),
        //         vm.matchCalldata(),
        //         vm.matchCalldata(),
        //         vm.matchCalldata(),
        //         vm.matchCalldata()
        //     ),
        //     abi.encode(true)
        // );

        // // 5. package a fake PasskeySig into userOp.signature
        // OwnershipManagement.PasskeySig memory ps = OwnershipManagement.PasskeySig({
        //     authenticatorData: hex"11223344", // fake bytes
        //     clientDataJSON: hex"55667788", // fake bytes
        //     r: bytes32(uint256(0xAAA)),
        //     s: bytes32(uint256(0xBBB))
        // });
        // userOp.signature = abi.encode(ps);

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
