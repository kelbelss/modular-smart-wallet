// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {Test, console} from "lib/forge-std/src/Test.sol";

// ERC-4337 (Account Abstraction - EntryPoint simulations)
import {EntryPointSimulations} from "lib/account-abstraction/contracts/core/EntryPointSimulations.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {UserOperationLib} from "lib/account-abstraction/contracts/core/UserOperationLib.sol";

// Contracts being tested
import {ModularWallet} from "../src/ModularWallet.sol";
import {WalletFactory} from "../src/WalletFactory.sol";
import {OwnershipManagement} from "../src/modules/OwnershipManagement.sol";

// Build a UserOperation whose callData calls rotateKey(newX, newY) on the signer module.
// Runs handleOps, which first validates the old key (faked) then dispatches to execute → module’s rotateKey is triggered.
// Asserts that the on-chain key was updated.

contract RotateKey_OM_Test is Test {
    using UserOperationLib for PackedUserOperation;

    EntryPointSimulations entryPoint;
    WalletFactory factory;
    OwnershipManagement ownershipModule;
    address ownerEOA;
    address fallbackAdmin;

    // Deterministic address Daimo uses for the on-chain P256Verifier
    // The fixed address that the P-256 library staticcalls to on-chain.
    // Intercept any call here and force it to return `true` so that signature verification always succeeds for the sake of this test.
    address constant P256_VERIFIER_ADDRESS = 0xc2b78104907F722DABAc4C69f826a522B2754De4;

    /// @notice Deploy EntryPoint, module & factory, and set P-256 verify to true
    function setUp() public {
        // deploy EntryPoint
        entryPoint = new EntryPointSimulations();
        // deploy the ownership management module
        ownershipModule = new OwnershipManagement();
        // deploy factory, wiring in the EntryPoint & signer module
        factory = new WalletFactory(IEntryPoint(address(entryPoint)), address(ownershipModule));

        // create an EOA to be the owner of the wallet
        ownerEOA = vm.addr(1);

        // create a fallback admin for the ownership module
        fallbackAdmin = vm.addr(2);

        // intercept *any* staticcall to the P-256 precompile and return “true”
        vm.mockCall(P256_VERIFIER_ADDRESS, bytes(""), abi.encode(true));
    }

    /// @notice Full passkey‐rotation flow in one UserOp
    function testRotateKeyFlow() public {
        // A) Deploy a fresh wallet with an initial pubkey (x0,y0)
        bytes32 salt = keccak256("rotate"); // deterministic salt
        bytes32 x0 = bytes32(uint256(0x111));
        bytes32 y0 = bytes32(uint256(0x222));

        // Factory.createWallet(salt, abi.encode(initialX, initialY)) - signed by ownerEOA
        vm.prank(ownerEOA);
        ModularWallet wallet = factory.createWallet(salt, abi.encode(x0, y0, fallbackAdmin));

        // Verify the initial public key stored on-chain
        (bytes32 storedX0, bytes32 storedY0) = ownershipModule.getPublicKey(address(wallet));
        assertEq(storedX0, x0);
        assertEq(storedY0, y0);

        // B) Build a UserOp to call rotateKey(x1, y1) and rotate (x1,y1)
        bytes32 x1 = bytes32(uint256(0x333));
        bytes32 y1 = bytes32(uint256(0x444));

        // Encode: mode=0, (to=ownershipModule, value=0, data=rotateKey(newX,newY))
        bytes32 mode = bytes32(0); // // 3) Include the ERC-4337 “mode” (single-call == bytes32(0))
        // Prepare the module call: rotateKey(x1, y1)
        bytes memory rotateCalldata = abi.encodeCall(OwnershipManagement.rotateKey, (x1, y1));
        // Wrap call in the 7579 execution tuple: (to, value, data)
        bytes memory execCalldata = abi.encode(address(ownershipModule), uint256(0), rotateCalldata);
        // prepend the wallet.execute selector so the execute(mode, execCalldata) entrypoint is invoked
        bytes memory fullCallData = abi.encodeWithSelector(ModularWallet.execute.selector, mode, execCalldata);

        // C) Fill out a minimal PackedUserOperation
        PackedUserOperation memory uo;
        uo.sender = address(wallet);
        uo.nonce = entryPoint.getNonce(address(wallet), 0);
        uo.initCode = ""; // already deployed
        uo.callData = fullCallData;
        uo.accountGasLimits = _pack(500_000, 150_000);
        uo.gasFees = _pack(1 gwei, 1 gwei);
        uo.preVerificationGas = 50_0000;
        uo.paymasterAndData = "";

        // Fake PasskeySig → verifier set to always returns true
        OwnershipManagement.PasskeySig memory ps = OwnershipManagement.PasskeySig({
            authenticatorData: hex"aa",
            clientDataJSON: hex"bb",
            r: bytes32(uint256(1)),
            s: bytes32(uint256(2))
        });
        uo.signature = abi.encode(ps);

        // D) Prefund & execute the bundle via EntryPoint.handleOps

        entryPoint.depositTo{value: 1 ether}(address(wallet)); // wallet must have a deposit so handleOps can pay for gas
        PackedUserOperation[] memory bundle = new PackedUserOperation[](1);
        bundle[0] = uo;
        entryPoint.handleOps(bundle, payable(ownerEOA));

        // E) Verify the rotation worked on-chain
        (bytes32 storedX1, bytes32 storedY1) = ownershipModule.getPublicKey(address(wallet));
        assertEq(storedX1, x1);
        assertEq(storedY1, y1);
    }

    /// @dev Packs two uint128s into a single bytes32 for gas/fee fields
    function _pack(uint256 high, uint256 low) internal pure returns (bytes32) {
        return bytes32((high << 128) | low);
    }
}
