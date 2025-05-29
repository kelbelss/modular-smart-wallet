// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

// ERC-7579 (Modular Smart Account)
import {IERC7579Module} from "../erc7579/IERC7579Module.sol";
import {IERC7579Execution} from "../erc7579/IERC7579Execution.sol";
import {ModuleTypeIds} from "../erc7579/ModuleTypeIds.sol";

/**
 * @title Dollar-Cost-Averaging (DCA) Execution Module
 * @notice Minimal ERC-7579 EXECUTION module that lets a wallet stream a fixed amount of ETH or an ERC-20
 *         at regular, user-defined intervals.
 * @dev -‐- How it works
 *
 * 1.  The wallet (owner) calls `createPlan()` once through
 *     `wallet.execute(...)`.
 * 2.  Anyone may later trigger `run(planId)` **after** the interval
 *     has elapsed.
 * 3.  `run()` re-schedules itself (`nextExec`) and performs exactly
 *     one transfer:
 *         • ETH → wallet executes a value-call to `destination`.
 *         • ERC-20 → wallet executes `token.transfer(destination, amount)`.
 *
 *  The module never holds funds itself; transfers are performed
 *  *via* the wallet, so balances/allowances remain exactly as if the
 *  owner had signed the call.
 *
 *  ▸ Gas / audit surface kept intentionally tiny for take-home test.
 *
 * @author Kelly Smulian
 */
contract DCA is IERC7579Module {
    // --- Events ---
    event PlanCreated(address indexed wallet, uint256 indexed id);
    event PlanExecuted(address indexed wallet, uint256 indexed id);

    // --- Errors ---
    error DCA_TooEarly();

    // --- Types ---
    struct Plan {
        address token; // ERC-20 or address(0) for native ETH
        address destination; // receiver
        uint96 amount; // amount each run
        uint32 interval; // seconds between runs
        uint64 nextExec; // timestamp when it can run again
    }

    // --- State ---
    /// wallet ⇒ array of its DCA plans
    mapping(address wallet => Plan[]) internal plans;

    // --- Installation ---
    /// @inheritdoc IERC7579Module
    function isModuleType(uint256 id) external pure override returns (bool) {
        return id == ModuleTypeIds.EXECUTION;
    }

    /// @inheritdoc IERC7579Module
    /// @dev no special init needed for this MVP
    function onInstall(bytes calldata) external override { /* nothing */ }

    /// @inheritdoc IERC7579Module
    /// @dev remove all plans for the wallet that un-installs
    function onUninstall(bytes calldata) external override {
        delete plans[msg.sender];
    }

    // --- External Functions ---

    /**
     * @notice Create a new periodic DCA plan.
     * @param token ERC-20 to spend, or `address(0)` for ETH
     * @param destination Receiver of each payment
     * @param amount Exact amount sent every interval
     * @param interval Seconds between two successive runs
     */
    function createPlan(address token, address destination, uint96 amount, uint32 interval) external {
        plans[msg.sender].push(Plan(token, destination, amount, interval, uint64(block.timestamp + interval)));
        emit PlanCreated(msg.sender, plans[msg.sender].length - 1);
    }

    /**
     * @notice Execute one occurrence of a previously created plan.
     * @dev Re-entrancy safe: wallet → DCA → wallet.executeFromExecutor never re-enters this contract.
     * @param  planId  Index returned by `createPlan`
     */
    function run(uint256 planId) external {
        Plan storage plan = plans[msg.sender][planId];
        require(block.timestamp >= plan.nextExec, DCA_TooEarly());
        // schedule next time _before_ external calls
        plan.nextExec = uint64(block.timestamp + plan.interval);

        if (plan.token == address(0)) {
            // native ETH – call via the account so it bubbles gas/payment rules
            IERC7579Execution(msg.sender).executeFromExecutor(
                bytes32(0), // single-call mode
                abi.encode(plan.destination, uint256(plan.amount), bytes("")) // (to,value,data)
            );
        } else {
            // ERC-20 – pull straight from the wallet’s balance
            IERC20(plan.token).transferFrom(msg.sender, plan.destination, plan.amount);

            // IERC7579Execution wallet = IERC7579Execution(msg.sender);
            // bytes memory data = abi.encodeWithSelector(IERC20.transfer.selector, p.dest, p.amount);
            // wallet.executeFromExecutor(bytes32(0), abi.encode(p.token, uint256(0), data));
        }

        emit PlanExecuted(msg.sender, planId);
    }

    // --- Helpers ---
    function getPlan(address wallet, uint256 id) external view returns (Plan memory) {
        return plans[wallet][id];
    }
}
