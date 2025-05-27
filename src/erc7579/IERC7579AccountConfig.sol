// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

/**
 * @title ERC-7579 Account Configuration Interface
 * @dev Every account MUST implement these so tools know what it supports.
 */
interface IERC7579AccountConfig {
    /// A unique string identifying this account implementation, e.g. "acme.wallet.v1"
    function accountId() external view returns (string memory);

    /// Returns true if this account supports the given execution mode.
    function supportsExecutionMode(bytes32 mode) external view returns (bool);

    /// Returns true if the given module (address) of that typeId is installed.
    function supportsModule(uint256 moduleTypeId) external view returns (bool);
}
