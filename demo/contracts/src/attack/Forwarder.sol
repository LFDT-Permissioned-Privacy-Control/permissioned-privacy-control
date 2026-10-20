// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.19;

/**
 * @title Forwarder
 * @notice A contract that forwards calls to arbitrary addresses.
 * @dev This contract is used to test cross-org isolation.
 *      If a user deploys this to Org A and tries to forward calls to Org B's contracts,
 *      the runtime tracer MUST detect and block this.
 *
 * ATTACK SCENARIO:
 * 1. Attacker deploys Forwarder to Org A
 * 2. Attacker calls forwarder.forward(OrgB_Contract, calldata)
 * 3. Forwarder makes CALL to OrgB_Contract
 * 4. EXPECTED: Runtime tracer detects cross-org call and DENIES the transaction
 */
contract Forwarder {
    event ForwardedCall(address indexed target, bool success, bytes returnData);

    /**
     * @notice Forward a call to any address
     * @param target The address to call
     * @param data The calldata to send
     * @return success Whether the call succeeded
     * @return returnData The return data from the call
     */
    function forward(address target, bytes calldata data) external payable returns (bool success, bytes memory returnData) {
        (success, returnData) = target.call{value: msg.value}(data);
        emit ForwardedCall(target, success, returnData);
    }

    /**
     * @notice Forward a call and revert if it fails
     * @param target The address to call
     * @param data The calldata to send
     * @return returnData The return data from the call
     */
    function forwardStrict(address target, bytes calldata data) external payable returns (bytes memory returnData) {
        bool success;
        (success, returnData) = target.call{value: msg.value}(data);
        require(success, "Forwarder: call failed");
    }

    /**
     * @notice Forward a static call (read-only) to any address
     * @param target The address to call
     * @param data The calldata to send
     * @return returnData The return data from the call
     */
    function forwardStatic(address target, bytes calldata data) external view returns (bytes memory returnData) {
        bool success;
        (success, returnData) = target.staticcall(data);
        require(success, "Forwarder: staticcall failed");
    }

    /**
     * @notice Forward a delegatecall to any address (DANGEROUS - executes in this contract's context)
     * @param target The address to delegatecall
     * @param data The calldata to send
     * @return returnData The return data from the call
     */
    function forwardDelegate(address target, bytes calldata data) external returns (bytes memory returnData) {
        bool success;
        (success, returnData) = target.delegatecall(data);
        require(success, "Forwarder: delegatecall failed");
    }

    receive() external payable {}
}
