// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.19;

/**
 * @title Target
 * @notice A simple contract that can be called to verify cross-org isolation.
 * @dev This contract is deployed to Org B. If Org A's Forwarder tries to call it,
 *      the runtime tracer should detect and block this cross-org access.
 */
contract Target {
    uint256 public value;
    address public lastCaller;

    event ValueSet(address indexed caller, uint256 newValue);
    event Pinged(address indexed caller);

    /**
     * @notice Set the stored value
     * @param _value The new value to store
     */
    function setValue(uint256 _value) external {
        value = _value;
        lastCaller = msg.sender;
        emit ValueSet(msg.sender, _value);
    }

    /**
     * @notice Get the stored value
     * @return The current stored value
     */
    function getValue() external view returns (uint256) {
        return value;
    }

    /**
     * @notice A simple function to verify the contract is callable
     */
    function ping() external {
        lastCaller = msg.sender;
        emit Pinged(msg.sender);
    }

    /**
     * @notice Returns a greeting (for testing read calls)
     * @return A greeting string
     */
    function greet() external pure returns (string memory) {
        return "Hello from Target!";
    }
}
