// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title Forwarder
/// @notice A simple forwarding contract used by the demo acceptance suite.
/// @dev The suite uses it to force a trace-level internal call so the
/// block explorer must render internal txs, labels, and counts correctly.
contract Forwarder {
    event ForwardedCall(address indexed target, bool success, bytes returnData);

    function forward(address target, bytes calldata data) external payable returns (bool success, bytes memory returnData) {
        (success, returnData) = target.call{value: msg.value}(data);
        emit ForwardedCall(target, success, returnData);
    }

    function forwardStrict(address target, bytes calldata data) external payable returns (bytes memory returnData) {
        bool success;
        (success, returnData) = target.call{value: msg.value}(data);
        require(success, "Forwarder: call failed");
    }

    function forwardStatic(address target, bytes calldata data) external view returns (bytes memory returnData) {
        bool success;
        (success, returnData) = target.staticcall(data);
        require(success, "Forwarder: staticcall failed");
    }

    function forwardDelegate(address target, bytes calldata data) external returns (bytes memory returnData) {
        bool success;
        (success, returnData) = target.delegatecall(data);
        require(success, "Forwarder: delegatecall failed");
    }

    receive() external payable {}
}
