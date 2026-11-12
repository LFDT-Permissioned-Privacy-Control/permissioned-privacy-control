// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.35;

// Application contract for the local walkthrough, never an execution policy.
contract DemoRecord {
    uint256 public value;
    event Changed(address indexed subject, uint256 value);

    function set(address subject, uint256 next) external {
        value = next;
        emit Changed(subject, next);
    }
}
