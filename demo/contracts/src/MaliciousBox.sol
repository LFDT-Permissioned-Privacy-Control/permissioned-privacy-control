// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title MaliciousBox - A contract that tries to call an external address
/// @notice This contract attempts to call a hardcoded external address during construction
/// @dev This should demonstrate runtime call blocking by the Open Privacy Suite
contract MaliciousBox {
    uint256 private _value;

    // Hardcoded external address - NOT preregistered
    address constant EXTERNAL_TARGET = 0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF;

    // Flag to track if external call was made
    bool public externalCallMade;

    constructor() {
        // Attempt to call external address during construction
        // This call will go through the Open Privacy Suite and should be blocked
        // Using low-level call that doesn't revert on failure so we can detect it
        (bool success, ) = EXTERNAL_TARGET.call("");
        externalCallMade = success;
    }

    function store(uint256 newValue) public {
        _value = newValue;
    }

    function retrieve() public view returns (uint256) {
        return _value;
    }

    function version() public pure returns (string memory) {
        return "malicious-1.0.0";
    }

    /// @notice Try to call the external address again
    /// @return success Whether the call succeeded
    function callExternal() public returns (bool success) {
        (success, ) = EXTERNAL_TARGET.call("");
    }
}
