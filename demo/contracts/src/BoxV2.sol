// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "./BoxV1.sol";

/// @title BoxV2 - Upgraded version of Box with additional features
/// @notice This contract adds increment functionality
contract BoxV2 is BoxV1 {
    /// @notice Increment the stored value by 1
    function increment() public {
        store(retrieve() + 1);
    }

    /// @notice Get the contract version
    /// @return Version string
    function version() public pure virtual override returns (string memory) {
        return "2.0.0";
    }
}
