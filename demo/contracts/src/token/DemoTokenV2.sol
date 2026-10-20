// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "./DemoToken.sol";

/// @title DemoTokenV2 - Upgraded version of DemoToken with burn functionality
/// @notice Adds burn function for token holders
contract DemoTokenV2 is DemoToken {
    /// @notice Burn tokens from caller's balance
    /// @param amount The amount to burn
    function burn(uint256 amount) public {
        _burn(msg.sender, amount);
    }

    /// @notice Burn tokens from a specific account (requires allowance)
    /// @param account The account to burn from
    /// @param amount The amount to burn
    function burnFrom(address account, uint256 amount) public {
        _spendAllowance(account, msg.sender, amount);
        _burn(account, amount);
    }

    /// @notice Get the contract version
    /// @return Version string
    function version() public pure virtual override returns (string memory) {
        return "2.0.0";
    }
}
