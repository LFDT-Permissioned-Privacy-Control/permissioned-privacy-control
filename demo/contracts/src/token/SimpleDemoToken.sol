// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/// @title SimpleDemoToken - A simple ERC20 token for CREATE3 demos
/// @notice This contract demonstrates CREATE3 usage with circular dependencies
/// @dev Non-upgradeable version for simpler demo flow
contract SimpleDemoToken is ERC20, Ownable {
    /// @notice The liquidity pool address (set during initialization for auto-approval)
    address public pool;

    /// @notice Whether the contract has been initialized
    bool private _initialized;

    constructor() ERC20("Demo Token", "DEMO") Ownable(msg.sender) {}

    /// @notice Initialize the token contract (can only be called once)
    /// @param initialOwner The owner address
    /// @param poolAddress The liquidity pool address (computed via CREATE3 before deployment)
    function initialize(address initialOwner, address poolAddress) public {
        require(!_initialized, "Already initialized");
        _initialized = true;
        _transferOwnership(initialOwner);
        pool = poolAddress;
    }

    /// @notice Mint new tokens (owner only)
    /// @param to The recipient address
    /// @param amount The amount to mint
    function mint(address to, uint256 amount) public onlyOwner {
        _mint(to, amount);
    }

    /// @notice Get the contract version
    /// @return Version string
    function version() public pure virtual returns (string memory) {
        return "1.0.0";
    }
}
