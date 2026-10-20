// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";

/// @title DemoToken - A simple UUPS upgradeable ERC20 token
/// @notice This contract demonstrates CREATE3 usage with circular dependencies
/// @dev The pool address is passed in constructor to enable auto-approval for swaps
contract DemoToken is Initializable, ERC20Upgradeable, UUPSUpgradeable, OwnableUpgradeable {
    /// @notice The liquidity pool address (set during initialization for auto-approval)
    address public pool;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initialize the token contract
    /// @param initialOwner The owner address
    /// @param poolAddress The liquidity pool address (computed via CREATE3 before deployment)
    function initialize(address initialOwner, address poolAddress) public initializer {
        __ERC20_init("Demo Token", "DEMO");
        __Ownable_init(initialOwner);
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

    /// @notice Required by UUPS pattern
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}
