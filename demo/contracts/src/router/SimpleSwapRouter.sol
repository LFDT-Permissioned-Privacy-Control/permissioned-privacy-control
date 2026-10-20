// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface ISimpleLiquidityPool {
    function getSwapQuote(uint256 tokenAmount) external view returns (uint256);
    function swapTokensForETH(uint256 tokenAmount) external;
}

/// @title SimpleSwapRouter - A simple swap router for CREATE3 demos
/// @notice This contract demonstrates CREATE3 usage with circular dependencies
/// @dev Non-upgradeable version for simpler demo flow
contract SimpleSwapRouter is Ownable {
    /// @notice The pool address
    address public pool;

    /// @notice The token address
    address public token;

    /// @notice Whether the contract has been initialized
    bool private _initialized;

    constructor() Ownable(msg.sender) {}

    /// @notice Initialize the router contract
    /// @param initialOwner The owner address
    /// @param poolAddress The pool address (computed via CREATE3 before deployment)
    /// @param tokenAddress The token address (computed via CREATE3 before deployment)
    function initialize(address initialOwner, address poolAddress, address tokenAddress) public {
        require(!_initialized, "Already initialized");
        _initialized = true;
        _transferOwnership(initialOwner);
        pool = poolAddress;
        token = tokenAddress;
    }

    /// @notice Get quote for swapping tokens to ETH
    /// @param tokenAmount The amount of tokens to swap
    /// @return ethAmount The amount of ETH that would be received
    function getQuote(uint256 tokenAmount) public view returns (uint256) {
        require(pool != address(0), "Not initialized");
        return ISimpleLiquidityPool(pool).getSwapQuote(tokenAmount);
    }

    /// @notice Swap tokens for ETH through the pool
    /// @param tokenAmount The amount of tokens to swap
    function swap(uint256 tokenAmount) public {
        require(pool != address(0) && token != address(0), "Not initialized");

        // Transfer tokens from user to router
        IERC20(token).transferFrom(msg.sender, address(this), tokenAmount);

        // Approve pool to spend tokens
        IERC20(token).approve(pool, tokenAmount);

        // Execute swap
        ISimpleLiquidityPool(pool).swapTokensForETH(tokenAmount);

        // Forward ETH to user
        payable(msg.sender).transfer(address(this).balance);
    }

    /// @notice Get the contract version
    function version() public pure virtual returns (string memory) {
        return "1.0.0";
    }

    /// @notice Allow receiving ETH
    receive() external payable {}
}
