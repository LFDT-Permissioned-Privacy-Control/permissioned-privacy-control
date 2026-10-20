// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title SimpleLiquidityPool - A simple AMM pool for CREATE3 demos
/// @notice This contract demonstrates CREATE3 usage with circular dependencies
/// @dev Non-upgradeable version for simpler demo flow
contract SimpleLiquidityPool is Ownable {
    /// @notice The token address
    address public token;

    /// @notice Token reserves
    uint256 public tokenReserve;

    /// @notice ETH reserves
    uint256 public ethReserve;

    /// @notice Whether the contract has been initialized
    bool private _initialized;

    constructor() Ownable(msg.sender) {}

    /// @notice Initialize the pool contract
    /// @param initialOwner The owner address
    /// @param tokenAddress The token address (computed via CREATE3 before deployment)
    function initialize(address initialOwner, address tokenAddress) public {
        require(!_initialized, "Already initialized");
        _initialized = true;
        _transferOwnership(initialOwner);
        token = tokenAddress;
    }

    /// @notice Add liquidity to the pool
    /// @param tokenAmount The amount of tokens to add
    function addLiquidity(uint256 tokenAmount) public payable {
        require(token != address(0), "Not initialized");
        IERC20(token).transferFrom(msg.sender, address(this), tokenAmount);
        tokenReserve += tokenAmount;
        ethReserve += msg.value;
    }

    /// @notice Get quote for swapping tokens to ETH
    /// @param tokenAmount The amount of tokens to swap
    /// @return ethAmount The amount of ETH that would be received
    function getSwapQuote(uint256 tokenAmount) public view returns (uint256 ethAmount) {
        if (tokenReserve == 0 || ethReserve == 0) return 0;
        // Simple constant product formula
        ethAmount = (tokenAmount * ethReserve) / (tokenReserve + tokenAmount);
    }

    /// @notice Swap tokens for ETH
    /// @param tokenAmount The amount of tokens to swap
    function swapTokensForETH(uint256 tokenAmount) public {
        require(token != address(0), "Not initialized");
        uint256 ethAmount = getSwapQuote(tokenAmount);
        require(ethAmount > 0, "Insufficient liquidity");

        IERC20(token).transferFrom(msg.sender, address(this), tokenAmount);
        tokenReserve += tokenAmount;
        ethReserve -= ethAmount;

        payable(msg.sender).transfer(ethAmount);
    }

    /// @notice Get the contract version
    function version() public pure virtual returns (string memory) {
        return "1.0.0";
    }

    /// @notice Allow receiving ETH
    receive() external payable {}
}
