// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "../pool/LiquidityPool.sol";

/// @title SwapRouter - Router for swap operations
/// @notice Provides a unified interface for swapping through liquidity pools
/// @dev Demonstrates CREATE3 usage: needs both Pool and Token addresses
contract SwapRouter is Initializable, UUPSUpgradeable, OwnableUpgradeable {
    /// @notice The liquidity pool contract
    LiquidityPool public pool;

    /// @notice The token contract
    IERC20 public token;

    /// @notice Emitted when a swap is executed through the router
    event RouterSwap(
        address indexed user,
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 amountOut
    );

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initialize the router
    /// @param initialOwner The owner address
    /// @param poolAddress The pool address (computed via CREATE3 before deployment)
    /// @param tokenAddress The token address (computed via CREATE3 before deployment)
    function initialize(
        address initialOwner,
        address poolAddress,
        address tokenAddress
    ) public initializer {
        __Ownable_init(initialOwner);
        pool = LiquidityPool(payable(poolAddress));
        token = IERC20(tokenAddress);
    }

    /// @notice Swap exact tokens for ETH
    /// @param tokenAmount The exact amount of tokens to swap
    /// @param minEthOut The minimum ETH to receive (slippage protection)
    /// @return ethOut The amount of ETH received
    function swapExactTokensForEth(
        uint256 tokenAmount,
        uint256 minEthOut
    ) public returns (uint256 ethOut) {
        require(tokenAmount > 0, "Amount must be > 0");

        // Transfer tokens from user to router
        require(token.transferFrom(msg.sender, address(this), tokenAmount), "Transfer failed");

        // Approve pool to spend tokens
        require(token.approve(address(pool), tokenAmount), "Approve failed");

        // Execute swap
        ethOut = pool.swapTokenForEth(tokenAmount);
        require(ethOut >= minEthOut, "Insufficient output");

        // Transfer ETH to user
        (bool success, ) = msg.sender.call{value: ethOut}("");
        require(success, "ETH transfer failed");

        emit RouterSwap(msg.sender, address(token), address(0), tokenAmount, ethOut);
    }

    /// @notice Swap exact ETH for tokens
    /// @param minTokenOut The minimum tokens to receive (slippage protection)
    /// @return tokenOut The amount of tokens received
    function swapExactEthForTokens(uint256 minTokenOut) public payable returns (uint256 tokenOut) {
        require(msg.value > 0, "Must send ETH");

        // Execute swap
        tokenOut = pool.swapEthForToken{value: msg.value}();
        require(tokenOut >= minTokenOut, "Insufficient output");

        // Transfer tokens to user
        require(token.transfer(msg.sender, tokenOut), "Token transfer failed");

        emit RouterSwap(msg.sender, address(0), address(token), msg.value, tokenOut);
    }

    /// @notice Get expected output for a token to ETH swap
    /// @param tokenAmount The input token amount
    /// @return ethOut The expected ETH output
    function getTokenToEthOutput(uint256 tokenAmount) public view returns (uint256 ethOut) {
        ethOut = pool.getOutputAmount(tokenAmount, pool.tokenReserve(), pool.ethReserve());
    }

    /// @notice Get expected output for an ETH to token swap
    /// @param ethAmount The input ETH amount
    /// @return tokenOut The expected token output
    function getEthToTokenOutput(uint256 ethAmount) public view returns (uint256 tokenOut) {
        tokenOut = pool.getOutputAmount(ethAmount, pool.ethReserve(), pool.tokenReserve());
    }

    /// @notice Get the contract version
    /// @return Version string
    function version() public pure virtual returns (string memory) {
        return "1.0.0";
    }

    /// @notice Required by UUPS pattern
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    /// @notice Allow contract to receive ETH
    receive() external payable {}
}
