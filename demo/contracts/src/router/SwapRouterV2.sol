// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "./SwapRouter.sol";

/// @title SwapRouterV2 - Upgraded router with deadline and enhanced slippage protection
/// @notice Adds transaction deadline and improved safety features
contract SwapRouterV2 is SwapRouter {
    /// @notice Modifier to check transaction deadline
    /// @param deadline The timestamp by which the transaction must be executed
    modifier ensure(uint256 deadline) {
        require(deadline >= block.timestamp, "Transaction expired");
        _;
    }

    /// @notice Swap exact tokens for ETH with deadline
    /// @param tokenAmount The exact amount of tokens to swap
    /// @param minEthOut The minimum ETH to receive (slippage protection)
    /// @param deadline The timestamp deadline for the transaction
    /// @return ethOut The amount of ETH received
    function swapExactTokensForEthWithDeadline(
        uint256 tokenAmount,
        uint256 minEthOut,
        uint256 deadline
    ) public ensure(deadline) returns (uint256 ethOut) {
        return swapExactTokensForEth(tokenAmount, minEthOut);
    }

    /// @notice Swap exact ETH for tokens with deadline
    /// @param minTokenOut The minimum tokens to receive (slippage protection)
    /// @param deadline The timestamp deadline for the transaction
    /// @return tokenOut The amount of tokens received
    function swapExactEthForTokensWithDeadline(
        uint256 minTokenOut,
        uint256 deadline
    ) public payable ensure(deadline) returns (uint256 tokenOut) {
        return swapExactEthForTokens(minTokenOut);
    }

    /// @notice Calculate minimum output with slippage tolerance
    /// @param expectedOutput The expected output amount
    /// @param slippageBps The slippage tolerance in basis points (e.g., 50 = 0.5%)
    /// @return minOutput The minimum acceptable output
    function calculateMinOutput(
        uint256 expectedOutput,
        uint256 slippageBps
    ) public pure returns (uint256 minOutput) {
        require(slippageBps <= 10000, "Invalid slippage");
        minOutput = (expectedOutput * (10000 - slippageBps)) / 10000;
    }

    /// @notice Convenience function: swap tokens for ETH with slippage tolerance
    /// @param tokenAmount The amount of tokens to swap
    /// @param slippageBps The slippage tolerance in basis points
    /// @param deadline The timestamp deadline
    /// @return ethOut The amount of ETH received
    function swapTokensForEthWithSlippage(
        uint256 tokenAmount,
        uint256 slippageBps,
        uint256 deadline
    ) public ensure(deadline) returns (uint256 ethOut) {
        uint256 expectedOut = getTokenToEthOutput(tokenAmount);
        uint256 minOut = calculateMinOutput(expectedOut, slippageBps);
        return swapExactTokensForEth(tokenAmount, minOut);
    }

    /// @notice Convenience function: swap ETH for tokens with slippage tolerance
    /// @param slippageBps The slippage tolerance in basis points
    /// @param deadline The timestamp deadline
    /// @return tokenOut The amount of tokens received
    function swapEthForTokensWithSlippage(
        uint256 slippageBps,
        uint256 deadline
    ) public payable ensure(deadline) returns (uint256 tokenOut) {
        uint256 expectedOut = getEthToTokenOutput(msg.value);
        uint256 minOut = calculateMinOutput(expectedOut, slippageBps);
        return swapExactEthForTokens(minOut);
    }

    /// @notice Get the contract version
    /// @return Version string
    function version() public pure virtual override returns (string memory) {
        return "2.0.0";
    }
}
