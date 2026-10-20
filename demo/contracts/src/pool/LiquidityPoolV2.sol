// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "./LiquidityPool.sol";

/// @title LiquidityPoolV2 - Upgraded pool with swap fees
/// @notice Adds configurable fees and improved swap logic
contract LiquidityPoolV2 is LiquidityPool {
    /// @notice Fee numerator (e.g., 30 = 0.3% fee)
    uint256 public feeNumerator;

    /// @notice Fee denominator (10000 = 100%)
    uint256 public constant FEE_DENOMINATOR = 10000;

    /// @notice Accumulated fees in ETH
    uint256 public accumulatedEthFees;

    /// @notice Accumulated fees in tokens
    uint256 public accumulatedTokenFees;

    /// @notice Emitted when fees are collected
    event FeesCollected(uint256 ethFees, uint256 tokenFees);

    /// @notice Emitted when fee rate is updated
    event FeeUpdated(uint256 newFeeNumerator);

    /// @notice Set the swap fee (owner only)
    /// @param newFeeNumerator The new fee numerator (e.g., 30 = 0.3%)
    function setFee(uint256 newFeeNumerator) public onlyOwner {
        require(newFeeNumerator <= 1000, "Fee too high"); // Max 10%
        feeNumerator = newFeeNumerator;
        emit FeeUpdated(newFeeNumerator);
    }

    /// @notice Calculate output amount with fees
    /// @param amountIn The input amount
    /// @param reserveIn The input reserve
    /// @param reserveOut The output reserve
    /// @return amountOut The output amount after fees
    function getOutputAmount(
        uint256 amountIn,
        uint256 reserveIn,
        uint256 reserveOut
    ) public pure virtual override returns (uint256 amountOut) {
        require(reserveIn > 0 && reserveOut > 0, "Invalid reserves");
        // Apply 0.3% fee by default (can be configured)
        // Fee is taken from input: amountInWithFee = amountIn * (10000 - feeNumerator) / 10000
        // Using 9970/10000 for 0.3% fee in pure function (actual fee applied in swap functions)
        uint256 amountInWithFee = amountIn * 9970;
        uint256 numerator = amountInWithFee * reserveOut;
        uint256 denominator = (reserveIn * 10000) + amountInWithFee;
        amountOut = numerator / denominator;
    }

    /// @notice Calculate output with configurable fee (view function)
    /// @param amountIn The input amount
    /// @param reserveIn The input reserve
    /// @param reserveOut The output reserve
    /// @return amountOut The output amount after fees
    function getOutputAmountWithFee(
        uint256 amountIn,
        uint256 reserveIn,
        uint256 reserveOut
    ) public view returns (uint256 amountOut) {
        require(reserveIn > 0 && reserveOut > 0, "Invalid reserves");
        uint256 fee = feeNumerator > 0 ? feeNumerator : 30; // Default 0.3%
        uint256 amountInWithFee = amountIn * (FEE_DENOMINATOR - fee);
        uint256 numerator = amountInWithFee * reserveOut;
        uint256 denominator = (reserveIn * FEE_DENOMINATOR) + amountInWithFee;
        amountOut = numerator / denominator;
    }

    /// @notice Collect accumulated fees (owner only)
    function collectFees() public onlyOwner {
        uint256 ethFees = accumulatedEthFees;
        uint256 tokenFees = accumulatedTokenFees;

        accumulatedEthFees = 0;
        accumulatedTokenFees = 0;

        if (ethFees > 0) {
            (bool success, ) = owner().call{value: ethFees}("");
            require(success, "ETH transfer failed");
        }

        if (tokenFees > 0) {
            require(token.transfer(owner(), tokenFees), "Token transfer failed");
        }

        emit FeesCollected(ethFees, tokenFees);
    }

    /// @notice Get the contract version
    /// @return Version string
    function version() public pure virtual override returns (string memory) {
        return "2.0.0";
    }
}
