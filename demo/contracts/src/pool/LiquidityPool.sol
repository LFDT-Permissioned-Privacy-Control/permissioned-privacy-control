// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title LiquidityPool - A simple AMM pool with constant product formula
/// @notice Demonstrates CREATE3 circular dependency: needs token address, token needs pool address
/// @dev Uses x*y=k formula for price calculation
contract LiquidityPool is Initializable, UUPSUpgradeable, OwnableUpgradeable {
    /// @notice The token traded in this pool (paired with ETH)
    IERC20 public token;

    /// @notice Reserve of tokens in the pool
    uint256 public tokenReserve;

    /// @notice Reserve of ETH in the pool
    uint256 public ethReserve;

    /// @notice Total LP shares issued
    uint256 public totalShares;

    /// @notice LP share balances
    mapping(address => uint256) public shares;

    /// @notice Emitted when liquidity is added
    event LiquidityAdded(address indexed provider, uint256 tokenAmount, uint256 ethAmount, uint256 shares);

    /// @notice Emitted when liquidity is removed
    event LiquidityRemoved(address indexed provider, uint256 tokenAmount, uint256 ethAmount, uint256 shares);

    /// @notice Emitted when a swap occurs
    event Swap(address indexed user, bool tokenToEth, uint256 amountIn, uint256 amountOut);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initialize the pool
    /// @param initialOwner The owner address
    /// @param tokenAddress The token address (computed via CREATE3 before deployment)
    function initialize(address initialOwner, address tokenAddress) public initializer {
        __Ownable_init(initialOwner);
        token = IERC20(tokenAddress);
    }

    /// @notice Add liquidity to the pool
    /// @param tokenAmount The amount of tokens to add
    /// @return sharesToMint The number of LP shares minted
    function addLiquidity(uint256 tokenAmount) public payable returns (uint256 sharesToMint) {
        require(msg.value > 0, "Must send ETH");
        require(tokenAmount > 0, "Must send tokens");

        if (totalShares == 0) {
            // First liquidity provider sets the initial ratio
            sharesToMint = msg.value; // Use ETH amount as initial shares
        } else {
            // Subsequent providers must match the current ratio
            uint256 ethShare = (msg.value * totalShares) / ethReserve;
            uint256 tokenShare = (tokenAmount * totalShares) / tokenReserve;
            sharesToMint = ethShare < tokenShare ? ethShare : tokenShare;
        }

        require(sharesToMint > 0, "Insufficient liquidity");

        // Transfer tokens from sender
        require(token.transferFrom(msg.sender, address(this), tokenAmount), "Token transfer failed");

        // Update reserves
        tokenReserve += tokenAmount;
        ethReserve += msg.value;

        // Mint shares
        shares[msg.sender] += sharesToMint;
        totalShares += sharesToMint;

        emit LiquidityAdded(msg.sender, tokenAmount, msg.value, sharesToMint);
    }

    /// @notice Remove liquidity from the pool
    /// @param shareAmount The number of LP shares to burn
    /// @return tokenAmount The tokens returned
    /// @return ethAmount The ETH returned
    function removeLiquidity(uint256 shareAmount) public returns (uint256 tokenAmount, uint256 ethAmount) {
        require(shareAmount > 0, "Must burn shares");
        require(shares[msg.sender] >= shareAmount, "Insufficient shares");

        // Calculate amounts to return
        tokenAmount = (shareAmount * tokenReserve) / totalShares;
        ethAmount = (shareAmount * ethReserve) / totalShares;

        // Update state
        shares[msg.sender] -= shareAmount;
        totalShares -= shareAmount;
        tokenReserve -= tokenAmount;
        ethReserve -= ethAmount;

        // Transfer assets
        require(token.transfer(msg.sender, tokenAmount), "Token transfer failed");
        (bool success, ) = msg.sender.call{value: ethAmount}("");
        require(success, "ETH transfer failed");

        emit LiquidityRemoved(msg.sender, tokenAmount, ethAmount, shareAmount);
    }

    /// @notice Swap tokens for ETH
    /// @param tokenAmount The amount of tokens to swap
    /// @return ethOut The amount of ETH received
    function swapTokenForEth(uint256 tokenAmount) public returns (uint256 ethOut) {
        require(tokenAmount > 0, "Amount must be > 0");

        // Calculate output using x*y=k formula
        ethOut = getOutputAmount(tokenAmount, tokenReserve, ethReserve);
        require(ethOut > 0, "Insufficient output");

        // Transfer tokens in
        require(token.transferFrom(msg.sender, address(this), tokenAmount), "Token transfer failed");

        // Update reserves
        tokenReserve += tokenAmount;
        ethReserve -= ethOut;

        // Transfer ETH out
        (bool success, ) = msg.sender.call{value: ethOut}("");
        require(success, "ETH transfer failed");

        emit Swap(msg.sender, true, tokenAmount, ethOut);
    }

    /// @notice Swap ETH for tokens
    /// @return tokenOut The amount of tokens received
    function swapEthForToken() public payable returns (uint256 tokenOut) {
        require(msg.value > 0, "Must send ETH");

        // Calculate output using x*y=k formula
        tokenOut = getOutputAmount(msg.value, ethReserve, tokenReserve);
        require(tokenOut > 0, "Insufficient output");

        // Update reserves
        ethReserve += msg.value;
        tokenReserve -= tokenOut;

        // Transfer tokens out
        require(token.transfer(msg.sender, tokenOut), "Token transfer failed");

        emit Swap(msg.sender, false, msg.value, tokenOut);
    }

    /// @notice Calculate output amount using constant product formula
    /// @param amountIn The input amount
    /// @param reserveIn The input reserve
    /// @param reserveOut The output reserve
    /// @return amountOut The output amount
    function getOutputAmount(
        uint256 amountIn,
        uint256 reserveIn,
        uint256 reserveOut
    ) public pure virtual returns (uint256 amountOut) {
        require(reserveIn > 0 && reserveOut > 0, "Invalid reserves");
        // Simple x*y=k formula without fees
        uint256 numerator = amountIn * reserveOut;
        uint256 denominator = reserveIn + amountIn;
        amountOut = numerator / denominator;
    }

    /// @notice Get the current price of tokens in ETH
    /// @return price The price (scaled by 1e18)
    function getTokenPrice() public view returns (uint256 price) {
        if (tokenReserve == 0) return 0;
        price = (ethReserve * 1e18) / tokenReserve;
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
