// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title Counter - A simple test contract for RBAC testing
/// @notice This contract is used to test contract ownership and permissions in the admin UI
contract Counter {
    uint256 private _count;
    address public owner;

    event CountIncremented(address indexed by, uint256 newCount);
    event CountDecremented(address indexed by, uint256 newCount);
    event CountReset(address indexed by);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    modifier onlyOwner() {
        require(msg.sender == owner, "Counter: caller is not the owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// @notice Get the current count
    function count() external view returns (uint256) {
        return _count;
    }

    /// @notice Increment the counter by 1
    function increment() external {
        _count += 1;
        emit CountIncremented(msg.sender, _count);
    }

    /// @notice Decrement the counter by 1 (reverts if count is 0)
    function decrement() external {
        require(_count > 0, "Counter: count is already zero");
        _count -= 1;
        emit CountDecremented(msg.sender, _count);
    }

    /// @notice Reset the counter to 0 (owner only)
    function reset() external onlyOwner {
        _count = 0;
        emit CountReset(msg.sender);
    }

    /// @notice Transfer ownership (owner only)
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Counter: new owner is the zero address");
        address oldOwner = owner;
        owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}
