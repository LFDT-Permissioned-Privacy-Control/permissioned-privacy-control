// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

/// @title BoxV1 - A simple upgradeable contract for demo purposes
/// @notice This contract stores a value and can be upgraded
contract BoxV1 is Initializable, UUPSUpgradeable, OwnableUpgradeable {
    uint256 private _value;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address initialOwner) public initializer {
        __Ownable_init(initialOwner);
    }

    /// @notice Store a new value
    /// @param newValue The value to store
    function store(uint256 newValue) public {
        _value = newValue;
    }

    /// @notice Retrieve the stored value
    /// @return The stored value
    function retrieve() public view returns (uint256) {
        return _value;
    }

    /// @notice Get the contract version
    /// @return Version string
    function version() public pure virtual returns (string memory) {
        return "1.0.0";
    }

    /// @notice Required by UUPS pattern
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}
