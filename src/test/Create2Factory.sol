// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title Child - A simple contract deployed via CREATE2 by the factory
contract Child {
    address public factory;
    uint256 public value;

    constructor(uint256 _initialValue) {
        factory = msg.sender;
        value = _initialValue;
    }

    function setValue(uint256 _value) external {
        value = _value;
    }
}

/// @title Create2Factory - Deploys Child contracts via CREATE2 for testing
/// @dev Used to test that the Open Privacy Suite correctly handles runtime CREATE2
contract Create2Factory {
    event ChildDeployed(address indexed child, bytes32 indexed salt);

    /// @notice Deploy a Child contract using CREATE2
    /// @param salt The salt for deterministic address calculation
    /// @param initialValue The initial value for the Child contract
    /// @return child The address of the deployed Child contract
    function deployChild(bytes32 salt, uint256 initialValue) external returns (address child) {
        bytes memory bytecode = abi.encodePacked(
            type(Child).creationCode,
            abi.encode(initialValue)
        );

        assembly {
            child := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
        }
        require(child != address(0), "CREATE2 failed");

        emit ChildDeployed(child, salt);
        return child;
    }

    /// @notice Predict the address of a Child contract
    /// @param salt The salt used for deployment
    /// @param initialValue The initial value (affects initcode hash)
    /// @return The predicted address
    function predictAddress(bytes32 salt, uint256 initialValue) external view returns (address) {
        bytes memory bytecode = abi.encodePacked(
            type(Child).creationCode,
            abi.encode(initialValue)
        );
        bytes32 hash = keccak256(
            abi.encodePacked(bytes1(0xff), address(this), salt, keccak256(bytecode))
        );
        return address(uint160(uint256(hash)));
    }
}
