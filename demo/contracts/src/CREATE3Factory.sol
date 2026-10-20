// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title CREATE3 Factory (Solmate-compatible)
/// @notice A factory contract for deploying contracts to deterministic addresses using CREATE3
/// @dev This implementation is compatible with the standard Solmate/Solady CREATE3 pattern.
///      The deployed address depends ONLY on factory address and salt, NOT on msg.sender.
contract CREATE3Factory {
    /// @dev The bytecode for the minimal CREATE proxy
    bytes internal constant PROXY_BYTECODE = hex"67363d3d37363d34f03d5260086018f3";

    event ContractDeployed(address indexed deployed, bytes32 indexed salt);

    /// @notice Deploy a contract to a deterministic address
    /// @param salt The salt for CREATE2 deployment of the proxy
    /// @param creationCode The contract creation code to deploy
    /// @return deployed The address of the deployed contract
    function deploy(bytes32 salt, bytes memory creationCode) external payable returns (address deployed) {
        // Deploy the CREATE proxy using CREATE2 (salt used directly, no mixing)
        address proxy;
        bytes memory proxyBytecode = PROXY_BYTECODE;
        assembly {
            proxy := create2(0, add(proxyBytecode, 32), mload(proxyBytecode), salt)
        }
        require(proxy != address(0), "CREATE3: proxy deployment failed");

        // Call the proxy with the creation code to deploy the actual contract
        (bool success, ) = proxy.call{value: msg.value}(creationCode);
        require(success, "CREATE3: deployment failed");

        // Calculate the deployed address (CREATE uses nonce 1 for the first deployment)
        deployed = address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xd6),
            bytes1(0x94),
            proxy,
            bytes1(0x01)
        )))));

        // Verify deployment
        uint256 codeSize;
        assembly { codeSize := extcodesize(deployed) }
        require(codeSize > 0, "CREATE3: deployment verification failed");

        emit ContractDeployed(deployed, salt);
    }

    /// @notice Predict the address a contract will be deployed to
    /// @param salt The salt that will be used for deployment
    /// @return The predicted address (independent of deployer)
    function getDeployed(bytes32 salt) external view returns (address) {
        // Calculate the CREATE2 proxy address
        address proxy = address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xff),
            address(this),
            salt,
            keccak256(PROXY_BYTECODE)
        )))));

        // Calculate the CREATE address (nonce 1)
        return address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xd6),
            bytes1(0x94),
            proxy,
            bytes1(0x01)
        )))));
    }
}
