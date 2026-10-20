// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../src/token/DemoToken.sol";
import "../src/pool/LiquidityPool.sol";
import "../src/router/SwapRouter.sol";

/// @title DeployDeFi - Deploy the DeFi demo contracts
/// @notice This script deploys Token, Pool, and Router with their UUPS proxies
/// @dev For use with Open Privacy Suite, addresses should be preregistered via privacy-cli
contract DeployDeFi is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        console.log("Deployer:", deployer);
        console.log("");

        vm.startBroadcast(deployerPrivateKey);

        // Step 1: Deploy implementation contracts
        console.log("=== Deploying Implementation Contracts ===");

        DemoToken tokenImpl = new DemoToken();
        console.log("DemoToken implementation:", address(tokenImpl));

        LiquidityPool poolImpl = new LiquidityPool();
        console.log("LiquidityPool implementation:", address(poolImpl));

        SwapRouter routerImpl = new SwapRouter();
        console.log("SwapRouter implementation:", address(routerImpl));
        console.log("");

        // Step 2: Deploy proxies with initialization
        // Note: In a CREATE3 deployment, these addresses would be precomputed
        // For this demo, we deploy sequentially and pass addresses

        console.log("=== Deploying Proxy Contracts ===");

        // Deploy Token proxy first (needs pool address - we'll set it to zero initially)
        // DemoToken.initialize(address initialOwner, address poolAddress)
        bytes memory tokenInitData = abi.encodeCall(
            DemoToken.initialize,
            (deployer, address(0))
        );
        ERC1967Proxy tokenProxy = new ERC1967Proxy(address(tokenImpl), tokenInitData);
        address tokenAddress = address(tokenProxy);
        console.log("DemoToken proxy:", tokenAddress);

        // Deploy Pool proxy (needs token address)
        // LiquidityPool.initialize(address initialOwner, address tokenAddress)
        bytes memory poolInitData = abi.encodeCall(
            LiquidityPool.initialize,
            (deployer, tokenAddress)
        );
        ERC1967Proxy poolProxy = new ERC1967Proxy(address(poolImpl), poolInitData);
        address poolAddress = address(poolProxy);
        console.log("LiquidityPool proxy:", poolAddress);

        // Deploy Router proxy (needs both addresses)
        // SwapRouter.initialize(address initialOwner, address poolAddress, address tokenAddress)
        bytes memory routerInitData = abi.encodeCall(
            SwapRouter.initialize,
            (deployer, poolAddress, tokenAddress)
        );
        ERC1967Proxy routerProxy = new ERC1967Proxy(address(routerImpl), routerInitData);
        address routerAddress = address(routerProxy);
        console.log("SwapRouter proxy:", routerAddress);
        console.log("");

        // Step 3: Setup complete
        console.log("=== Setup Complete ===");
        console.log("Note: Pool address in Token is set to zero (would need setter for circular ref)");

        console.log("");
        console.log("=== Deployment Complete ===");
        console.log("Token:  ", tokenAddress);
        console.log("Pool:   ", poolAddress);
        console.log("Router: ", routerAddress);

        vm.stopBroadcast();
    }
}

/// @dev CREATE3 Factory interface for deterministic deployments
interface ICREATE3Factory {
    function deploy(bytes32 salt, bytes memory creationCode) external payable returns (address deployed);
    function getDeployed(address deployer, bytes32 salt) external view returns (address deployed);
}

/// @title DeployDeFiWithCREATE3 - Deploy using CREATE3 factory
/// @notice This demonstrates the CREATE3 deployment flow with precomputed addresses
contract DeployDeFiWithCREATE3 is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        address factory = vm.envAddress("CREATE3_FACTORY");

        console.log("Deployer:", deployer);
        console.log("Factory:", factory);
        console.log("");

        // Step 1: Compute addresses deterministically
        console.log("=== Computing CREATE3 Addresses ===");

        bytes32 tokenSalt = keccak256(abi.encodePacked("DemoToken", deployer));
        bytes32 poolSalt = keccak256(abi.encodePacked("LiquidityPool", deployer));
        bytes32 routerSalt = keccak256(abi.encodePacked("SwapRouter", deployer));

        address tokenAddress = ICREATE3Factory(factory).getDeployed(deployer, tokenSalt);
        address poolAddress = ICREATE3Factory(factory).getDeployed(deployer, poolSalt);
        address routerAddress = ICREATE3Factory(factory).getDeployed(deployer, routerSalt);

        console.log("Token will be at:", tokenAddress);
        console.log("Pool will be at:", poolAddress);
        console.log("Router will be at:", routerAddress);
        console.log("");

        vm.startBroadcast(deployerPrivateKey);

        // Step 2: Deploy implementations
        console.log("=== Deploying Implementations ===");

        DemoToken tokenImpl = new DemoToken();
        LiquidityPool poolImpl = new LiquidityPool();
        SwapRouter routerImpl = new SwapRouter();

        // Step 3: Deploy proxies via CREATE3
        // The key insight: we can pass the PRECOMPUTED addresses to constructors
        // because CREATE3 guarantees the deployment addresses

        console.log("=== Deploying Proxies via CREATE3 ===");

        // Token proxy - can now reference pool address that doesn't exist yet!
        // DemoToken.initialize(address initialOwner, address poolAddress)
        bytes memory tokenCreationCode = abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(
                address(tokenImpl),
                abi.encodeCall(DemoToken.initialize, (deployer, poolAddress))
            )
        );
        ICREATE3Factory(factory).deploy(tokenSalt, tokenCreationCode);
        console.log("Deployed Token at:", tokenAddress);

        // Pool proxy - references token that was just deployed
        // LiquidityPool.initialize(address initialOwner, address tokenAddress)
        bytes memory poolCreationCode = abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(
                address(poolImpl),
                abi.encodeCall(LiquidityPool.initialize, (deployer, tokenAddress))
            )
        );
        ICREATE3Factory(factory).deploy(poolSalt, poolCreationCode);
        console.log("Deployed Pool at:", poolAddress);

        // Router proxy - references both
        // SwapRouter.initialize(address initialOwner, address poolAddress, address tokenAddress)
        bytes memory routerCreationCode = abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(
                address(routerImpl),
                abi.encodeCall(SwapRouter.initialize, (deployer, poolAddress, tokenAddress))
            )
        );
        ICREATE3Factory(factory).deploy(routerSalt, routerCreationCode);
        console.log("Deployed Router at:", routerAddress);

        vm.stopBroadcast();

        console.log("");
        console.log("=== CREATE3 Deployment Complete ===");
        console.log("All contracts deployed with circular references resolved!");
    }
}
