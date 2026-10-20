package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// fundAccounts sends ETH to all test accounts from the funding account
func (lt *LoadTester) fundAccounts(ctx context.Context) error {
	fundingAddr := crypto.PubkeyToAddress(lt.fundingKey.PublicKey)

	// Get funding account nonce
	nonce, err := lt.nodeClient.NonceAt(ctx, fundingAddr, nil)
	if err != nil {
		return fmt.Errorf("failed to get funding nonce: %w", err)
	}

	// Amount to fund each account (10 ETH)
	amount := new(big.Int).Mul(big.NewInt(10), big.NewInt(1000000000000000000)) // 10 ETH in wei
	gasLimit := uint64(21000)
	gasPrice := big.NewInt(1000000000) // 1 gwei

	for i, acc := range lt.accounts {
		tx := types.NewTransaction(
			nonce,
			acc.Address,
			amount,
			gasLimit,
			gasPrice,
			nil,
		)

		signedTx, err := types.SignTx(tx, types.NewEIP155Signer(lt.chainID), lt.fundingKey)
		if err != nil {
			return fmt.Errorf("failed to sign funding tx: %w", err)
		}

		if err := lt.nodeClient.SendTransaction(ctx, signedTx); err != nil {
			return fmt.Errorf("failed to send funding tx to account %d: %w", i, err)
		}

		nonce++
		fmt.Printf("  Funded account %d: %s\n", i, acc.Address.Hex())
	}

	// Wait for last tx to be mined
	fmt.Println("  Waiting for funding txs to be mined...")
	time.Sleep(2 * time.Second)

	return nil
}

// setupProxyAuth creates org, group, and users in the proxy
func (lt *LoadTester) setupProxyAuth(ctx context.Context) error {
	// Create organization
	orgSlug := fmt.Sprintf("loadtest-%d", time.Now().Unix())
	orgResp, err := lt.apiCall(ctx, "POST", "/api/v1/orgs", map[string]interface{}{
		"slug": orgSlug,
		"name": "Load Test Organization",
	})
	if err != nil {
		return fmt.Errorf("failed to create org: %w", err)
	}
	lt.orgID = orgResp["id"].(string)
	fmt.Printf("  Created org: %s (id: %s)\n", orgSlug, lt.orgID)

	// Create group
	groupResp, err := lt.apiCall(ctx, "POST", fmt.Sprintf("/api/v1/orgs/%s/groups", lt.orgID), map[string]interface{}{
		"slug": "loadtest-users",
		"name": "Load Test Users",
	})
	if err != nil {
		return fmt.Errorf("failed to create group: %w", err)
	}
	lt.groupID = groupResp["id"].(string)
	fmt.Printf("  Created group: loadtest-users (id: %s)\n", lt.groupID)

	// Set group access with all necessary permissions
	_, err = lt.apiCall(ctx, "PUT", fmt.Sprintf("/api/v1/orgs/%s/groups/%s/access", lt.orgID, lt.groupID), map[string]interface{}{
		"allowed_methods": []string{
			"eth_call",
			"eth_sendRawTransaction",
			"eth_sendTransaction",
			"eth_estimateGas",
			"eth_getBalance",
			"eth_getCode",
			"eth_getTransactionCount",
			"eth_getTransactionReceipt",
			"eth_blockNumber",
			"eth_chainId",
			"eth_gasPrice",
		},
		"claims": []string{"deploy"},
	})
	if err != nil {
		return fmt.Errorf("failed to set group access: %w", err)
	}
	fmt.Println("  Set group access permissions")

	// Authenticate each account and add to group
	for i, acc := range lt.accounts {
		// Get JWT token via mock login
		token, err := lt.getJWTToken(ctx, acc.DID())
		if err != nil {
			return fmt.Errorf("failed to get JWT for account %d: %w", i, err)
		}
		acc.JWTToken = token

		// Find user ID
		usersResp, err := lt.apiCall(ctx, "GET", "/api/v1/users", nil)
		if err != nil {
			return fmt.Errorf("failed to list users: %w", err)
		}

		var userID string
		if users, ok := usersResp["users"].([]interface{}); ok {
			for _, u := range users {
				user := u.(map[string]interface{})
				if user["external_id"] == acc.DID() {
					userID = user["id"].(string)
					break
				}
			}
		}

		// Also check if response is an array directly
		if userID == "" {
			// Try parsing as direct array
			var users []map[string]interface{}
			respBytes, _ := json.Marshal(usersResp)
			if err := json.Unmarshal(respBytes, &users); err == nil {
				for _, user := range users {
					if user["external_id"] == acc.DID() {
						userID = user["id"].(string)
						break
					}
				}
			}
		}

		if userID == "" {
			return fmt.Errorf("user not found after auth for account %d", i)
		}

		// Update KYC status
		_, err = lt.apiCall(ctx, "PUT", fmt.Sprintf("/api/v1/users/%s", userID), map[string]interface{}{
			"kyc": true,
		})
		if err != nil {
			return fmt.Errorf("failed to update KYC for account %d: %w", i, err)
		}

		// Add to group
		_, err = lt.apiCall(ctx, "POST", fmt.Sprintf("/api/v1/users/%s/memberships", userID), map[string]interface{}{
			"org_id":   lt.orgID,
			"group_id": lt.groupID,
		})
		if err != nil {
			return fmt.Errorf("failed to add account %d to group: %w", i, err)
		}

		// Refresh token after membership
		token, err = lt.getJWTToken(ctx, acc.DID())
		if err != nil {
			return fmt.Errorf("failed to refresh JWT for account %d: %w", i, err)
		}
		acc.JWTToken = token

		fmt.Printf("  Authenticated account %d: %s\n", i, acc.Address.Hex())
	}

	return nil
}

// getJWTToken gets a JWT token for the given DID using mock login
// This follows the two-step auth flow: /auth/request -> /auth/verify
func (lt *LoadTester) getJWTToken(ctx context.Context, did string) (string, error) {
	// Step 1: Create auth request to get session ID
	req, err := http.NewRequestWithContext(ctx, "POST", lt.cfg.ProxyURL+"/auth/request", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := lt.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("auth request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("auth request failed with %d: %s", resp.StatusCode, string(body))
	}

	var authReqResult struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&authReqResult); err != nil {
		return "", fmt.Errorf("failed to decode auth request response: %w", err)
	}

	// Step 2: Verify with mock JWZ token
	verifyBody := map[string]interface{}{
		"session_id": authReqResult.SessionID,
		"jwz_token":  fmt.Sprintf("mock.%s", did),
	}
	bodyBytes, _ := json.Marshal(verifyBody)

	req2, err := http.NewRequestWithContext(ctx, "POST", lt.cfg.ProxyURL+"/auth/verify", bytes.NewReader(bodyBytes))
	if err != nil {
		return "", err
	}
	req2.Header.Set("Content-Type", "application/json")

	resp2, err := lt.httpClient.Do(req2)
	if err != nil {
		return "", fmt.Errorf("auth verify failed: %w", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp2.Body)
		return "", fmt.Errorf("auth verify failed with %d: %s", resp2.StatusCode, string(body))
	}

	var verifyResult struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&verifyResult); err != nil {
		return "", fmt.Errorf("failed to decode verify response: %w", err)
	}

	if verifyResult.AccessToken == "" {
		return "", fmt.Errorf("no access_token in response")
	}

	return verifyResult.AccessToken, nil
}

// deployContracts deploys the test ERC20 token contracts directly to the node
// and registers them with the proxy RBAC system
func (lt *LoadTester) deployContracts(ctx context.Context) error {
	// Use first account for deployment
	deployer := lt.accounts[0]

	// Get current nonce from chain (in case of re-runs)
	nonce, err := lt.nodeClient.NonceAt(ctx, deployer.Address, nil)
	if err != nil {
		return fmt.Errorf("failed to get deployer nonce: %w", err)
	}
	deployer.SetNonce(nonce)

	// Deploy Token A
	tokenAAddr, err := lt.deployERC20(ctx, deployer, "LoadTestTokenA", "LTA")
	if err != nil {
		return fmt.Errorf("failed to deploy Token A: %w", err)
	}
	lt.tokenA = tokenAAddr
	fmt.Printf("  Deployed Token A: %s\n", tokenAAddr.Hex())

	// Deploy Token B
	tokenBAddr, err := lt.deployERC20(ctx, deployer, "LoadTestTokenB", "LTB")
	if err != nil {
		return fmt.Errorf("failed to deploy Token B: %w", err)
	}
	lt.tokenB = tokenBAddr
	fmt.Printf("  Deployed Token B: %s\n", tokenBAddr.Hex())

	// Wait for deployments to be mined
	time.Sleep(2 * time.Second)

	// Register contracts with the proxy RBAC system
	// This allows users to access them through the proxy
	fmt.Println("  Registering contracts with proxy...")
	if err := lt.registerContract(ctx, tokenAAddr, "LoadTestTokenA"); err != nil {
		fmt.Printf("  Warning: failed to register Token A: %v\n", err)
	}
	if err := lt.registerContract(ctx, tokenBAddr, "LoadTestTokenB"); err != nil {
		fmt.Printf("  Warning: failed to register Token B: %v\n", err)
	}

	return nil
}

// registerContract registers a contract with the proxy RBAC system
func (lt *LoadTester) registerContract(ctx context.Context, addr common.Address, name string) error {
	_, err := lt.apiCall(ctx, "POST", fmt.Sprintf("/api/v1/orgs/%s/contracts", lt.orgID), map[string]interface{}{
		"address": addr.Hex(),
		"name":    name,
		"claims":  []string{},
	})
	return err
}

// deployERC20 deploys a simple ERC20 token contract directly to the node
// Note: We deploy directly to node (bypassing proxy) because the proxy requires
// runtime tracing for eth_sendRawTransaction. Contract calls during the load
// test will go through the proxy.
func (lt *LoadTester) deployERC20(ctx context.Context, deployer *Account, _, _ string) (common.Address, error) {
	// Use a minimal ERC20 that auto-mints tokens to deployer (no constructor args needed)
	deployData := getMinimalERC20Bytecode()

	nonce := deployer.GetAndIncrementNonce()
	gasLimit := uint64(2000000)
	gasPrice := big.NewInt(10000000000) // 10 gwei for faster inclusion

	tx := types.NewContractCreation(
		nonce,
		big.NewInt(0),
		gasLimit,
		gasPrice,
		deployData,
	)

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(lt.chainID), deployer.PrivateKey)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to sign deploy tx: %w", err)
	}

	// Send directly to node (bypass proxy for deployment)
	if err := lt.nodeClient.SendTransaction(ctx, signedTx); err != nil {
		return common.Address{}, fmt.Errorf("failed to send deploy tx: %w", err)
	}

	// Calculate contract address
	contractAddr := crypto.CreateAddress(deployer.Address, nonce)

	// Wait for transaction to be mined
	txHash := signedTx.Hash()
	fmt.Printf("    Waiting for tx %s...\n", txHash.Hex())

	for i := 0; i < 60; i++ { // Wait up to 60 seconds
		receipt, err := lt.nodeClient.TransactionReceipt(ctx, txHash)
		if err == nil && receipt != nil {
			if receipt.Status == 1 {
				fmt.Printf("    Deployed at block %d\n", receipt.BlockNumber.Uint64())
				break
			} else {
				return common.Address{}, fmt.Errorf("deployment tx reverted")
			}
		}
		time.Sleep(1 * time.Second)
	}

	// Verify deployment
	code, err := lt.nodeClient.CodeAt(ctx, contractAddr, nil)
	if err != nil || len(code) == 0 {
		return common.Address{}, fmt.Errorf("contract not deployed at expected address %s", contractAddr.Hex())
	}

	return contractAddr, nil
}

// distributeTokens sends tokens from deployer to all other accounts
func (lt *LoadTester) distributeTokens(ctx context.Context) error {
	deployer := lt.accounts[0]

	// Amount to send to each account
	amount := new(big.Int).Mul(big.NewInt(10000), big.NewInt(1e18)) // 10K tokens

	for i, acc := range lt.accounts {
		if i == 0 {
			continue // Skip deployer
		}

		// Transfer Token A
		if err := lt.transferToken(ctx, deployer, lt.tokenA, acc.Address, amount); err != nil {
			return fmt.Errorf("failed to transfer Token A to account %d: %w", i, err)
		}

		// Transfer Token B
		if err := lt.transferToken(ctx, deployer, lt.tokenB, acc.Address, amount); err != nil {
			return fmt.Errorf("failed to transfer Token B to account %d: %w", i, err)
		}

		fmt.Printf("  Distributed tokens to account %d\n", i)
	}

	time.Sleep(2 * time.Second)
	return nil
}

// transferToken sends ERC20 tokens directly to the node (for setup)
func (lt *LoadTester) transferToken(ctx context.Context, from *Account, token, to common.Address, amount *big.Int) error {
	data := buildTransferData(to, amount)

	nonce := from.GetAndIncrementNonce()
	gasLimit := uint64(100000)
	gasPrice := big.NewInt(1000000000)

	tx := types.NewTransaction(
		nonce,
		token,
		big.NewInt(0),
		gasLimit,
		gasPrice,
		data,
	)

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(lt.chainID), from.PrivateKey)
	if err != nil {
		return err
	}

	// Send directly to node (bypass proxy for setup)
	return lt.nodeClient.SendTransaction(ctx, signedTx)
}

// initializeNonces fetches the current nonce for all accounts
func (lt *LoadTester) initializeNonces(ctx context.Context) error {
	for i, acc := range lt.accounts {
		nonce, err := lt.nodeClient.NonceAt(ctx, acc.Address, nil)
		if err != nil {
			return fmt.Errorf("failed to get nonce for account %d: %w", i, err)
		}
		acc.SetNonce(nonce)
		fmt.Printf("  Account %d nonce: %d\n", i, nonce)
	}
	return nil
}

// apiCall makes an API call to the proxy admin endpoints
func (lt *LoadTester) apiCall(ctx context.Context, method, path string, body map[string]interface{}) (map[string]interface{}, error) {
	var reqBody io.Reader
	if body != nil {
		bodyBytes, _ := json.Marshal(body)
		reqBody = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, lt.cfg.ProxyURL+path, reqBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := lt.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(respBody))
	}

	var result map[string]interface{}
	if len(respBody) > 0 {
		// Try to parse as object first
		if err := json.Unmarshal(respBody, &result); err != nil {
			// If it fails, it might be an array - wrap it
			var arr []interface{}
			if err := json.Unmarshal(respBody, &arr); err == nil {
				result = map[string]interface{}{"users": arr}
			}
		}
	}

	return result, nil
}

// getMinimalERC20Bytecode returns bytecode for a minimal ERC20 token that auto-mints to deployer.
// This is a complete ERC20 with transfer, balanceOf, approve, allowance, transferFrom.
// Compiled with solc 0.8.20, no constructor args needed.
func getMinimalERC20Bytecode() []byte {
	// Minimal ERC20: auto-mints 1,000,000 * 10^18 tokens to deployer
	// Source: https://github.com/OpenZeppelin/openzeppelin-contracts (simplified)
	//
	// contract MinimalERC20 {
	//     mapping(address => uint256) public balanceOf;
	//     mapping(address => mapping(address => uint256)) public allowance;
	//     uint256 public totalSupply;
	//     constructor() { balanceOf[msg.sender] = 1e24; totalSupply = 1e24; }
	//     function transfer(address to, uint256 amount) public returns (bool) { ... }
	//     function approve(address spender, uint256 amount) public returns (bool) { ... }
	//     function transferFrom(address from, address to, uint256 amount) public returns (bool) { ... }
	// }
	bytecodeHex := "608060405269d3c21bcecceda100000060008033600052602060002055806002555050610494806100316000396000f3fe608060405234801561001057600080fd5b50600436106100625760003560e01c8063095ea7b31461006757806318160ddd1461008f57806323b872dd146100a557806370a08231146100b8578063a9059cbb146100e1578063dd62ed3e146100f4575b600080fd5b61007a6100753660046103b4565b61012d565b60405190151581526020015b60405180910390f35b61009760025481565b604051908152602001610086565b61007a6100b33660046103de565b610143565b6100976100c636600461041a565b6001600160a01b031660009081526020819052604090205490565b61007a6100ef3660046103b4565b6101d9565b61009761010236600461043c565b6001600160a01b03918216600090815260016020908152604080832093909416825291909152205490565b600061013a3384846101e6565b50600192915050565b6001600160a01b038316600090815260016020908152604080832033845290915281205482811015610197576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b6101ab85336101a68685610469565b6101e6565b6101b68585856102a8565b506001949350505050565b600061013a3384846102a8565b6001600160a01b038316610226576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b6001600160a01b038216610266576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b6001600160a01b0393841660009081526001602090815260408083209490951682529283528381209190915593909355505050565b6001600160a01b0383166102db576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b6001600160a01b03821661031b576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b6001600160a01b03831660009081526020819052604090205481111561036d576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b6001600160a01b0392831660009081526020819052604080822080548490039055929093168352912080549091019055565b80356001600160a01b03811681146103b057600080fd5b919050565b600080604083850312156103c857600080fd5b6103d18361039f565b946020939093013593505050565b6000806000606084860312156103f457600080fd5b6103fd8461039f565b925061040b6020850161039f565b9150604084013590509250925092565b60006020828403121561042d57600080fd5b6104368261039f565b92915050565b6000806040838503121561045057600080fd5b6104598361039f565b91506103d16020840161039f565b8181038181111561043657634e487b7160e01b600052601160045260246000fdfea164736f6c6343000814000a"

	bytecode, _ := hex.DecodeString(bytecodeHex)
	return bytecode
}
