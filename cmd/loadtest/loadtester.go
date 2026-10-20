package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

// LoadTester manages the load testing process
type LoadTester struct {
	cfg        *Config
	fundingKey *ecdsa.PrivateKey
	accounts   []*Account

	// Clients
	nodeClient *ethclient.Client // Direct node connection
	httpClient *http.Client

	// Deployed contracts
	tokenA common.Address
	tokenB common.Address
	pool   common.Address

	// Chain info
	chainID *big.Int

	// Organization info (for proxy auth)
	orgID   string
	groupID string

	// Metrics
	metrics *Metrics
}

// NewLoadTester creates a new load tester instance
func NewLoadTester(cfg *Config) (*LoadTester, error) {
	fundingKey, err := ParsePrivateKey(cfg.FundingKey)
	if err != nil {
		return nil, fmt.Errorf("invalid funding key: %w", err)
	}

	nodeClient, err := ethclient.Dial(cfg.NodeURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to node: %w", err)
	}

	accounts, err := GenerateAccounts(fundingKey, cfg.NumAccounts)
	if err != nil {
		return nil, fmt.Errorf("failed to generate accounts: %w", err)
	}

	return &LoadTester{
		cfg:        cfg,
		fundingKey: fundingKey,
		accounts:   accounts,
		nodeClient: nodeClient,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		metrics:    NewMetrics(),
	}, nil
}

// Setup performs Phase 1: account creation, funding, contract deployment
func (lt *LoadTester) Setup(ctx context.Context) error {
	var err error

	// Get chain ID
	lt.chainID, err = lt.nodeClient.ChainID(ctx)
	if err != nil {
		return fmt.Errorf("failed to get chain ID: %w", err)
	}
	fmt.Printf("Chain ID: %d\n", lt.chainID)
	if lt.cfg.Direct {
		fmt.Println("Mode: DIRECT (bypassing proxy)")
	} else {
		fmt.Println("Mode: PROXY (with runtime tracing)")
	}

	// Print funding account
	fundingAddr := crypto.PubkeyToAddress(lt.fundingKey.PublicKey)
	fmt.Printf("Funding account: %s\n", fundingAddr.Hex())

	// Print test accounts
	fmt.Printf("Generated %d test accounts:\n", len(lt.accounts))
	for i, acc := range lt.accounts {
		fmt.Printf("  [%d] %s\n", i, acc.Address.Hex())
	}
	fmt.Println()

	// Step 1: Fund accounts with ETH (direct to node)
	fmt.Println("Step 1: Funding accounts with ETH...")
	if err := lt.fundAccounts(ctx); err != nil {
		return fmt.Errorf("failed to fund accounts: %w", err)
	}

	// Step 2: Create org, group, users in proxy (skip in direct mode)
	if !lt.cfg.Direct {
		fmt.Println("Step 2: Setting up proxy authentication...")
		if err := lt.setupProxyAuth(ctx); err != nil {
			return fmt.Errorf("failed to setup proxy auth: %w", err)
		}
	} else {
		fmt.Println("Step 2: Skipping proxy auth (direct mode)")
	}

	// Step 3: Deploy contracts
	fmt.Println("Step 3: Deploying contracts...")
	if err := lt.deployContracts(ctx); err != nil {
		return fmt.Errorf("failed to deploy contracts: %w", err)
	}

	// Step 4: Fund accounts with tokens
	fmt.Println("Step 4: Distributing tokens to accounts...")
	if err := lt.distributeTokens(ctx); err != nil {
		return fmt.Errorf("failed to distribute tokens: %w", err)
	}

	// Step 5: Initialize nonces for all accounts
	fmt.Println("Step 5: Initializing nonces...")
	if err := lt.initializeNonces(ctx); err != nil {
		return fmt.Errorf("failed to initialize nonces: %w", err)
	}

	return nil
}

// Run executes Phase 2: the load test
func (lt *LoadTester) Run(ctx context.Context) error {
	// Create a context with timeout for the load test duration
	testCtx, cancel := context.WithTimeout(ctx, lt.cfg.Duration)
	defer cancel()

	fmt.Printf("Starting load test for %v...\n", lt.cfg.Duration)
	fmt.Println("Press Ctrl+C to stop early")
	fmt.Println()

	// Start pool monitor
	poolCtx, poolCancel := context.WithCancel(ctx)
	throttle := make(chan struct{}, 1)
	go lt.monitorPool(poolCtx, throttle)
	defer poolCancel()

	// Start workers (one per account)
	var wg sync.WaitGroup
	for _, acc := range lt.accounts {
		wg.Add(1)
		go lt.worker(testCtx, &wg, acc, throttle)
	}

	// Wait for completion or cancellation
	<-testCtx.Done()

	// Signal workers to stop and wait
	fmt.Println("\nStopping workers...")
	wg.Wait()

	return nil
}

// worker sends transactions for a single account
func (lt *LoadTester) worker(ctx context.Context, wg *sync.WaitGroup, acc *Account, throttle <-chan struct{}) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-throttle:
			// Pool is full, wait a bit
			time.Sleep(100 * time.Millisecond)
			continue
		default:
			// Send a transaction
			lt.sendTransaction(ctx, acc)
		}
	}
}

// sendTransaction sends a single transaction and records metrics
func (lt *LoadTester) sendTransaction(ctx context.Context, acc *Account) {
	start := time.Now()

	// Build transaction — EOA→EOA value transfer (RD-1112 workload) or ERC-20.
	nonce := acc.GetAndIncrementNonce()
	var tx *types.Transaction
	var err error
	if lt.cfg.ValueTransfer {
		tx, err = lt.buildValueTransfer(acc, nonce)
	} else {
		tx, err = lt.buildTokenTransfer(acc, nonce)
	}
	if err != nil {
		lt.metrics.RecordError()
		return
	}

	// Send transaction - either via proxy or directly to node
	if lt.cfg.Direct {
		err = lt.nodeClient.SendTransaction(ctx, tx)
	} else {
		err = lt.sendRawTxViaProxy(ctx, acc, tx)
	}
	latency := time.Since(start)

	if err != nil {
		lt.metrics.RecordError()
		// Log occasional errors
		if lt.metrics.errors.Load()%100 == 1 {
			fmt.Printf("Error sending tx: %v\n", err)
		}
	} else {
		lt.metrics.RecordSuccess(latency, tx.Gas())
	}
}

// buildTokenTransfer creates a signed token transfer transaction
func (lt *LoadTester) buildTokenTransfer(acc *Account, nonce uint64) (*types.Transaction, error) {
	// Transfer 1 token to a random other account
	toIdx := (acc.Index + 1) % len(lt.accounts)
	to := lt.accounts[toIdx].Address

	// ERC20 transfer(address,uint256) = 0xa9059cbb
	data := buildTransferData(to, big.NewInt(1))

	gasLimit := uint64(100000)
	gasPrice := big.NewInt(1000000000) // 1 gwei

	tx := types.NewTransaction(
		nonce,
		lt.tokenA,
		big.NewInt(0),
		gasLimit,
		gasPrice,
		data,
	)

	// Sign the transaction
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(lt.chainID), acc.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign tx: %w", err)
	}

	return signedTx, nil
}

// buildValueTransfer creates a signed EOA→EOA value transfer (no calldata) —
// the RD-1112 target workload. This exercises the proxy's hot path
// (eth_getCode EOA check + access control + audit), unlike the ERC-20 path
// which hits a contract and triggers debug_traceCall.
func (lt *LoadTester) buildValueTransfer(acc *Account, nonce uint64) (*types.Transaction, error) {
	toIdx := (acc.Index + 1) % len(lt.accounts)
	to := lt.accounts[toIdx].Address

	tx := types.NewTransaction(
		nonce,
		to,
		big.NewInt(1),          // 1 wei
		21000,                  // plain transfer gas
		big.NewInt(1000000000), // 1 gwei
		nil,                    // no calldata → EOA transfer
	)

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(lt.chainID), acc.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign value-transfer tx: %w", err)
	}
	return signedTx, nil
}

// sendRawTxViaProxy sends a signed transaction through the Open Privacy Suite
// using eth_sendRawTransaction. Requires runtime tracing to be enabled on the proxy.
func (lt *LoadTester) sendRawTxViaProxy(ctx context.Context, acc *Account, tx *types.Transaction) error {
	// Encode transaction to RLP
	rawTx, err := tx.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to encode tx: %w", err)
	}

	// Build JSON-RPC request
	reqBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_sendRawTransaction",
		"params":  []string{fmt.Sprintf("0x%x", rawTx)},
		"id":      1,
	}

	bodyBytes, _ := json.Marshal(reqBody)

	req, err := http.NewRequestWithContext(ctx, "POST", lt.cfg.ProxyURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+acc.JWTToken)

	resp, err := lt.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("proxy returned %d: %s", resp.StatusCode, string(body))
	}

	// Parse response to check for RPC error
	var rpcResp struct {
		Result string `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		return nil // Assume success if we can't parse
	}
	if rpcResp.Error != nil {
		return fmt.Errorf("RPC error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	return nil
}

// monitorPool monitors the txpool and signals throttling when needed
func (lt *LoadTester) monitorPool(ctx context.Context, throttle chan<- struct{}) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pending, queued := lt.getPoolStatus()
			total := pending + queued

			if total > lt.cfg.MaxPoolSize {
				// Signal throttle (non-blocking)
				select {
				case throttle <- struct{}{}:
				default:
				}
			}

			// Print pool status periodically
			if lt.metrics.txCount.Load()%1000 == 0 && lt.metrics.txCount.Load() > 0 {
				fmt.Printf("Pool: pending=%d, queued=%d, total=%d\n", pending, queued, total)
			}
		}
	}
}

// getPoolStatus queries the txpool status from the node
func (lt *LoadTester) getPoolStatus() (pending, queued int) {
	reqBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "txpool_status",
		"params":  []interface{}{},
		"id":      1,
	}

	bodyBytes, _ := json.Marshal(reqBody)
	resp, err := lt.httpClient.Post(lt.cfg.NodeURL, "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		return 0, 0
	}
	defer resp.Body.Close()

	var result struct {
		Result struct {
			Pending string `json:"pending"`
			Queued  string `json:"queued"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, 0
	}

	// Parse hex values
	fmt.Sscanf(strings.TrimPrefix(result.Result.Pending, "0x"), "%x", &pending)
	fmt.Sscanf(strings.TrimPrefix(result.Result.Queued, "0x"), "%x", &queued)

	return pending, queued
}

// PrintResults prints the final metrics
func (lt *LoadTester) PrintResults() {
	lt.metrics.PrintSummary(lt.cfg.Duration)
}

// buildTransferData builds the calldata for ERC20 transfer(address,uint256)
func buildTransferData(to common.Address, amount *big.Int) []byte {
	// transfer(address,uint256) selector: 0xa9059cbb
	selector := []byte{0xa9, 0x05, 0x9c, 0xbb}

	// Pad address to 32 bytes
	addrPadded := common.LeftPadBytes(to.Bytes(), 32)

	// Pad amount to 32 bytes
	amountPadded := common.LeftPadBytes(amount.Bytes(), 32)

	return append(append(selector, addrPadded...), amountPadded...)
}

// Metrics tracks load test metrics
type Metrics struct {
	txCount   atomic.Int64
	errors    atomic.Int64
	totalGas  atomic.Uint64
	latencies []time.Duration
	latencyMu sync.Mutex
	startTime time.Time
}

// NewMetrics creates a new metrics tracker
func NewMetrics() *Metrics {
	return &Metrics{
		latencies: make([]time.Duration, 0, 100000),
		startTime: time.Now(),
	}
}

// RecordSuccess records a successful transaction
func (m *Metrics) RecordSuccess(latency time.Duration, gas uint64) {
	m.txCount.Add(1)
	m.totalGas.Add(gas)

	m.latencyMu.Lock()
	m.latencies = append(m.latencies, latency)
	m.latencyMu.Unlock()
}

// RecordError records a failed transaction
func (m *Metrics) RecordError() {
	m.errors.Add(1)
}

// PrintSummary prints the metrics summary
func (m *Metrics) PrintSummary(duration time.Duration) {
	txCount := m.txCount.Load()
	errors := m.errors.Load()
	totalGas := m.totalGas.Load()
	elapsed := time.Since(m.startTime).Seconds()

	fmt.Println()
	fmt.Println("=== Load Test Results ===")
	fmt.Printf("Duration:     %.2f seconds\n", elapsed)
	fmt.Printf("Total TXs:    %d\n", txCount)
	fmt.Printf("Errors:       %d (%.2f%%)\n", errors, float64(errors)/float64(txCount+errors)*100)
	fmt.Printf("TX/sec:       %.2f\n", float64(txCount)/elapsed)
	fmt.Printf("Total Gas:    %d\n", totalGas)
	fmt.Printf("MGas/sec:     %.2f\n", float64(totalGas)/elapsed/1_000_000)

	// Calculate latency percentiles
	m.latencyMu.Lock()
	defer m.latencyMu.Unlock()

	if len(m.latencies) > 0 {
		// Sort latencies for percentile calculation
		sorted := make([]time.Duration, len(m.latencies))
		copy(sorted, m.latencies)
		sortDurations(sorted)

		p50 := sorted[len(sorted)*50/100]
		p95 := sorted[len(sorted)*95/100]
		p99 := sorted[len(sorted)*99/100]

		fmt.Println()
		fmt.Println("Latency (request to proxy response):")
		fmt.Printf("  p50:        %v\n", p50)
		fmt.Printf("  p95:        %v\n", p95)
		fmt.Printf("  p99:        %v\n", p99)
	}
}

// sortDurations sorts a slice of durations in place
func sortDurations(d []time.Duration) {
	for i := 0; i < len(d); i++ {
		for j := i + 1; j < len(d); j++ {
			if d[j] < d[i] {
				d[i], d[j] = d[j], d[i]
			}
		}
	}
}
