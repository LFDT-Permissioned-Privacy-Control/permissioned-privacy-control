package main

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Account represents a test account with its state
type Account struct {
	Index      int
	Address    common.Address
	PrivateKey *ecdsa.PrivateKey
	JWTToken   string
	Nonce      uint64
	mu         sync.Mutex
}

// GetAndIncrementNonce atomically gets the current nonce and increments it
func (a *Account) GetAndIncrementNonce() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	nonce := a.Nonce
	a.Nonce++
	return nonce
}

// SetNonce sets the nonce (used during initialization)
func (a *Account) SetNonce(nonce uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Nonce = nonce
}

// DID returns a unique DID for this account
func (a *Account) DID() string {
	return fmt.Sprintf("did:loadtest:account-%d-%s", a.Index, a.Address.Hex()[2:10])
}

// GenerateAccounts creates n accounts deterministically from a seed
func GenerateAccounts(seedKey *ecdsa.PrivateKey, n int) ([]*Account, error) {
	accounts := make([]*Account, n)

	for i := 0; i < n; i++ {
		// Derive account key deterministically: hash(seed_key + index)
		data := append(crypto.FromECDSA(seedKey), big.NewInt(int64(i)).Bytes()...)
		hash := crypto.Keccak256(data)

		privateKey, err := crypto.ToECDSA(hash)
		if err != nil {
			return nil, fmt.Errorf("failed to generate key for account %d: %w", i, err)
		}

		accounts[i] = &Account{
			Index:      i,
			Address:    crypto.PubkeyToAddress(privateKey.PublicKey),
			PrivateKey: privateKey,
		}
	}

	return accounts, nil
}

// ParsePrivateKey parses a hex-encoded private key
func ParsePrivateKey(hexKey string) (*ecdsa.PrivateKey, error) {
	hexKey = strings.TrimPrefix(hexKey, "0x")
	return crypto.HexToECDSA(hexKey)
}

// AccountAddresses returns all account addresses
func AccountAddresses(accounts []*Account) []common.Address {
	addrs := make([]common.Address, len(accounts))
	for i, acc := range accounts {
		addrs[i] = acc.Address
	}
	return addrs
}
