// Package networkidentity defines the canonical operational network identity.
// Deriving a key does not verify the connected node or its genesis.
package networkidentity

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"unicode/utf8"
)

var ErrInvalid = errors.New("invalid network binding")

type Binding struct {
	Environment  string `json:"environment"`
	ChainID      string `json:"chainId"`
	GenesisHash  string `json:"genesisHash"`
	DeploymentID string `json:"deploymentId"`
}

func text(s string) bool {
	if s == "" || len(s) > 128 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func (n Binding) Key() ([32]byte, error) {
	var zero [32]byte
	if len(n.ChainID) == 0 || len(n.ChainID) > 20 || n.ChainID[0] == '0' || !text(n.Environment) || !text(n.DeploymentID) || len(n.GenesisHash) != 66 || !strings.HasPrefix(n.GenesisHash, "0x") {
		return zero, ErrInvalid
	}
	for _, c := range n.ChainID {
		if c < '0' || c > '9' {
			return zero, ErrInvalid
		}
	}
	if _, err := strconv.ParseUint(n.ChainID, 10, 64); err != nil {
		return zero, ErrInvalid
	}
	raw, err := hex.DecodeString(n.GenesisHash[2:])
	if err != nil || hex.EncodeToString(raw) != n.GenesisHash[2:] {
		return zero, ErrInvalid
	}
	h := sha256.New()
	for _, p := range []string{"ops-ledger-network/v1", n.Environment, n.ChainID, n.GenesisHash, n.DeploymentID} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(p)))
		h.Write(size[:])
		h.Write([]byte(p))
	}
	copy(zero[:], h.Sum(nil))
	return zero, nil
}
