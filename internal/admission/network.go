// Package admission supplies financial checks and durable operational effects.
// Its internal Go input is trusted orchestration, not a public permission mint.
package admission

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"math/big"
	"strings"
	"unicode/utf8"

	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
	"privacy-proxy/internal/identity"
)

type Digest [32]byte

func (d Digest) String() string { return "sha256:" + hex.EncodeToString(d[:]) }
func ParseDigest(raw string) (Digest, error) {
	var d Digest
	if len(raw) != 71 || !strings.HasPrefix(raw, "sha256:") {
		return d, ErrInvalid
	}
	decoded, err := hex.DecodeString(raw[7:])
	if err != nil || hex.EncodeToString(decoded) != raw[7:] {
		return d, ErrInvalid
	}
	copy(d[:], decoded)
	return d, nil
}
func lp(h hash.Hash, raw []byte) {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(raw)))
	h.Write(size[:])
	h.Write(raw)
}
func HashParts(domain string, parts ...[]byte) Digest {
	h := sha256.New()
	lp(h, []byte(domain))
	for _, part := range parts {
		lp(h, part)
	}
	var d Digest
	copy(d[:], h.Sum(nil))
	return d
}
func text(raw string, max int, empty bool) bool {
	if (!empty && raw == "") || len(raw) > max || !utf8.ValidString(raw) {
		return false
	}
	for _, r := range raw {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
func ValidUUID(raw string) bool {
	id, err := uuid.Parse(raw)
	return err == nil && id != uuid.Nil && id.String() == raw
}
func ParseAddress(raw string) (common.Address, error) {
	if len(raw) != 42 || !strings.HasPrefix(raw, "0x") {
		return common.Address{}, ErrInvalid
	}
	bytes, err := hex.DecodeString(raw[2:])
	if err != nil {
		return common.Address{}, ErrInvalid
	}
	return common.BytesToAddress(bytes), nil
}
func AddressString(address common.Address) string { return "0x" + hex.EncodeToString(address[:]) }
func ParseUint256(raw string, positive bool) (*big.Int, error) {
	if len(raw) == 0 || len(raw) > 78 || (len(raw) > 1 && raw[0] == '0') {
		return nil, ErrInvalid
	}
	for _, r := range raw {
		if r < '0' || r > '9' {
			return nil, ErrInvalid
		}
	}
	n, ok := new(big.Int).SetString(raw, 10)
	if !ok || n.BitLen() > 256 || (positive && n.Sign() == 0) {
		return nil, ErrInvalid
	}
	return n, nil
}

type NetworkBinding struct {
	Environment  string `json:"environment"`
	ChainID      string `json:"chainId"`
	GenesisHash  string `json:"genesisHash"`
	DeploymentID string `json:"deploymentId"`
}

func (n NetworkBinding) Key() (Digest, error) {
	chain, err := ParseUint256(n.ChainID, true)
	if err != nil || !chain.IsUint64() || !text(n.Environment, 128, false) || !text(n.DeploymentID, 128, false) || len(n.GenesisHash) != 66 || !strings.HasPrefix(n.GenesisHash, "0x") {
		return Digest{}, ErrInvalid
	}
	decoded, err := hex.DecodeString(n.GenesisHash[2:])
	if err != nil || hex.EncodeToString(decoded) != n.GenesisHash[2:] {
		return Digest{}, ErrInvalid
	}
	return HashParts("ops-ledger-network/v1", []byte(n.Environment), []byte(n.ChainID), []byte(n.GenesisHash), []byte(n.DeploymentID)), nil
}

type ExpectedState struct {
	Generation string
	Coverage   Digest
}

func (s ExpectedState) Valid() bool { return ValidUUID(s.Generation) }
func HashLock(network Digest, tx common.Hash) (int32, int32) {
	d := HashParts("ops-admission-hash-lock/v1", network[:], tx[:])
	return int32(binary.BigEndian.Uint32(d[:4])), int32(binary.BigEndian.Uint32(d[4:8]))
}
func validActor(actor string) bool { return identity.ValidActorID(actor) }
