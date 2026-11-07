// Package walletops orchestrates user-proved operational wallet associations.
// A link supplies neither group membership nor transaction permission.
package walletops

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
)

type Namespace [32]byte

func (n Namespace) String() string { return "sha256:" + hex.EncodeToString(n[:]) }

type ExpectedState struct {
	Generation string
	Coverage   [32]byte
}

func (s ExpectedState) Valid() bool {
	id, err := uuid.Parse(s.Generation)
	return err == nil && id != uuid.Nil && id.String() == s.Generation
}

type ServiceBinding struct {
	ServiceOrigin string `json:"serviceOrigin"`
	Environment   string `json:"environment"`
	ChainID       string `json:"chainId"`
	GenesisHash   string `json:"genesisHash"`
	DeploymentID  string `json:"deploymentId"`
}

func text(s string, max int) bool {
	if len(s) == 0 || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func (b ServiceBinding) Namespace() (Namespace, error) {
	u, err := url.Parse(b.ServiceOrigin)
	if err != nil || !text(b.ServiceOrigin, 2048) || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.String() != b.ServiceOrigin || !text(b.Environment, 128) || !text(b.DeploymentID, 128) {
		return Namespace{}, ErrInvalid
	}
	if len(b.ChainID) == 0 || len(b.ChainID) > 78 || b.ChainID[0] == '0' {
		return Namespace{}, ErrInvalid
	}
	for _, r := range b.ChainID {
		if r < '0' || r > '9' {
			return Namespace{}, ErrInvalid
		}
	}
	chain, ok := new(big.Int).SetString(b.ChainID, 10)
	if !ok || chain.BitLen() > 256 {
		return Namespace{}, ErrInvalid
	}
	if len(b.GenesisHash) != 66 || !strings.HasPrefix(b.GenesisHash, "0x") {
		return Namespace{}, ErrInvalid
	}
	raw, err := hex.DecodeString(b.GenesisHash[2:])
	if err != nil || hex.EncodeToString(raw) != b.GenesisHash[2:] {
		return Namespace{}, ErrInvalid
	}
	h := sha256.New()
	for _, part := range []string{"ops.wallet.namespace/v1", b.ServiceOrigin, b.Environment, b.ChainID, b.GenesisHash, b.DeploymentID} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(part)))
		h.Write(size[:])
		h.Write([]byte(part))
	}
	var namespace Namespace
	copy(namespace[:], h.Sum(nil))
	return namespace, nil
}

func ParseAddress(raw string) (common.Address, error) {
	if len(raw) != 42 || !strings.HasPrefix(raw, "0x") {
		return common.Address{}, ErrInvalid
	}
	decoded, err := hex.DecodeString(raw[2:])
	if err != nil {
		return common.Address{}, ErrInvalid
	}
	return common.BytesToAddress(decoded), nil
}
func AddressString(address common.Address) string { return "0x" + hex.EncodeToString(address[:]) }
func ParseNonce(raw string) ([32]byte, error) {
	var nonce [32]byte
	if len(raw) != 64 {
		return nonce, ErrInvalid
	}
	bytes, err := hex.DecodeString(raw)
	if err != nil || hex.EncodeToString(bytes) != raw {
		return nonce, ErrInvalid
	}
	copy(nonce[:], bytes)
	return nonce, nil
}
func ActorLock(namespace Namespace, actor string) (int32, int32) {
	h := sha256.New()
	for _, part := range [][]byte{[]byte("ops-wallet-actor-lock/v1"), namespace[:], []byte(actor)} {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(part)))
		h.Write(n[:])
		h.Write(part)
	}
	sum := h.Sum(nil)
	return int32(binary.BigEndian.Uint32(sum[:4])), int32(binary.BigEndian.Uint32(sum[4:8]))
}
