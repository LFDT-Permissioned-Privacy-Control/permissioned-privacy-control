package disclosurecase

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math/big"

	"privacy-proxy/internal/disclosurepolicy"
	"privacy-proxy/internal/policybundle"
)

// Namespace separates stored cases by selected environment/chain and restore
// generation. It is a public identity, not proof of the connected blockchain.
// Production uses metadata from the SAME selected snapshot as verification.
func Namespace(metadata policybundle.BundleMetadata, rawEpoch string) (string, error) {
	chain := metadata.ChainID
	if !ValidEpoch(rawEpoch) || !disclosurepolicy.Text(metadata.Environment, 128) || len(chain) == 0 || len(chain) > 78 || len(chain) > 1 && chain[0] == '0' {
		return "", ErrInvalid
	}
	for _, digit := range chain {
		if digit < '0' || digit > '9' {
			return "", ErrInvalid
		}
	}
	n, ok := new(big.Int).SetString(chain, 10)
	if !ok || n.BitLen() > 256 {
		return "", ErrInvalid
	}
	h := sha256.New()
	for _, value := range []string{"ops.disclosure.case-namespace/v1", metadata.Environment, chain, rawEpoch} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(value)))
		h.Write(size[:])
		h.Write([]byte(value))
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
