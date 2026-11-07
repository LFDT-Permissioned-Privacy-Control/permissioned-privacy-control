// Package walletproof contains only bounded wallet-message and EIP-191
// primitives. It knows no database, identity provider or permission policy.
package walletproof

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func HashMessage(message string) []byte {
	return crypto.Keccak256([]byte("\x19Ethereum Signed Message:\n"+strconv.Itoa(len(message))), []byte(message))
}

// RecoverLegacy preserves the legacy decoder, recovery and errors. V2 proof
// management uses RecoverV2, which adds explicit canonical-scalar checks.
func RecoverLegacy(message, signatureHex string) (common.Address, error) {
	sig, err := hex.DecodeString(strings.TrimPrefix(signatureHex, "0x"))
	if err != nil {
		return common.Address{}, fmt.Errorf("invalid signature encoding: %w", err)
	}
	if len(sig) != 65 {
		return common.Address{}, fmt.Errorf("invalid signature length: expected 65 bytes, got %d", len(sig))
	}
	if sig[64] >= 27 {
		sig[64] -= 27
	}
	pub, err := crypto.SigToPub(HashMessage(message), sig)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to recover public key: %w", err)
	}
	return crypto.PubkeyToAddress(*pub), nil
}

func Signature(raw string) ([]byte, error) {
	if len(raw) != 132 || !strings.HasPrefix(raw, "0x") {
		return nil, errors.New("invalid wallet signature")
	}
	sig, err := hex.DecodeString(raw[2:])
	if err != nil {
		return nil, errors.New("invalid wallet signature")
	}
	v := sig[64]
	if v == 27 || v == 28 {
		v -= 27
	}
	if v > 1 || !crypto.ValidateSignatureValues(v, new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:64]), true) {
		return nil, errors.New("invalid wallet signature")
	}
	return sig, nil
}

func RecoverV2(message string, signature []byte) (common.Address, error) {
	if len(message) == 0 || len(message) > MaxMessageBytes || len(signature) != 65 {
		return common.Address{}, errors.New("invalid wallet proof")
	}
	sig, err := Signature("0x" + hex.EncodeToString(signature))
	if err != nil {
		return common.Address{}, err
	}
	if sig[64] >= 27 {
		sig[64] -= 27
	}
	pub, err := crypto.SigToPub(HashMessage(message), sig)
	if err != nil {
		return common.Address{}, errors.New("invalid wallet proof")
	}
	return crypto.PubkeyToAddress(*pub), nil
}
