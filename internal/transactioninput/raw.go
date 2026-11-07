// Package transactioninput verifies a bounded signed Ethereum envelope. It
// establishes its signer and bytes, never the OPS actor submitting those bytes.
package transactioninput

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

const MaxRawBytes = 512 << 10

type InputProfile struct{ protected bool }

func ProtectedEVMProfile() InputProfile { return InputProfile{protected: true} }

type Limits struct{ MaxRawBytes int }

func DefaultLimits() Limits { return Limits{MaxRawBytes: MaxRawBytes} }

type ErrorCode string

const (
	InvalidOptions  ErrorCode = "invalid_options"
	InvalidInput    ErrorCode = "invalid_input"
	UnsupportedType ErrorCode = "unsupported_type"
	WrongChain      ErrorCode = "wrong_chain"
	InputLimit      ErrorCode = "input_limit"
)

type Error struct{ Code ErrorCode }

func (e *Error) Error() string { return "signed transaction: " + string(e.Code) }

type VerifiedTransaction struct {
	tx     *types.Transaction
	raw    []byte
	signer common.Address
}

func DecodeRaw(rawHex, expectedChainID string, profile InputProfile, limits Limits) (VerifiedTransaction, error) {
	fail := func(code ErrorCode) (VerifiedTransaction, error) { return VerifiedTransaction{}, &Error{code} }
	if !profile.protected || limits.MaxRawBytes <= 0 || limits.MaxRawBytes > MaxRawBytes || expectedChainID == "" || len(expectedChainID) > 78 || expectedChainID[0] == '0' {
		return fail(InvalidOptions)
	}
	for _, c := range expectedChainID {
		if c < '0' || c > '9' {
			return fail(InvalidOptions)
		}
	}
	chain, ok := new(big.Int).SetString(expectedChainID, 10)
	if !ok || chain.Sign() <= 0 || chain.BitLen() > 256 {
		return fail(InvalidOptions)
	}
	if len(rawHex) > 2+2*limits.MaxRawBytes {
		return fail(InputLimit)
	}
	if len(rawHex) < 4 || len(rawHex)%2 != 0 || !strings.HasPrefix(rawHex, "0x") {
		return fail(InvalidInput)
	}
	raw, err := hex.DecodeString(rawHex[2:])
	if err != nil {
		return fail(InvalidInput)
	}
	if raw[0] <= 0x7f && raw[0] != types.AccessListTxType && raw[0] != types.DynamicFeeTxType {
		return fail(UnsupportedType)
	}
	tx := new(types.Transaction)
	if tx.UnmarshalBinary(raw) != nil {
		return fail(InvalidInput)
	}
	if !tx.Protected() || (tx.Type() != types.LegacyTxType && tx.Type() != types.AccessListTxType && tx.Type() != types.DynamicFeeTxType) {
		return fail(UnsupportedType)
	}
	for _, n := range []*big.Int{tx.ChainId(), tx.Value(), tx.GasPrice(), tx.GasFeeCap(), tx.GasTipCap()} {
		if n.Sign() < 0 || n.BitLen() > 256 {
			return fail(InvalidInput)
		}
	}
	if tx.ChainId().Cmp(chain) != 0 {
		return fail(WrongChain)
	}
	if tx.GasTipCap().Cmp(tx.GasFeeCap()) > 0 {
		return fail(InvalidInput)
	}
	canonical, err := tx.MarshalBinary()
	if err != nil || !bytes.Equal(raw, canonical) {
		return fail(InvalidInput)
	}
	signer, err := types.Sender(types.LatestSignerForChainID(chain), tx)
	if err != nil {
		return fail(InvalidInput)
	}
	return VerifiedTransaction{tx: tx, raw: raw, signer: signer}, nil
}

func (v VerifiedTransaction) Valid() bool { return v.tx != nil && len(v.raw) != 0 }
func (v VerifiedTransaction) Hash() common.Hash {
	if !v.Valid() {
		return common.Hash{}
	}
	return v.tx.Hash()
}
func (v VerifiedTransaction) ChainID() string {
	if !v.Valid() {
		return ""
	}
	return v.tx.ChainId().String()
}
func (v VerifiedTransaction) Signer() common.Address { return v.signer }
func (v VerifiedTransaction) Destination() (common.Address, bool) {
	if !v.Valid() || v.tx.To() == nil {
		return common.Address{}, false
	}
	return *v.tx.To(), true
}
func (v VerifiedTransaction) Creation() bool { return v.Valid() && v.tx.To() == nil }
func (v VerifiedTransaction) Type() uint8 {
	if !v.Valid() {
		return 0
	}
	return v.tx.Type()
}
func (v VerifiedTransaction) Nonce() uint64 {
	if !v.Valid() {
		return 0
	}
	return v.tx.Nonce()
}
func (v VerifiedTransaction) Gas() uint64 {
	if !v.Valid() {
		return 0
	}
	return v.tx.Gas()
}
func (v VerifiedTransaction) Input() []byte {
	if !v.Valid() {
		return nil
	}
	return bytes.Clone(v.tx.Data())
}
func (v VerifiedTransaction) Value() *big.Int {
	if !v.Valid() {
		return nil
	}
	return v.tx.Value()
}
func (v VerifiedTransaction) GasPrice() *big.Int {
	if !v.Valid() {
		return nil
	}
	return v.tx.GasPrice()
}
func (v VerifiedTransaction) FeeCap() *big.Int {
	if !v.Valid() {
		return nil
	}
	return v.tx.GasFeeCap()
}
func (v VerifiedTransaction) TipCap() *big.Int {
	if !v.Valid() {
		return nil
	}
	return v.tx.GasTipCap()
}
func (v VerifiedTransaction) RawBytes() []byte { return bytes.Clone(v.raw) }
func (v VerifiedTransaction) RawHex() string {
	if !v.Valid() {
		return ""
	}
	return "0x" + hex.EncodeToString(v.raw)
}
func (v VerifiedTransaction) AccessList() types.AccessList {
	if !v.Valid() {
		return nil
	}
	list := v.tx.AccessList()
	if list == nil {
		return nil
	}
	out := make(types.AccessList, len(list))
	for i, e := range list {
		out[i] = types.AccessTuple{Address: e.Address, StorageKeys: append([]common.Hash(nil), e.StorageKeys...)}
	}
	return out
}
