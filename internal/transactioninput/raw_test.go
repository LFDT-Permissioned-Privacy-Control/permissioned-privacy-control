package transactioninput_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"privacy-proxy/internal/transactioninput"
)

func signed(t *testing.T, kind uint8, value *big.Int) string {
	t.Helper()
	key, _ := crypto.HexToECDSA(strings.Repeat("0", 63) + "1")
	to := common.HexToAddress("0x1111111111111111111111111111111111111111")
	list := types.AccessList{{Address: to, StorageKeys: []common.Hash{common.HexToHash("0xabc")}}}
	var data types.TxData
	switch kind {
	case 0:
		data = &types.LegacyTx{Nonce: math.MaxUint64, Gas: math.MaxUint64, GasPrice: big.NewInt(1), To: &to, Value: value, Data: []byte{1, 2}}
	case 1:
		data = &types.AccessListTx{ChainID: big.NewInt(1), Nonce: math.MaxUint64, Gas: math.MaxUint64, GasPrice: big.NewInt(1), To: &to, Value: value, Data: []byte{1, 2}, AccessList: list}
	case 2:
		data = &types.DynamicFeeTx{ChainID: big.NewInt(1), Nonce: math.MaxUint64, Gas: math.MaxUint64, GasFeeCap: big.NewInt(9), GasTipCap: big.NewInt(2), To: &to, Value: value, Data: []byte{1, 2}, AccessList: list}
	}
	tx, err := types.SignTx(types.NewTx(data), types.LatestSignerForChainID(big.NewInt(1)), key)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := tx.MarshalBinary()
	return "0x" + hex.EncodeToString(raw)
}

func TestSignedEnvelopesPreserveAllFieldsAndDetachedValues(t *testing.T) {
	for _, kind := range []uint8{0, 1, 2} {
		raw := signed(t, kind, big.NewInt(7))
		v, err := transactioninput.DecodeRaw(raw, "1", transactioninput.ProtectedEVMProfile(), transactioninput.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		if !v.Valid() || v.Type() != kind || v.Signer() != common.HexToAddress("0x7e5f4552091a69125d5dfcb7b8c2659029395bdf") || v.Nonce() != math.MaxUint64 || v.Gas() != math.MaxUint64 || v.Value().Int64() != 7 || v.Creation() || v.ChainID() != "1" || v.RawHex() != raw {
			t.Fatal("signed fields changed")
		}
		to, ok := v.Destination()
		if !ok || to != common.HexToAddress("0x1111111111111111111111111111111111111111") {
			t.Fatal("lost destination")
		}
		v.Value().SetInt64(0)
		v.GasPrice().SetInt64(0)
		v.FeeCap().SetInt64(0)
		v.TipCap().SetInt64(0)
		v.Input()[0] = 9
		v.RawBytes()[0] = 0
		if kind != 0 {
			l := v.AccessList()
			l[0].Address = common.Address{}
			l[0].StorageKeys[0] = common.Hash{}
			if v.AccessList()[0].StorageKeys[0] != (common.HexToHash("0xabc")) {
				t.Fatal("access list alias")
			}
		}
		if v.Value().Int64() != 7 || v.GasPrice().Sign() == 0 || !bytes.Equal(v.Input(), []byte{1, 2}) || v.RawHex() != raw {
			t.Fatal("borrowed state escaped")
		}
	}
}

func TestPinnedGethAccessListBinaryGolden(t *testing.T) {
	// Binary vector from pinned geth v1.17.8 core/types/transaction_test.go.
	raw := "0x01f8630103018261a894b94f5374fce5edbc8e2a8697c15331677e6ebf0b0a825544c001a0c9519f4f2b30335884581971573fadf60c6204f59a911df35ee8a540456b2660a032f1e8e2c5dd761f9e4f88f41c8310aeaba26a8bfcdacfedfa12ec3862d37521"
	v, err := transactioninput.DecodeRaw(raw, "1", transactioninput.ProtectedEVMProfile(), transactioninput.DefaultLimits())
	if err != nil || v.Type() != 1 || v.Nonce() != 3 || v.Gas() != 25000 || v.Value().Int64() != 10 || !bytes.Equal(v.Input(), []byte{0x55, 0x44}) || v.RawHex() != raw {
		t.Fatal("golden changed", err)
	}
}

func TestMalformedUnsupportedAndOversizedSignedInput(t *testing.T) {
	valid := signed(t, 2, big.NewInt(7))
	for name, raw := range map[string]string{"unprotected": "0xdf800182520894111111111111111111111111111111111111111180801b0101", "blob": "0x03c0", "setcode": "0x04c0", "unknown": "0x7fc0", "trailing": valid + "00", "odd": valid + "0", "whitespace": " " + valid, "bad hex": "0xgg", "zero signature": "0x02e2018001028252089411111111111111111111111111111111111111118080c0808080", "huge": "0x" + strings.Repeat("00", transactioninput.MaxRawBytes+1)} {
		t.Run(name, func(t *testing.T) {
			v, err := transactioninput.DecodeRaw(raw, "1", transactioninput.ProtectedEVMProfile(), transactioninput.DefaultLimits())
			if err == nil || v.Valid() {
				t.Fatal("invalid envelope accepted")
			}
		})
	}
	for _, chain := range []string{"", "0", "01", "-1", strings.Repeat("9", 79)} {
		if _, err := transactioninput.DecodeRaw(valid, chain, transactioninput.ProtectedEVMProfile(), transactioninput.DefaultLimits()); err == nil {
			t.Fatal("chain option accepted", chain)
		}
	}
	if _, err := transactioninput.DecodeRaw(valid, "2", transactioninput.ProtectedEVMProfile(), transactioninput.DefaultLimits()); err == nil {
		t.Fatal("wrong chain accepted")
	}
	if _, err := transactioninput.DecodeRaw(valid, "1", transactioninput.InputProfile{}, transactioninput.DefaultLimits()); err == nil {
		t.Fatal("zero profile accepted")
	}
	if _, err := transactioninput.DecodeRaw(valid, "1", transactioninput.ProtectedEVMProfile(), transactioninput.Limits{}); err == nil {
		t.Fatal("zero limits accepted")
	}
	tooBig := signed(t, 0, new(big.Int).Lsh(big.NewInt(1), 256))
	v, err := transactioninput.DecodeRaw(tooBig, "1", transactioninput.ProtectedEVMProfile(), transactioninput.DefaultLimits())
	var typed *transactioninput.Error
	if v.Valid() || !errors.As(err, &typed) {
		t.Fatal("wide value accepted", err)
	}
	if (transactioninput.VerifiedTransaction{}).Valid() {
		t.Fatal("zero input valid")
	}
}

func TestProtectionSignatureCanonicalityAndCreation(t *testing.T) {
	key, _ := crypto.HexToECDSA(strings.Repeat("0", 63) + "1")
	decode := func(tx *types.Transaction) (transactioninput.VerifiedTransaction, error) {
		raw, _ := tx.MarshalBinary()
		return transactioninput.DecodeRaw("0x"+hex.EncodeToString(raw), "1", transactioninput.ProtectedEVMProfile(), transactioninput.DefaultLimits())
	}
	unprotected, err := types.SignTx(types.NewContractCreation(1, big.NewInt(0), 100000, big.NewInt(1), []byte{0x60, 0}), types.HomesteadSigner{}, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decode(unprotected); err == nil {
		t.Fatal("valid unprotected signature accepted")
	}
	creation, err := types.SignTx(types.NewContractCreation(1, big.NewInt(0), 100000, big.NewInt(1), []byte{0x60, 0}), types.LatestSignerForChainID(big.NewInt(1)), key)
	if err != nil {
		t.Fatal(err)
	}
	v, err := decode(creation)
	if err != nil || !v.Creation() {
		t.Fatal("creation identity lost", err)
	}
	if _, ok := v.Destination(); ok {
		t.Fatal("creation invented to")
	}
	valid := signed(t, 2, big.NewInt(7))
	raw, _ := hex.DecodeString(valid[2:])
	tx := new(types.Transaction)
	if tx.UnmarshalBinary(raw) != nil {
		t.Fatal("fixture")
	}
	sigV, r, s := tx.RawSignatureValues()
	to := tx.To()
	highS := types.NewTx(&types.DynamicFeeTx{ChainID: big.NewInt(1), Nonce: tx.Nonce(), Gas: tx.Gas(), GasFeeCap: tx.GasFeeCap(), GasTipCap: tx.GasTipCap(), Value: tx.Value(), To: to, Data: tx.Data(), AccessList: tx.AccessList(), V: new(big.Int).Sub(big.NewInt(1), sigV), R: r, S: new(big.Int).Sub(crypto.S256().Params().N, s)})
	if _, err := decode(highS); err == nil {
		t.Fatal("malleable high-S signature accepted")
	}
	if _, err := transactioninput.DecodeRaw(valid, "1", transactioninput.ProtectedEVMProfile(), transactioninput.Limits{MaxRawBytes: len(raw)}); err != nil {
		t.Fatal("exact input limit", err)
	}
	if _, err := transactioninput.DecodeRaw(valid, "1", transactioninput.ProtectedEVMProfile(), transactioninput.Limits{MaxRawBytes: len(raw) - 1}); err == nil {
		t.Fatal("lower byte limit ignored")
	}
}
