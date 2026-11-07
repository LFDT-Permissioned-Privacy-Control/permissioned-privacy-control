package rpcexecution

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"privacy-proxy/internal/transactioninput"
)

func guardTransaction(t *testing.T) transactioninput.VerifiedTransaction {
	t.Helper()
	key, _ := crypto.HexToECDSA(strings.Repeat("0", 63) + "1")
	tx, err := types.SignTx(types.NewTransaction(1, common.HexToAddress(testTarget), big.NewInt(0), 100000, big.NewInt(1), nil), types.LatestSignerForChainID(big.NewInt(1)), key)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := tx.MarshalBinary()
	v, err := transactioninput.DecodeRaw("0x"+hex.EncodeToString(raw), "1", transactioninput.ProtectedEVMProfile(), transactioninput.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func trustedGuard(t *testing.T, tx transactioninput.VerifiedTransaction) TrustedGuardEvidence {
	t.Helper()
	root := rootTrace()
	root["from"] = tx.Signer().Hex()
	raw, _ := json.Marshal(root)
	return TrustedGuardEvidence{Profile: GuardRetainedProfileID, Calls: raw, Prestate: []byte(`{"` + testTarget + `":{"code":"0x6000"}}`), ChainID: 1, TransactionHash: tx.Hash(), Fingerprint: common.HexToHash("0x1"), HashMode: 3, HeaderHash: common.HexToHash(testHash), HeaderTimestamp: 10, HeaderPresent: true}
}

func TestRetainedGuardScopeAndAnchorAreExplicit(t *testing.T) {
	tx := guardTransaction(t)
	n := baseNode()
	server := httptest.NewServer(n)
	defer server.Close()
	binding := testBinding(server.URL)
	binding.Profile = GuardRetainedProfileID
	c, err := NewClient(server.Client().Transport, binding, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	c, _ = c.WithCredential("")
	e := trustedGuard(t, tx)
	execution, err := c.QualifyTrustedGuardEvidence(t.Context(), tx, e)
	if err != nil {
		t.Fatal(err)
	}
	if !execution.Signed() || execution.Anchor().Profile != GuardRetainedProfileID {
		t.Fatal("scope relabeled")
	}
	e.Calls[0] = '['
	if !bytes.HasPrefix(execution.RawEvidence(), []byte(`{"callTracer":{`)) {
		t.Fatal("raw alias")
	}
	b, _ := ParseBlockSelector(nil)
	if _, err := c.AcquireCall(t.Context(), testCall(t), b); err == nil {
		t.Fatal("Guard profile acquired simulation")
	}
	ordinary := testBinding(server.URL)
	o, _ := NewClient(server.Client().Transport, ordinary, DefaultLimits())
	o, _ = o.WithCredential("")
	if _, err := o.QualifyTrustedGuardEvidence(t.Context(), tx, trustedGuard(t, tx)); err == nil {
		t.Fatal("call profile qualified Guard evidence")
	}
	for name, change := range map[string]func(*TrustedGuardEvidence){"tx": func(e *TrustedGuardEvidence) { e.TransactionHash = common.Hash{} }, "chain": func(e *TrustedGuardEvidence) { e.ChainID = 2 }, "profile": func(e *TrustedGuardEvidence) { e.Profile = NodeProfileID }, "header": func(e *TrustedGuardEvidence) { e.HeaderPresent = false }, "fork": func(e *TrustedGuardEvidence) { e.HeaderTimestamp = 20 }, "fingerprint": func(e *TrustedGuardEvidence) { e.Fingerprint = common.Hash{} }, "mode": func(e *TrustedGuardEvidence) { e.HashMode = 1 }, "root": func(e *TrustedGuardEvidence) { e.Calls = []byte(`{"type":"CALL"}`) }} {
		t.Run(name, func(t *testing.T) {
			e := trustedGuard(t, tx)
			change(&e)
			if _, err := c.QualifyTrustedGuardEvidence(t.Context(), tx, e); err == nil {
				t.Fatal("bad binding accepted")
			}
		})
	}
	// includeEmpty=false means missing accounts stay unknown. An exact-anchor
	// supplement is required; a PRESENT account with omitted code is empty.
	e = trustedGuard(t, tx)
	e.Prestate = []byte(`{}`)
	if _, err := c.QualifyTrustedGuardEvidence(t.Context(), tx, e); err != nil {
		t.Fatal(err)
	}
	if len(n.methods) != 1 || n.methods[0] != "eth_getCode" || n.anchors[0] != testHash {
		t.Fatal("missing code guessed or re-traced", n.methods)
	}
	e.Prestate = []byte(`{"` + testTarget + `":{}}`)
	execution, err = c.QualifyTrustedGuardEvidence(t.Context(), tx, e)
	if err != nil {
		t.Fatal(err)
	}
	code, known := execution.Code(common.HexToAddress(testTarget))
	if !known || code.HasCode() || len(n.methods) != 1 {
		t.Fatal("present known empty account changed")
	}
}

func TestRetainedGuardStorageIsBoundedAndNotAcceptedByCallProfile(t *testing.T) {
	zero := "0x" + strings.Repeat("00", 32)
	word := "0x" + strings.Repeat("ab", 32)
	for name, storage := range map[string]string{"null": "null", "array": "[]", "short key": `{"0x0":"` + zero + `"}`, "short value": `{"` + zero + `":"0x0"}`, "null value": `{"` + zero + `":null}`, "duplicate": `{"` + word + `":"` + zero + `","0x` + strings.Repeat("AB", 32) + `":"` + zero + `"}`} {
		t.Run(name, func(t *testing.T) {
			raw := []byte(`{"` + testTarget + `":{"storage":` + storage + `}}`)
			if _, _, err := decodePrestateProfile(raw, DefaultLimits(), true); err == nil {
				t.Fatal("invalid storage accepted")
			}
		})
	}
	storage := `{"` + zero + `":"` + word + `"}`
	raw := []byte(`{"` + testTarget + `":{"storage":` + storage + `}}`)
	if _, _, err := decodePrestateProfile(raw, DefaultLimits(), true); err != nil {
		t.Fatal(err)
	}
	if _, _, err := decodePrestate(raw, DefaultLimits()); err == nil {
		t.Fatal("ordinary call parser accepted storage")
	}
	var buf strings.Builder
	buf.WriteByte('{')
	for i := 0; i < MaxGuardSlotsPerAccount; i++ {
		if i > 0 {
			buf.WriteByte(',')
		}
		fmt.Fprintf(&buf, `"0x%064x":"%s"`, i, zero)
	}
	buf.WriteByte('}')
	total := 0
	if err := checkGuardStorage([]byte(buf.String()), &total); err != nil || total != MaxGuardSlotsPerAccount {
		t.Fatal("exact slot limit", err, total)
	}
	over := buf.String()[:buf.Len()-1] + fmt.Sprintf(`,"0x%064x":"%s"}`, MaxGuardSlotsPerAccount, zero)
	total = 0
	if checkGuardStorage([]byte(over), &total) == nil {
		t.Fatal("per-account overflow")
	}
	total = MaxGuardSlots - 1
	if checkGuardStorage([]byte(storage), &total) != nil || total != MaxGuardSlots {
		t.Fatal("exact aggregate limit")
	}
	if checkGuardStorage([]byte(storage), &total) == nil {
		t.Fatal("aggregate overflow")
	}
}
