package rpcengine_test

import (
	"encoding/hex"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"privacy-proxy/internal/nativeadmission"
	"privacy-proxy/internal/rpcengine"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/runtimepolicy"
	"privacy-proxy/internal/transactioninput"
)

func TestCallCatalogCannotActivateSignedRetainedGuardEvidence(t *testing.T) {
	f := newFixture()
	snapshot := f.load(t)
	clock := func() time.Time { return time.Unix(now, 0) }
	factory, err := runtimepolicy.NewFactory(snapshot, clock)
	if err != nil {
		t.Fatal(err)
	}
	view, err := factory.Build(token(t, snapshot, f.roles))
	if err != nil {
		t.Fatal(err)
	}
	key, _ := crypto.HexToECDSA(strings.Repeat("0", 63) + "1")
	to := common.HexToAddress(addressA)
	signed, err := types.SignTx(types.NewTransaction(1, to, big.NewInt(0), 100000, big.NewInt(1), nil), types.LatestSignerForChainID(big.NewInt(1)), key)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := signed.MarshalBinary()
	tx, err := transactioninput.DecodeRaw("0x"+hex.EncodeToString(raw), "1", transactioninput.ProtectedEVMProfile(), transactioninput.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	bindings := map[string]*rpcexecution.Client{}
	for _, org := range []string{orgA, orgB} {
		c, err := rpcexecution.NewClient(http.DefaultTransport, rpcexecution.NodeBinding{OrganizationID: org, URL: "http://unused.invalid", ChainID: "1", Profile: rpcexecution.GuardRetainedProfileID, PragueStartInclusive: 10, PragueEndExclusive: 20, AllowUnauthenticated: true}, rpcexecution.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		bindings[org] = c
	}
	client, _ := bindings[orgA].WithCredential("")
	execution, err := client.QualifyTrustedGuardEvidence(t.Context(), tx, rpcexecution.TrustedGuardEvidence{Profile: rpcexecution.GuardRetainedProfileID, Calls: []byte(`{"type":"CALL","from":"` + tx.Signer().Hex() + `","to":"` + addressA + `","input":"0x","value":"0x0","gas":"0x10000","gasUsed":"0x1"}`), Prestate: []byte(`{"` + addressA + `":{"code":"0x6000"}}`), ChainID: 1, TransactionHash: tx.Hash(), Fingerprint: common.HexToHash("0x1"), HashMode: 3, HeaderHash: common.HexToHash(nodeHash), HeaderTimestamp: 10, HeaderPresent: true})
	if err != nil {
		t.Fatal(err)
	}
	wallets, err := nativeadmission.NewWalletSnapshot(view.ActorID(), "ownership-proof", clock(), []common.Address{tx.Signer()})
	if err != nil {
		t.Fatal(err)
	}
	admission, err := nativeadmission.New(snapshot, clock)
	if err != nil {
		t.Fatal(err)
	}
	if admission.Check(t.Context(), view, orgA, execution, wallets).Allowed {
		t.Fatal("call-only native engine accepted signed scope")
	}
	if _, err := rpcengine.New(snapshot, bindings, nil, clock); err == nil {
		t.Fatal("call-only engine accepted Guard profile bindings")
	}
}
