package rpcengine_test

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"privacy-proxy/internal/nativeadmission"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/runtimepolicy"
	"privacy-proxy/internal/transactioninput"
)

func rawTransaction(t *testing.T, input []byte) transactioninput.VerifiedTransaction {
	t.Helper()
	key, _ := crypto.HexToECDSA(strings.Repeat("0", 63) + "1")
	tx, err := types.SignTx(types.NewTransaction(9, common.HexToAddress(addressA), big.NewInt(0), 100000, big.NewInt(1), input), types.LatestSignerForChainID(big.NewInt(1)), key)
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

func TestRawNativeSignerIsVerifiedAndSimulationNeverBorrowsIt(t *testing.T) {
	for _, source := range []policycore.AddressSource{policycore.AddressSourceSigner, policycore.AddressSourcePrincipalLinked} {
		t.Run(string(source), func(t *testing.T) {
			f := newFixture()
			f.rawMode = policybundle.RawSubmissionOPSPreflight
			var abi any
			json.Unmarshal([]byte(`[{"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"name":"who","type":"address"}],"outputs":[{"type":"uint256"}]}]`), &abi)
			canonical := encoded(t, abi)
			f.contracts[0].ABI = canonical
			f.bindings[0].Allow = []policycore.FrameRule{{StorageAddress: addressA, Selector: "0x70a08231", ABIDigest: policycore.ABIDigest(string(canonical)), Args: []policycore.ArgConstraint{{Index: 0, AddressEquals: &policycore.AddressMatch{Source: source}}}}}
			f.capability(policybundle.CapabilityCalldata)
			if source == policycore.AddressSourcePrincipalLinked {
				f.capability(policybundle.CapabilityLinkedWallets)
			}
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
			if _, err := nativeadmission.New(snapshot, clock); err == nil {
				t.Fatal("old constructor accepted composed profile")
			}
			native, err := nativeadmission.NewRaw(snapshot, clock)
			if err != nil {
				t.Fatal(err)
			}
			signer := common.HexToAddress("0x7e5f4552091a69125d5dfcb7b8c2659029395bdf")
			input := append(common.FromHex("0x70a08231"), common.LeftPadBytes(signer.Bytes(), 32)...)
			tx := rawTransaction(t, input)
			n := &node{}
			server := httptest.NewServer(n)
			defer server.Close()
			binding := rpcexecution.NodeBinding{OrganizationID: orgA, URL: server.URL, ChainID: "1", Profile: rpcexecution.SignedCallProfileID, PragueStartInclusive: 10, PragueEndExclusive: 20, AllowUnauthenticated: true}
			client, err := rpcexecution.NewClient(server.Client().Transport, binding, rpcexecution.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			client, _ = client.WithCredential("")
			execution, err := client.AcquireSigned(t.Context(), tx)
			if err != nil {
				t.Fatal(err)
			}
			empty, _ := nativeadmission.NewWalletSnapshot(view.ActorID(), "empty", clock(), []common.Address{})
			linked, _ := nativeadmission.NewWalletSnapshot(view.ActorID(), "linked", clock(), []common.Address{signer})
			if got := native.CheckSigned(t.Context(), view, orgA, execution, empty).Allowed; got != (source == policycore.AddressSourceSigner) {
				t.Fatal("signer/actor ownership conflated", got)
			}
			if !native.CheckSigned(t.Context(), view, orgA, execution, linked).Allowed {
				t.Fatal("qualified signer/linked rule denied")
			}
			if native.Check(t.Context(), view, orgA, execution, linked).Allowed {
				t.Fatal("signed scope accepted as simulation")
			}
			binding.Profile = rpcexecution.NodeProfileID
			simulationClient, _ := rpcexecution.NewClient(server.Client().Transport, binding, rpcexecution.DefaultLimits())
			simulationClient, _ = simulationClient.WithCredential("")
			callRaw := encoded(t, map[string]any{"from": signer.Hex(), "to": addressA, "input": "0x" + hex.EncodeToString(input)})
			call, err := rpcexecution.NormalizeCall(callRaw)
			if err != nil {
				t.Fatal(err)
			}
			block, _ := rpcexecution.ParseBlockSelector(nil)
			simulation, err := simulationClient.AcquireCall(t.Context(), call, block)
			if err != nil {
				t.Fatal(err)
			}
			if got := native.Check(t.Context(), view, orgA, simulation, linked).Allowed; got != (source == policycore.AddressSourcePrincipalLinked) {
				t.Fatal("simulation borrowed signer or changed linked behavior", got)
			}
			if native.Check(t.Context(), view, orgA, simulation, empty).Allowed {
				t.Fatal("simulation explicit-from link floor lost")
			}
			if native.CheckSigned(t.Context(), view, orgA, simulation, linked).Allowed {
				t.Fatal("simulation relabeled signed")
			}
		})
	}
}
