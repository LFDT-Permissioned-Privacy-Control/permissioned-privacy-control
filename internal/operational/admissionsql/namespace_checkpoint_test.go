package admissionsql_test

import (
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	a "privacy-proxy/internal/admission"
	"privacy-proxy/internal/creationfacts"
	h "privacy-proxy/internal/historynamespace"
	"privacy-proxy/internal/operational/admissionsql"
	"privacy-proxy/internal/rpcexecution"
)

func TestNamespaceCheckpointActualTLSAndPostgresOpaqueImport(t *testing.T) {
	d, _ := namespaceDBSetup(t)
	genesis := &types.Header{Number: big.NewInt(0), Difficulty: big.NewInt(0), GasLimit: 30000000, Time: 1, UncleHash: types.EmptyUncleHash, TxHash: types.EmptyTxsHash, ReceiptHash: types.EmptyReceiptsHash, Extra: []byte{}}
	entry := types.CopyHeader(genesis)
	entry.Number, entry.Time, entry.ParentHash = big.NewInt(100), 1000, genesis.Hash()
	point := types.CopyHeader(entry)
	point.Number, point.Time, point.ParentHash = big.NewInt(150), 1500, entry.Hash()
	binding := a.NetworkBinding{Environment: "test", ChainID: "1", GenesisHash: genesis.Hash().Hex(), DeploymentID: uuid.NewString()}
	generation := uuid.NewString()
	if err := admissionsql.BootstrapEmpty(t.Context(), d.db.ownerDSN, binding, generation); err != nil {
		t.Fatal(err)
	}
	key, _ := binding.Key()
	era := h.ModelEra{EntryNumber: 100, EntryHash: h.Hash(entry.Hash()), EntryTimestamp: 1000, EndTimestampExclusive: 2000}
	if err := admissionsql.BootstrapNamespace(t.Context(), d.db.ownerDSN, binding, generation, era, h.DefaultCapacityLimits(), true, true); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     uint64            `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			t.Error("bad fixture RPC")
			return
		}
		calls.Add(1)
		var result any
		switch req.Method {
		case "eth_chainId":
			result = "0x1"
		case "eth_syncing":
			result = false
		case "eth_getHeaderByNumber":
			var selector string
			_ = json.Unmarshal(req.Params[0], &selector)
			if selector == "0x0" {
				result = genesis
			} else if selector == "0x96" {
				result = point
			} else {
				t.Error("unexpected checkpoint number", selector)
			}
		case "eth_getCode":
			var selector map[string]any
			if len(req.Params) != 2 || json.Unmarshal(req.Params[1], &selector) != nil || selector["blockHash"] != point.Hash().Hex() || selector["requireCanonical"] != true {
				t.Error("unbound code acquisition")
			}
			result = "0x6000"
		default:
			t.Error("unexpected fixture RPC", req.Method)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
	}))
	defer server.Close()
	source := creationfacts.Source{Network: creationfacts.Network{Key: creationfacts.Digest(key), Environment: binding.Environment, ChainID: binding.ChainID, Genesis: genesis.Hash(), Deployment: binding.DeploymentID}, URL: server.URL, Profile: rpcexecution.IncludedProfileID, PragueStart: 1000, PragueEnd: 2000}
	client, err := rpcexecution.NewNamespaceCheckpointClient(server.Client().Transport, source, rpcexecution.Credential{}, era, rpcexecution.DefaultNamespaceCheckpointLimits())
	if err != nil {
		t.Fatal(err)
	}
	address := h.Address{0x20}
	proof, err := client.Qualify(t.Context(), 150, []h.Address{address})
	if err != nil || calls.Load() != 9 {
		t.Fatal("owned actual TLS proof", err, calls.Load())
	}
	runtime := h.Hash(crypto.Keccak256Hash([]byte{0x60, 0x00}))
	statement := map[string]any{"kind": "prague-checkpoint", "address": address.String(), "runtimeHash": runtime.String(), "runtimeLength": 2, "initial": map[string]any{"kind": "org", "organizationId": "12345678-1234-4234-8234-123456789abc"}, "physical": map[string]any{"kind": "preexisting"}, "checkpoint": h.CheckpointRef{Number: 150, Hash: h.Hash(point.Hash())}}
	path, pin := namespaceArtifactFile(t, binding, era, uuid.NewString(), statement)
	m, _ := admissionsql.ReadNamespaceOwnerMetadata(t.Context(), d.db.ownerDSN, binding)
	if _, err := admissionsql.ImportNamespace(t.Context(), d.db.ownerDSN, binding, m.State, path, pin, &rpcexecution.NamespaceCheckpointProof{}, true); err == nil {
		t.Fatal("zero opaque proof imported")
	}
	imported, err := admissionsql.ImportNamespace(t.Context(), d.db.ownerDSN, binding, m.State, path, pin, proof, true)
	if err != nil {
		t.Fatal("actual proof-to-SQL import", err)
	}
	var storedHash, storedProof []byte
	if d.db.owner.QueryRow(t.Context(), `SELECT runtime_hash,proof_digest FROM ops_history_namespace_v1.legacy_contract_lifetimes WHERE network_key=$1`, key[:]).Scan(&storedHash, &storedProof) != nil || len(storedProof) != 32 || h.Hash(storedHash) != runtime || h.Digest(storedProof) != proof.Digest() {
		t.Fatal("normalized stored runtime/proof differs")
	}
	statement["runtimeHash"] = h.Hash{7}.String()
	badPath, badPin := namespaceArtifactFile(t, binding, era, uuid.NewString(), statement)
	if _, err := admissionsql.ImportNamespace(t.Context(), d.db.ownerDSN, binding, imported.State, badPath, badPin, proof, true); err == nil {
		t.Fatal("declared runtime bypassed actual owned proof")
	}
	if err := admissionsql.FinalizeNamespaceRecovery(t.Context(), d.db.ownerDSN, binding, imported.State, h.Digest{7}, true, true, 600); err != nil {
		t.Fatal("retained owned checkpoint witness", err)
	}
}

func TestNamespaceTransferActualPostgresAcceptedBirthPresence(t *testing.T) {
	d, _ := namespaceDBSetup(t)
	node, scope, _, snap, client := newObservedWork(t, d)
	_, qualified := acquireObserved(t, d, snap, client)
	if err := d.observer.PublishCreationObservation(t.Context(), qualified); err != nil {
		t.Fatal("accepted A2 birth publication", err)
	}
	network := client.Source().Network
	binding := a.NetworkBinding{Environment: network.Environment, ChainID: network.ChainID, GenesisHash: network.Genesis.Hex(), DeploymentID: network.Deployment}
	era := h.ModelEra{EntryNumber: 0, EntryHash: h.Hash(node.genesis.Hash()), EntryTimestamp: node.genesis.Time, EndTimestampExclusive: node.genesis.Time + 1000}
	if err := admissionsql.BootstrapNamespace(t.Context(), d.db.ownerDSN, binding, scope.State.Generation, era, h.DefaultCapacityLimits(), true, true); err != nil {
		t.Fatal(err)
	}
	m, err := admissionsql.ReadNamespaceOwnerMetadata(t.Context(), d.db.ownerDSN, binding)
	if err != nil {
		t.Fatal(err)
	}
	segment, err := h.PragueSegmentKey(h.Digest(scope.Network), h.Address(node.child), h.Hash(crypto.Keccak256Hash([]byte{0x60, 0})), 2)
	if err != nil {
		t.Fatal(err)
	}
	initial := map[string]any{"kind": "org", "organizationId": scope.Organization}
	transfer := map[string]any{"kind": "transfer", "address": node.child.Hex(), "segmentKind": "prague", "segment": segment.String(), "initial": initial, "previous": initial, "new": map[string]any{"kind": "public"}, "effectiveFrom": h.Cut{Number: 1, Hash: h.Hash(node.header.Hash()), Index: 1}}
	path, pin := namespaceArtifactFile(t, binding, era, uuid.NewString(), transfer)
	imported, err := admissionsql.ImportNamespace(t.Context(), d.db.ownerDSN, binding, m.State, path, pin, nil, true)
	if err != nil {
		t.Fatal("A2 original assertion presence", err)
	}
	// The archive only checks retained original-assertion presence. Canonical
	// eligibility at this attested transfer cut belongs to the later C2 pass.
	if err := admissionsql.FinalizeNamespaceRecovery(t.Context(), d.db.ownerDSN, binding, imported.State, h.Digest{7}, true, true, 600); err != nil {
		t.Fatal("restore accepted birth-backed transfer", err)
	}
	if births, associations := observedCounts(t, d, scope); births != 1 || associations != 1 {
		t.Fatal("namespace import mutated A2 originals", births, associations)
	}
}
