package protectedsource

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	a "privacy-proxy/internal/admission"
	"privacy-proxy/internal/creationcapture"
	cf "privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/creationobserver"
	d "privacy-proxy/internal/disclosuredata"
	p "privacy-proxy/internal/disclosurepolicy"
	f "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/nativeadmission"
	"privacy-proxy/internal/operational/admissionsql"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/rpcexecution"
)

// The captured intent is a trusted journal input, as in the existing observer
// integration tests; this does not rerun native preflight or claim consensus.
// The wallet version comes from an actual EIP-191 link. Included acquisition,
// qualification, original covered-capture validation, publication and namespace
// resolution are real. No birth/association/ownership SQL rows are fabricated.
func publishActualRootCreation(t *testing.T, h *eventsHTTPFixture, node *functionalNode) {
	t.Helper()
	ctx := t.Context()
	tx := node.tx
	if tx.To() != nil {
		t.Fatal("actual root CREATE required")
	}
	actor := f.Actor(f.Subject)
	wallet, err := h.control.wallet.Resolver.Load(ctx, actor)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := types.Sender(types.LatestSignerForChainID(tx.ChainId()), tx)
	if err != nil || !wallet.Contains(signer) {
		t.Fatal("creation signer lacks actual wallet proof", err)
	}
	created := crypto.CreateAddress(signer, tx.Nonce())
	reference := node.config.Source
	reference.Organization = ""
	ingress := reference
	ingress.Organization = f.Org
	ingress.Profile = rpcexecution.LifecycleSignedProfileID
	set, err := cf.SourceSet([]cf.Source{ingress})
	if err != nil {
		t.Fatal(err)
	}
	expected := h.config.Finance.ExpectedState
	metadata := creationcapture.Metadata{Network: reference.Network, State: cf.State{Generation: expected.Generation, Coverage: cf.Digest(expected.Coverage)}, Reference: reference.Digest(), SourceSet: set}
	floor := cf.Header{Number: 0, Hash: node.genesis.Hash(), Parent: node.genesis.ParentHash, Timestamp: node.genesis.Time}
	dsn := h.control.admission.Config().ConnString()
	if err = admissionsql.BootstrapCreationObserver(ctx, dsn, a.NetworkBinding(node.network), expected, metadata, floor); err != nil {
		t.Fatal("real observer bootstrap", err)
	}
	observer, err := admissionsql.OpenObserver(ctx, functionalDSN(dsn, "ad_observer"))
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close()
	writer, err := admissionsql.OpenCreationObserved(ctx, functionalDSN(dsn, "ad_app"), a.DefaultCreationLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	snapshot, err := observer.AcquireObserverLease(ctx, metadata.Network.Key, metadata.State, uuid.NewString(), set, metadata.Reference)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err = observer.PublishObserverHeaders(ctx, cf.HeaderUpdate{Before: snapshot, Common: floor, Tip: floor})
	if err != nil || !snapshot.State.CaptureReady {
		t.Fatal("capture readiness", err)
	}
	manifest, err := a.ParseDigest(string(h.config.Snapshot.Metadata().ManifestDigest))
	if err != nil {
		t.Fatal(err)
	}
	runtime, ok := h.config.Snapshot.Runtime()
	if !ok {
		t.Fatal("runtime")
	}
	runtimeDigest, err := a.ParseDigest(string(runtime.Digest()))
	if err != nil {
		t.Fatal(err)
	}
	compliance, ok := h.config.Snapshot.Compliance()
	if !ok {
		t.Fatal("compliance")
	}
	complianceDigest, err := a.ParseDigest(compliance.Digest())
	if err != nil {
		t.Fatal(err)
	}
	walletVersion, err := a.ParseDigest(wallet.Version())
	if err != nil {
		t.Fatal(err)
	}
	witness := a.Witness{AnchorHash: floor.Hash, AnchorNumber: 0, AnchorTimestamp: floor.Timestamp, EvidenceProfile: rpcexecution.LifecycleSignedProfileID, WalletVersion: walletVersion, DecisionAt: h.config.Clock(), WalletEvidenceAt: wallet.EvidenceAt(), ManifestDigest: manifest, ComplianceDigest: complianceDigest}
	witness.ID = witness.Digest()
	plan := nativeadmission.CreationPlanData{Version: nativeadmission.CapturedCreationPlanVersion, CaptureProfile: cf.CaptureProfile, Hash: tx.Hash(), RootOrg: f.Org, Manifest: manifest.String(), Runtime: runtimeDigest.String(), Chain: "1", Evidence: rpcexecution.LifecycleSignedProfileID, Entries: []nativeadmission.CreationEntry{{Address: created, Creator: signer, Caller: signer, Kind: "CREATE", Namespace: f.Org, InputHash: crypto.Keccak256Hash(tx.Data()), Value: "0x0", Depth: 0, Record: 0, CreationParent: -1, FactoryRoot: -1}}, Declarations: []policybundle.FactoryAttribution{}, FactoryRoots: []nativeadmission.CreationFactoryRoot{}}
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	intent := a.CreationIntent{Plan: raw, PlanDigest: a.Digest(nativeadmission.CapturedCreationPlanDigest(raw)), Anchor: rpcexecution.Anchor{Hash: floor.Hash, Number: 0, Timestamp: floor.Timestamp, ChainID: "1", OrganizationID: f.Org, Profile: plan.Evidence}, Wallet: &a.CreationWalletAuthority{Actor: actor, Organization: f.Org, Witness: witness.ID}, CapturedAt: h.config.Clock()}
	key, _ := node.network.Key()
	scope := a.Scope{Network: a.Digest(key), State: expected, Organization: f.Org, Actor: actor, Hash: tx.Hash()}
	now := time.Now().UTC().Truncate(time.Microsecond)
	coverage := cf.CoverageRecord{Version: 1, Policy: cf.CaptureProfile, Network: metadata.Network.Key, State: metadata.State, ObserverEpoch: snapshot.Lease.ObserverEpoch, CaptureEpoch: snapshot.Lease.CaptureEpoch, SourceSet: set, Reference: metadata.Reference, Ingress: ingress.Digest(), HighWater: floor, Latest: floor, HeaderVersion: snapshot.State.HeaderVersion, LeaseFence: snapshot.Lease.Fence, ProbeStarted: now, ProbeFinished: now.Add(time.Millisecond), ValidUntil: now.Add(time.Second)}
	if _, err = writer.WithCoveredRawTransaction(ctx, scope, a.CaptureCommitBinding{ObserverEpoch: coverage.ObserverEpoch, CaptureEpoch: coverage.CaptureEpoch, SourceSet: set}, func(raw a.RawTx) (a.CommitKind, error) {
		if _, err := raw.PutOrigin(a.Origin{Network: scope.Network, Hash: tx.Hash(), Actor: actor, Organization: f.Org, FirstAdmittedAt: intent.CapturedAt, Primary: witness}); err != nil {
			return 0, err
		}
		_, err := raw.(a.CoveredCreationRawTx).PutCoveredCreationIntent(intent, coverage)
		return a.CommitAllow, err
	}); err != nil {
		t.Fatal("real covered WALLET intent", err)
	}
	head := cf.Header{Number: node.head.Number.Uint64(), Hash: node.head.Hash(), Parent: node.head.ParentHash, Timestamp: node.head.Time}
	snapshot, err = observer.PublishObserverHeaders(ctx, cf.HeaderUpdate{Before: snapshot, Common: floor, Headers: []cf.Header{head}, Tip: head})
	if err != nil {
		t.Fatal("canonical observer prefix", err)
	}
	work, found, err := observer.LoadNextCreationWork(ctx, metadata.Network, snapshot)
	if err != nil || !found {
		t.Fatal("actual work load", found, err)
	}
	client, err := rpcexecution.NewIncludedClient(node.config.Transport, reference, node.config.Credential, rpcexecution.DefaultIncludedLimits())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := client.AcquireIncluded(ctx, tx.Hash())
	if err != nil {
		t.Fatal("actual included ROOT CREATE protocol", err)
	}
	qualified, err := creationobserver.QualifyIncluded(work, proof)
	if err != nil {
		t.Fatal("actual C2 qualification", err)
	}
	observation := qualified.Data()
	if len(observation.Births) != 1 || observation.Births[0].Record != 0 || observation.Births[0].Address != created || len(observation.Associations) != 1 || observation.Associations[0].Namespace != f.Org {
		t.Fatal("wrong actual root birth", observation)
	}
	if err = observer.PublishCreationObservation(ctx, qualified); err != nil {
		t.Fatal("real immutable C2 publication", err)
	}
}

func TestActualDisclosureEventsRootCreationRequiresIncludedC2Association(t *testing.T) {
	key, err := crypto.HexToECDSA("1111111111111111111111111111111111111111111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	created := crypto.CreateAddress(crypto.PubkeyToAddress(key.PublicKey), 0)
	unknown := common.HexToAddress("0xdead00000000000000000000000000000000beef")
	node := ownedFunctionalEventNode(t, functionalEventNodeOptions{
		To: map[int]*common.Address{0: nil},
		Logs: [][]*types.Log{{
			{Address: created, Topics: []common.Hash{{1}}, Data: []byte{1, 2, 3}},
			{Address: unknown, Topics: []common.Hash{{2}}, Data: []byte{4, 5, 6}},
		}},
	})
	h := actualEventsHTTP(t, node)
	id := h.openCase("auditor", []p.Resource{p.Events}, p.Full, f.Now+120)
	query := d.Query{Version: 1, Resource: p.Events, View: d.List}
	before, _ := h.page(id, query)
	if len(before.Result.Items) != 0 || before.Result.NextCursor != nil {
		t.Fatal("receipt createdAddress alone invented org ownership", before)
	}
	publishActualRootCreation(t, h, node)
	after, _ := h.page(id, query)
	if len(after.Result.Items) != 1 || after.Result.Items[0].Emitter != a.AddressString(created) || after.Result.Items[0].LogIndex != 0 || after.Result.Items[0].Data == nil || *after.Result.Items[0].Data != "0x010203" || after.Result.NextCursor != nil {
		t.Fatal("actual root creation event lost or unqualified emitter exposed", after)
	}
}
