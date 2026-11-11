package admissionsql_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"runtime"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	a "privacy-proxy/internal/admission"
	"privacy-proxy/internal/creationcapture"
	f "privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/creationobserver"
	h "privacy-proxy/internal/historynamespace"
	"privacy-proxy/internal/nativeadmission"
	"privacy-proxy/internal/operational/admissionsql"
	"privacy-proxy/internal/rpcexecution"
)

func namespaceReadScope(binding a.NetworkBinding, era h.ModelEra) (h.TrustedRootScope, []h.CanonicalBlock) {
	key, _ := binding.Key()
	address := h.Address{0x20}
	count := uint32(3)
	scope := h.TrustedRootScope{Network: h.Digest(key), Era: era, CanonicalViewID: h.Digest{44}, Head: h.CanonicalBlock{Number: 200, Hash: h.Hash{6}, Timestamp: 1900}, Roots: []h.Root{{Hash: h.Hash{20}, BlockHash: h.Hash{5}, Number: 120, Index: 0, Timestamp: 1200, To: &address}}}
	// This is the trusted future C-B DTO seam, not a node-qualification test.
	blocks := []h.CanonicalBlock{{Number: 100, Hash: h.Hash{1}, Timestamp: 1000, TxCount: &count}, {Number: 120, Hash: h.Hash{5}, Timestamp: 1200, TxCount: &count}, {Number: 150, Hash: h.Hash{2}, Timestamp: 1500, TxCount: &count}, scope.Head}
	return scope, blocks
}

func TestNamespaceResolveActualPostgresTypedRowsAndDiscoveryRecheck(t *testing.T) {
	d, dsn := namespaceDBSetup(t)
	binding, scope := creationScope(t, d.db)
	era := h.ModelEra{EntryNumber: 100, EntryHash: h.Hash{1}, EntryTimestamp: 1000, EndTimestampExclusive: 2000}
	if err := admissionsql.BootstrapNamespace(t.Context(), d.db.ownerDSN, binding, scope.State.Generation, era, h.DefaultCapacityLimits(), true, true); err != nil {
		t.Fatal(err)
	}
	m, _ := admissionsql.ReadNamespaceOwnerMetadata(t.Context(), d.db.ownerDSN, binding)
	cohort := uuid.NewString()
	path, pin := namespaceArtifactFile(t, binding, era, cohort, namespaceFinite(0x20))
	original, err := admissionsql.ImportNamespace(t.Context(), d.db.ownerDSN, binding, m.State, path, pin, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	org := map[string]any{"kind": "org", "organizationId": "12345678-1234-4234-8234-123456789abc"}
	edge := map[string]any{"kind": "transfer", "address": h.Address{0x20}.String(), "segmentKind": "prague", "segment": original.LifetimeSegments[0].String(), "initial": org, "previous": org, "new": map[string]any{"kind": "public"}, "effectiveFrom": h.Cut{Number: 120, Hash: h.Hash{5}, Index: 1}}
	path, pin = namespaceArtifactFile(t, binding, era, uuid.NewString(), edge)
	imported, err := admissionsql.ImportNamespace(t.Context(), d.db.ownerDSN, binding, original.State, path, pin, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := admissionsql.FinalizeNamespaceRecovery(t.Context(), d.db.ownerDSN, binding, imported.State, h.Digest{7}, true, true, 600); err != nil {
		t.Fatal(err)
	}
	reader, err := admissionsql.OpenNamespaceReader(t.Context(), dsn, binding, scope.State.Generation, era)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	input, blocks := namespaceReadScope(binding, era)
	requirements, err := reader.DiscoverRequirements(t.Context(), input)
	if err != nil {
		t.Fatal("real restricted-reader discovery", err)
	}
	pass := h.TrustedRootPass{Scope: input, CanonicalBlocks: blocks, ExpectedScopeDigest: requirements.ScopeDigest(), ExpectedRequirementsDigest: requirements.Digest()}
	result, err := reader.ResolvePass(t.Context(), pass)
	if err != nil || len(result.Results()) != 1 || result.Results()[0].Kind != h.KnownOrg || *result.Results()[0].OrganizationID != "12345678-1234-4234-8234-123456789abc" {
		t.Fatal("actual typed lifetime/edge rows", result, err)
	}
	again, err := reader.ResolvePass(t.Context(), pass)
	if err != nil || again.AuthorityDigest() != result.AuthorityDigest() {
		t.Fatal("unchanged whole repeat", err)
	}
	after := input
	after.Roots = append([]h.Root(nil), input.Roots...)
	after.Roots[0].Index = 1
	req, err := reader.DiscoverRequirements(t.Context(), after)
	if err != nil {
		t.Fatal(err)
	}
	public, err := reader.ResolvePass(t.Context(), h.TrustedRootPass{Scope: after, CanonicalBlocks: blocks, ExpectedScopeDigest: req.ScopeDigest(), ExpectedRequirementsDigest: req.Digest()})
	if err != nil || public.Results()[0].Kind != h.KnownPublic || public.Results()[0].OrganizationID != nil {
		t.Fatal("public mislabeled as data organization", public, err)
	}
	missing := pass
	missing.CanonicalBlocks = append([]h.CanonicalBlock(nil), blocks[:2]...)
	missing.CanonicalBlocks = append(missing.CanonicalBlocks, blocks[3])
	if _, err := reader.ResolvePass(t.Context(), missing); !errors.Is(err, h.ErrUnavailable) {
		t.Fatal("missing canonical endpoint repaired", err)
	}
	for _, name := range []string{"query ceiling at commit", "candidate sentinel", "output byte ceiling"} {
		t.Run(name, func(t *testing.T) {
			limits := h.DefaultReadLimits()
			switch name {
			case "query ceiling at commit":
				limits.MaxQueries = 8
			case "candidate sentinel":
				limits.MaxCandidates = 1
			case "output byte ceiling":
				limits.MaxOutputBytes = 1
			}
			limited, err := admissionsql.OpenNamespaceReaderWithLimits(t.Context(), dsn, binding, scope.State.Generation, era, limits)
			if err != nil {
				t.Fatal(err)
			}
			defer limited.Close()
			if name == "output byte ceiling" {
				got, err := limited.ResolvePass(t.Context(), pass)
				if !errors.Is(err, h.ErrTooBroad) || got != nil {
					t.Fatal("partial pass escaped failed budget", got, err)
				}
			} else {
				got, err := limited.DiscoverRequirements(t.Context(), input)
				if !errors.Is(err, h.ErrTooBroad) || got != nil {
					t.Fatal("partial discovery escaped failed budget", got, err)
				}
			}
		})
	}
	t.Run("whole pass cancellation and earlier parent deadline", func(t *testing.T) {
		limits := h.DefaultReadLimits()
		limits.Timeout = 40 * time.Millisecond
		limited, err := admissionsql.OpenNamespaceReaderWithLimits(t.Context(), dsn, binding, scope.State.Generation, era, limits)
		if err != nil {
			t.Fatal(err)
		}
		defer limited.Close()
		locker, err := pgx.Connect(t.Context(), d.db.ownerDSN)
		if err != nil {
			t.Fatal(err)
		}
		defer locker.Close(t.Context())
		lock, err := locker.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Rollback(context.Background())
		if _, err := lock.Exec(t.Context(), `LOCK TABLE ops_history_namespace_v1.namespace_transfers IN ACCESS EXCLUSIVE MODE`); err != nil {
			t.Fatal(err)
		}
		// The 500ms SQL lock wait cannot extend either the whole-pass
		// lower ceiling or a caller's earlier deadline. Neither path can
		// return the lifetime rows already read before the blocked query.
		if got, err := limited.DiscoverRequirements(t.Context(), input); !errors.Is(err, h.ErrUnavailable) || got != nil {
			t.Fatal("pass timeout released partial discovery", got, err)
		}
		parent, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
		defer cancel()
		if got, err := reader.ResolvePass(parent, pass); !errors.Is(err, h.ErrUnavailable) || got != nil || !errors.Is(parent.Err(), context.DeadlineExceeded) {
			t.Fatal("earlier parent deadline ignored or partial pass escaped", got, err, parent.Err())
		}
		canceled, cancelNow := context.WithCancel(t.Context())
		cancelNow()
		if got, err := reader.DiscoverRequirements(canceled, input); !errors.Is(err, h.ErrUnavailable) || got != nil {
			t.Fatal("canceled caller released discovery", got, err)
		}
	})
	// An exact discovery does not authorize later exposure after original
	// source deny/readiness changes, even if a previous result is still held.
	m, _ = admissionsql.ReadNamespaceOwnerMetadata(t.Context(), d.db.ownerDSN, binding)
	if err := admissionsql.BeginNamespaceRecovery(t.Context(), d.db.ownerDSN, binding, m.State, scope.State.Generation, true); err != nil {
		t.Fatal(err)
	}
	m, _ = admissionsql.ReadNamespaceOwnerMetadata(t.Context(), d.db.ownerDSN, binding)
	if err := admissionsql.RevokeNamespaceCohorts(t.Context(), d.db.ownerDSN, binding, m.State, []string{cohort}, "source-compromise", true); err != nil {
		t.Fatal(err)
	}
	m, _ = admissionsql.ReadNamespaceOwnerMetadata(t.Context(), d.db.ownerDSN, binding)
	if err := admissionsql.FinalizeNamespaceRecovery(t.Context(), d.db.ownerDSN, binding, m.State, h.Digest{8}, true, true, 600); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ResolvePass(t.Context(), pass); !errors.Is(err, h.ErrUnavailable) {
		t.Fatal("stale discovered authority survived denial", err)
	}
}

type namespaceObservedReadFixture struct {
	d         *observerDatabase
	reader    *admissionsql.NamespaceReader
	node      *observedNode
	scope     a.Scope
	intent    a.CreationIntent
	snapshot  f.ObserverSnapshot
	client    *rpcexecution.IncludedClient
	input     h.TrustedRootScope
	blocks    []h.CanonicalBlock
	late      *creationobserver.QualifiedObservation
	binding   a.NetworkBinding
	readerDSN string
}

func namespaceObservedRead(t *testing.T, prepareLate bool) *namespaceObservedReadFixture {
	t.Helper()
	d, dsn := namespaceDBSetup(t)
	node, scope, intent, snap, client := newObservedWork(t, d)
	_, qualified := acquireObserved(t, d, snap, client)
	var late *creationobserver.QualifiedObservation
	if prepareLate {
		// Capture both source intents before either observation publication.
		// The first immutable work snapshot contains only ref1; the second
		// contains ref1+ref2 and will be published later.
		plan, err := intent.CapturedPlanData()
		if err != nil {
			t.Fatal(err)
		}
		plan.Manifest = a.HashParts("late-namespace-read-source").String()
		second := intent
		second.Plan, err = json.Marshal(plan)
		if err != nil {
			t.Fatal(err)
		}
		second.PlanDigest = a.Digest(nativeadmission.CapturedCreationPlanDigest(second.Plan))
		metadata := creationcapture.Metadata{Network: client.Source().Network, State: snap.Lease.State, SourceSet: snap.Lease.SourceSet, Reference: snap.Lease.Reference}
		if err := commitCovered(t.Context(), d.app, scope, second, coverageRecord(metadata, snap, snap.State.Floor)); err != nil {
			t.Fatal("second real covered source", err)
		}
		_, late = acquireObserved(t, d, snap, client)
	}
	if err := d.observer.PublishCreationObservation(t.Context(), qualified); err != nil {
		t.Fatal("accepted automatic publication", err)
	}
	network := client.Source().Network
	binding := a.NetworkBinding{Environment: network.Environment, ChainID: network.ChainID, GenesisHash: network.Genesis.Hex(), DeploymentID: network.Deployment}
	era := h.ModelEra{EntryNumber: 0, EntryHash: h.Hash(node.genesis.Hash()), EntryTimestamp: node.genesis.Time, EndTimestampExclusive: node.genesis.Time + 1000}
	if err := admissionsql.BootstrapNamespace(t.Context(), d.db.ownerDSN, binding, scope.State.Generation, era, h.DefaultCapacityLimits(), true, true); err != nil {
		t.Fatal(err)
	}
	m, _ := admissionsql.ReadNamespaceOwnerMetadata(t.Context(), d.db.ownerDSN, binding)
	if err := admissionsql.FinalizeNamespaceRecovery(t.Context(), d.db.ownerDSN, binding, m.State, h.Digest{9}, true, true, 600); err != nil {
		t.Fatal(err)
	}
	reader, err := admissionsql.OpenNamespaceReader(t.Context(), dsn, binding, scope.State.Generation, era)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reader.Close)
	rootHeader := *node.header
	rootHeader.Number = big.NewInt(2)
	rootHeader.ParentHash = node.header.Hash()
	rootHeader.Time++
	address := h.Address(node.child)
	zero, one := uint32(0), uint32(1)
	head := h.CanonicalBlock{Number: 2, Hash: h.Hash(rootHeader.Hash()), ParentHash: h.Hash(rootHeader.ParentHash), Timestamp: rootHeader.Time, TxCount: &one}
	input := h.TrustedRootScope{Network: h.Digest(scope.Network), Era: era, CanonicalViewID: h.Digest{45}, Head: head, Roots: []h.Root{{Hash: h.Hash{20}, BlockHash: head.Hash, Number: head.Number, Timestamp: head.Timestamp, To: &address}}}
	// The included birth is independently acquired through the accepted A2
	// client/worker. ROOT block2 is a trusted C-B seam fixture, not a claim
	// that this helper acquired a complete real-node ROOT dataset.
	blocks := []h.CanonicalBlock{{Number: 0, Hash: h.Hash(node.genesis.Hash()), ParentHash: h.Hash(node.genesis.ParentHash), Timestamp: node.genesis.Time, TxCount: &zero}, {Number: 1, Hash: h.Hash(node.header.Hash()), ParentHash: h.Hash(node.header.ParentHash), Timestamp: node.header.Time, TxCount: &one}, head}
	return &namespaceObservedReadFixture{d, reader, node, scope, intent, snap, client, input, blocks, late, binding, dsn}
}

func TestNamespaceResolveActualPostgresAutomaticQualifiedBirth(t *testing.T) {
	f := namespaceObservedRead(t, false)
	req, err := f.reader.DiscoverRequirements(t.Context(), f.input)
	if err != nil {
		t.Fatal("automatic fact discovery", err)
	}
	pass := h.TrustedRootPass{Scope: f.input, CanonicalBlocks: f.blocks, ExpectedScopeDigest: req.ScopeDigest(), ExpectedRequirementsDigest: req.Digest()}
	result, err := f.reader.ResolvePass(t.Context(), pass)
	if err != nil || result.Results()[0].Kind != h.KnownOrg || *result.Results()[0].OrganizationID != f.scope.Organization {
		t.Fatal("accepted automatic namespace", result, err)
	}
	if _, err := f.d.db.owner.Exec(t.Context(), `UPDATE ops_admission_v2.creation_observer_state SET capture_ready=false,capture_heartbeat_until=NULL,lease_expires=clock_timestamp()-interval'1 second' WHERE network_key=$1`, f.scope.Network[:]); err != nil {
		t.Fatal(err)
	}
	again, err := f.reader.ResolvePass(t.Context(), pass)
	if err != nil || again.AuthorityDigest() != result.AuthorityDigest() {
		t.Fatal("transient capture/lease movement expired history", err)
	}
	// Restore only the original lease expiry so the real worker method can
	// perform its separately authenticated durable-quarantine transition.
	if _, err := f.d.db.owner.Exec(t.Context(), `UPDATE ops_admission_v2.creation_observer_state SET lease_expires=$2 WHERE network_key=$1`, f.scope.Network[:], f.snapshot.State.LeaseExpires); err != nil {
		t.Fatal(err)
	}
	if err := f.d.observer.QuarantineObserver(t.Context(), f.snapshot, "deep-reorg"); err != nil {
		t.Fatal("real durable quarantine", err)
	}
	if _, err := f.reader.ResolvePass(t.Context(), pass); !errors.Is(err, h.ErrUnavailable) {
		t.Fatal("durable source quarantine became an unowned fallback", err)
	}
}

func TestNamespaceResolveActualPostgresWholeRRAcrossChunks(t *testing.T) {
	fixture := namespaceObservedRead(t, true)
	input := fixture.input
	input.Roots = nil
	blocks := append([]h.CanonicalBlock(nil), fixture.blocks...)
	one := uint32(1)
	parent := blocks[1].Hash
	for i := 0; i < 65; i++ {
		number := uint64(2 + i)
		hash := h.Hash(crypto.Keccak256Hash([]byte{byte(i), 0x72}))
		block := h.CanonicalBlock{Number: number, Hash: hash, ParentHash: parent, Timestamp: fixture.node.header.Time + 1 + uint64(i), TxCount: &one}
		parent = hash
		if i == 0 {
			blocks[2] = block
		} else {
			blocks = append(blocks, block)
		}
		address := h.Address{1}
		address[19] = byte(i + 1)
		if i == 64 {
			address = h.Address(fixture.node.child)
		}
		input.Roots = append(input.Roots, h.Root{Hash: h.Hash(common.BigToHash(big.NewInt(int64(i + 100)))), BlockHash: hash, Number: number, Timestamp: block.Timestamp, To: &address})
		input.Head = block
	}
	// The child is in the SECOND sorted64-address chunk. The other roots
	// are trusted C-B seam fixtures that resolve Unknown, never complete data.
	req, err := fixture.reader.DiscoverRequirements(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	pass := h.TrustedRootPass{Scope: input, CanonicalBlocks: blocks, ExpectedScopeDigest: req.ScopeDigest(), ExpectedRequirementsDigest: req.Digest()}
	before, err := fixture.reader.ResolvePass(t.Context(), pass)
	if err != nil {
		t.Fatal(err)
	}
	locker, err := pgx.Connect(t.Context(), fixture.d.db.ownerDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer locker.Close(t.Context())
	tx, err := locker.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(t.Context(), `LOCK TABLE ops_history_namespace_v1.namespace_transfers IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		result *h.NamespacePass
		err    error
	}
	done := make(chan outcome, 1)
	go func() { p, err := fixture.reader.ResolvePass(t.Context(), pass); done <- outcome{p, err} }()
	wait, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	for {
		var blocked bool
		if err := fixture.d.db.owner.QueryRow(wait, `SELECT EXISTS(SELECT 1 FROM pg_locks l JOIN pg_class c ON c.oid=l.relation JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_stat_activity a ON a.pid=l.pid WHERE n.nspname='ops_history_namespace_v1' AND c.relname='namespace_transfers' AND a.usename='namespace_reader' AND NOT l.granted)`).Scan(&blocked); err != nil {
			t.Fatal("wait for actual reader lock", err)
		}
		if blocked {
			break
		}
		runtime.Gosched()
	}
	// No node call occurs under the read snapshot. This immutable second
	// observation was fully acquired/qualified before the reader started.
	if err := fixture.d.observer.PublishCreationObservation(t.Context(), fixture.late); err != nil {
		t.Fatal("real late A2 association publication", err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	result := <-done
	if result.err != nil || result.result == nil || result.result.AuthorityDigest() != before.AuthorityDigest() {
		t.Fatal("chunks mixed SQL snapshots", result.result, result.err)
	}
	if result.result.Results()[64].Kind != h.KnownOrg {
		t.Fatal("second chunk automatic fact missing")
	}
	if _, err := fixture.reader.ResolvePass(t.Context(), pass); !errors.Is(err, h.ErrUnavailable) {
		t.Fatal("whole repeat missed newly published original association", err)
	}
	var births, associations int64
	births, associations = observedCounts(t, fixture.d, fixture.scope)
	if births != 1 || associations != 2 {
		t.Fatal("late fixture failed real immutable publication", births, associations)
	}
}

func namespaceObservedRecovery(t *testing.T, fixture *namespaceObservedReadFixture, generation string, revokeEpoch string) *admissionsql.NamespaceReader {
	t.Helper()
	if revokeEpoch != "" {
		if err := fixture.d.observer.QuarantineObserver(t.Context(), fixture.snapshot, "uncertain-capture-trust"); err != nil {
			t.Fatal("sticky trust quarantine", err)
		}
	}
	if err := admissionsql.BeginRecovery(t.Context(), fixture.d.db.ownerDSN, fixture.binding, generation); err != nil {
		t.Fatal("actual drained global begin", err)
	}
	expected := a.ExpectedState{Generation: generation, Coverage: admissionsql.EmptyCoverage()}
	if revokeEpoch != "" {
		// BeginRecovery rotates the current operational observer epoch. Read
		// that explicit offline status; never reuse the earlier worker token.
		var recoveryEpoch string
		if err := fixture.d.db.owner.QueryRow(t.Context(), `SELECT observer_epoch::text FROM ops_admission_v2.creation_observer_state WHERE network_key=$1`, fixture.scope.Network[:]).Scan(&recoveryEpoch); err != nil {
			t.Fatal(err)
		}
		if err := admissionsql.RevokeCaptureEpochs(t.Context(), fixture.d.db.ownerDSN, fixture.binding, generation, recoveryEpoch, "freshness-unproven", []string{revokeEpoch}, true); err != nil {
			t.Fatal("actual permanent original epoch deny", err)
		}
		if err := admissionsql.FinalizeCreationObserverRecovery(t.Context(), fixture.d.db.ownerDSN, fixture.binding, expected, recoveryEpoch, true, true, 20*time.Second); err != nil {
			t.Fatal("actual sticky global finalize", err)
		}
	} else if err := admissionsql.FinalizeRecovery(t.Context(), fixture.d.db.ownerDSN, fixture.binding, expected, true); err != nil {
		t.Fatal("actual ordinary global finalize", err)
	}
	network := fixture.client.Source().Network
	snapshot, err := fixture.d.observer.AcquireObserverLease(t.Context(), network.Key, f.State{Generation: generation, Coverage: f.Digest(expected.Coverage)}, uuid.NewString(), fixture.snapshot.Lease.SourceSet, fixture.snapshot.Lease.Reference)
	if err != nil {
		t.Fatal("new generation worker lease", err)
	}
	snapshot, err = fixture.d.observer.PublishObserverHeaders(t.Context(), f.HeaderUpdate{Before: snapshot, Common: snapshot.State.Head, Tip: snapshot.State.Head})
	if err != nil || !snapshot.State.Ready {
		t.Fatal("closed awaiting-canonical activation", err)
	}
	fixture.snapshot = snapshot
	m, err := admissionsql.ReadNamespaceOwnerMetadata(t.Context(), fixture.d.db.ownerDSN, fixture.binding)
	if err != nil {
		t.Fatal(err)
	}
	if err := admissionsql.BeginNamespaceRecovery(t.Context(), fixture.d.db.ownerDSN, fixture.binding, m.State, generation, true); err != nil {
		t.Fatal("separate namespace begin", err)
	}
	m, err = admissionsql.ReadNamespaceOwnerMetadata(t.Context(), fixture.d.db.ownerDSN, fixture.binding)
	if err != nil {
		t.Fatal(err)
	}
	if err := admissionsql.FinalizeNamespaceRecovery(t.Context(), fixture.d.db.ownerDSN, fixture.binding, m.State, h.Digest{10}, true, true, 600); err != nil {
		t.Fatal("separate namespace finalize", err)
	}
	reader, err := admissionsql.OpenNamespaceReader(t.Context(), fixture.readerDSN, fixture.binding, generation, fixture.input.Era)
	if err != nil {
		t.Fatal("reopened current-generation reader", err)
	}
	t.Cleanup(reader.Close)
	return reader
}

func TestNamespaceResolveActualPostgresRecoveryPreservesOriginalCoverage(t *testing.T) {
	fixture := namespaceObservedRead(t, false)
	var originalGeneration string
	var originalDigest []byte
	if err := fixture.d.db.owner.QueryRow(t.Context(), `SELECT admission_generation::text,record_digest FROM ops_admission_v2.creation_capture_coverage WHERE network_key=$1`, fixture.scope.Network[:]).Scan(&originalGeneration, &originalDigest); err != nil {
		t.Fatal(err)
	}
	originalEpoch := fixture.snapshot.Lease.CaptureEpoch
	req, err := fixture.reader.DiscoverRequirements(t.Context(), fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	oldPass := h.TrustedRootPass{Scope: fixture.input, CanonicalBlocks: fixture.blocks, ExpectedScopeDigest: req.ScopeDigest(), ExpectedRequirementsDigest: req.Digest()}
	newGeneration := uuid.NewString()
	reader := namespaceObservedRecovery(t, fixture, newGeneration, "")
	if got, err := fixture.reader.ResolvePass(t.Context(), oldPass); !errors.Is(err, h.ErrUnavailable) || got != nil {
		t.Fatal("stale generation reader survived recovery", got, err)
	}
	req, err = reader.DiscoverRequirements(t.Context(), fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	pass := h.TrustedRootPass{Scope: fixture.input, CanonicalBlocks: fixture.blocks, ExpectedScopeDigest: req.ScopeDigest(), ExpectedRequirementsDigest: req.Digest()}
	result, err := reader.ResolvePass(t.Context(), pass)
	if err != nil || result.Results()[0].Kind != h.KnownOrg || result.Generation() != newGeneration {
		t.Fatal("unaffected historical original coverage was expired by recovery", result, err)
	}
	thirdGeneration := uuid.NewString()
	deniedReader := namespaceObservedRecovery(t, fixture, thirdGeneration, originalEpoch)
	req, err = deniedReader.DiscoverRequirements(t.Context(), fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	denied, err := deniedReader.ResolvePass(t.Context(), h.TrustedRootPass{Scope: fixture.input, CanonicalBlocks: fixture.blocks, ExpectedScopeDigest: req.ScopeDigest(), ExpectedRequirementsDigest: req.Digest()})
	if err != nil || denied.Results()[0].Kind != h.Unknown || denied.Results()[0].OrganizationID != nil {
		t.Fatal("revoked original supplied namespace or fallback owner", denied, err)
	}
	var afterGeneration string
	var afterDigest []byte
	if err := fixture.d.db.owner.QueryRow(t.Context(), `SELECT admission_generation::text,record_digest FROM ops_admission_v2.creation_capture_coverage WHERE network_key=$1`, fixture.scope.Network[:]).Scan(&afterGeneration, &afterDigest); err != nil {
		t.Fatal(err)
	}
	if afterGeneration != originalGeneration || afterGeneration == newGeneration || !bytes.Equal(afterDigest, originalDigest) {
		t.Fatal("recovery rewrote original capture provenance")
	}
}
