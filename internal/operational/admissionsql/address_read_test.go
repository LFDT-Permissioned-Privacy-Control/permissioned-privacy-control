package admissionsql_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	a "privacy-proxy/internal/admission"
	"privacy-proxy/internal/creationcapture"
	f "privacy-proxy/internal/creationfacts"
	df "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/networkidentity"
	"privacy-proxy/internal/operational/admissionsql"
	"privacy-proxy/internal/rpcengine"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/rpcstatepolicy"
)

func TestCurrentAddressActualFactsRolePublishedA2AndRecheck(t *testing.T) {
	d := setupObserver(t)
	node, scope, intent, snap, client := newObservedWork(t, d)
	_, qualified := acquireObserved(t, d, snap, client)
	if err := d.observer.PublishCreationObservation(t.Context(), qualified); err != nil {
		t.Fatal(err)
	}
	binding := f.AddressReadBinding{Network: client.Source().Network, State: snap.Lease.State, SourceSet: snap.Lease.SourceSet, Reference: snap.Lease.Reference, Profile: f.CurrentAddressProfile, Limits: f.DefaultAddressReadLimits()}
	reader, err := admissionsql.NewAddressReader(d.facts, binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admissionsql.NewAddressReader(d.app, binding); err == nil {
		t.Fatal("app role accepted as read-only facts source")
	}
	pass, err := reader.ReadAddressAssociations(t.Context(), node.child)
	if err != nil {
		t.Fatal("actual qualified factory association", err)
	}
	rows := pass.Candidates()
	if len(rows) != 1 || rows[0].Kind != "FACTORY" || rows[0].WalletActor != "" || rows[0].Namespace != scope.Organization {
		t.Fatal("factory invented deployer", rows)
	}
	rows[0].Namespace = "mutated"
	if pass.Candidates()[0].Namespace == "mutated" {
		t.Fatal("candidate getter aliases source")
	}
	if err := reader.RecheckAddressAssociations(t.Context(), pass); err != nil {
		t.Fatal("same current source", err)
	}
	other, err := admissionsql.NewAddressReader(d.facts, binding)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := other.ReadAddressAssociations(t.Context(), node.child)
	if err != nil {
		t.Fatal(err)
	}
	if reader.RecheckAddressAssociations(t.Context(), foreign) == nil {
		t.Fatal("foreign reader result accepted")
	}
	empty, err := reader.ReadAddressAssociations(t.Context(), common.HexToAddress("0xdead"))
	if err != nil || len(empty.Candidates()) != 0 {
		t.Fatal("bounded empty projection", err)
	}
	// The original capture's one-second diagnostic expiry is not a lease on
	// deployed-by authority. No original record or digest is rewritten.
	time.Sleep(1100 * time.Millisecond)
	if _, err := reader.ReadAddressAssociations(t.Context(), node.child); err != nil {
		t.Fatal("genuine current association expired with old capture diagnostic", err)
	}

	// Add a real late WALLET reference through the same accepted atomic
	// admission -> included proof -> qualified observer publication path.
	witness := creationWitness(intent, "current-address-wallet")
	intent.Wallet = &a.CreationWalletAuthority{Actor: scope.Actor, Organization: scope.Organization, Witness: witness.ID}
	metadata := creationcapture.Metadata{Network: client.Source().Network, State: snap.Lease.State, SourceSet: snap.Lease.SourceSet, Reference: snap.Lease.Reference}
	coverage := coverageRecord(metadata, snap, snap.State.Floor)
	_, err = d.app.WithCoveredRawTransaction(t.Context(), scope, a.CaptureCommitBinding{ObserverEpoch: coverage.ObserverEpoch, CaptureEpoch: coverage.CaptureEpoch, SourceSet: coverage.SourceSet}, func(raw a.RawTx) (a.CommitKind, error) {
		if _, err := raw.PutOrigin(a.Origin{Network: scope.Network, Hash: scope.Hash, Actor: scope.Actor, Organization: scope.Organization, FirstAdmittedAt: intent.CapturedAt, Primary: witness}); err != nil {
			return 0, err
		}
		_, err := raw.(a.CoveredCreationRawTx).PutCoveredCreationIntent(intent, coverage)
		return a.CommitAllow, err
	})
	if err != nil {
		t.Fatal(err)
	}
	_, qualified = acquireObserved(t, d, snap, client)
	if err := d.observer.PublishCreationObservation(t.Context(), qualified); err != nil {
		t.Fatal(err)
	}
	if reader.RecheckAddressAssociations(t.Context(), pass) == nil {
		t.Fatal("late target association did not invalidate original snapshot")
	}
	current, err := reader.ReadAddressAssociations(t.Context(), node.child)
	if err != nil {
		t.Fatal(err)
	}
	wallet := false
	for _, row := range current.Candidates() {
		if row.Kind == "WALLET" {
			wallet = row.WalletActor == scope.Actor && row.Namespace == scope.Organization
		}
	}
	if !wallet {
		t.Fatal("actual original WALLET actor absent", current.Candidates())
	}
	t.Run("actual_StateEngine_View_expiry_during_actual_SQL_recheck", func(t *testing.T) {
		fixture := df.DefaultStateFixture(t)
		snapshot := df.StateSnapshot(t, fixture)
		var clock atomic.Int64
		clock.Store(df.Now)
		network := networkidentity.Binding{Environment: binding.Network.Environment, ChainID: binding.Network.ChainID, GenesisHash: binding.Network.Genesis.Hex(), DeploymentID: binding.Network.Deployment}
		stateClient, err := rpcexecution.NewStateClient(http.DefaultTransport, rpcexecution.StateSource{Network: network, URL: client.Source().URL, AllowUnauthenticated: true}, rpcexecution.Credential{}, rpcexecution.DefaultStateLimits())
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(rpcstatepolicy.Source{APIVersion: rpcstatepolicy.APIVersion, Kind: rpcstatepolicy.Kind, BundleManifestDigest: string(snapshot.Metadata().ManifestDigest), AnonymousMethods: []string{}, PreRegisteredAddresses: []rpcstatepolicy.PreRegisteredAddress{}})
		policy, err := rpcstatepolicy.Compile(raw, rpcstatepolicy.Digest(sha256.Sum256(raw)))
		if err != nil {
			t.Fatal(err)
		}
		observed := &observedAddressReader{reader: reader, rechecked: make(chan error, 1)}
		engine, err := rpcengine.NewState(rpcengine.StateConfig{Snapshot: snapshot, Policy: policy, Network: network, Default: stateClient, Clients: map[rpcengine.StateBindingKey]*rpcexecution.StateClient{{OrganizationID: df.Org}: stateClient, {OrganizationID: df.OtherOrg}: stateClient}, Associations: observed, AssociationBinding: binding, QueryLimits: rpcexecution.DefaultStateLimits(), Clock: func() time.Time { return time.Unix(clock.Load(), 0) }})
		if err != nil {
			t.Fatal(err)
		}
		token := df.Token(t, snapshot, df.Subject, "Auditor")
		result := engine.QueryObserved(t.Context(), rpcengine.MetadataAuthorization([]string{"Bearer " + token}), scope.Organization, []byte(`{"id":1,"method":"eth_getCode","params":["`+node.child.Hex()+`","latest"]}`))
		m, err := result.MetadataFor(engine)
		if err != nil || m.Class != rpcengine.SuccessfulCompletion || result.PreflightFor(engine) != nil {
			t.Fatal("actual A2 -> originalJWT StateEngine path", m, err)
		}
		lock, err := d.db.owner.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Rollback(context.Background())
		if _, err := lock.Exec(t.Context(), `LOCK TABLE ops_admission_v2.creation_births IN ACCESS EXCLUSIVE MODE`); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- result.RequireDeliverable(t.Context(), engine) }()
		deadline := time.Now().Add(150 * time.Millisecond)
		for {
			var waiting bool
			if err := lock.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='creation_facts' AND wait_event_type='Lock')`).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if waiting {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("actual facts SQL was not blocked")
			}
			time.Sleep(time.Millisecond)
		}
		clock.Store(df.Now + 300)
		if err := lock.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := <-observed.rechecked; err != nil {
			t.Fatal("actual SQL did not succeed after release", err)
		}
		if err := <-done; err == nil {
			t.Fatal("View expired DURING successful actual SQL recheck released state")
		}
	})

	t.Run("actual_canonical_delivery_and_observer_progress", func(t *testing.T) { currentAddressCanonicalDelivery(t, d, reader, binding, node, snap) })

	// A PRESENT left-join orphan must not be converted into apparently empty
	// public data. Owner-only mutation is a finite corruption control.
	if _, err := d.db.owner.Exec(t.Context(), `CREATE TEMP TABLE saved_current_associations AS SELECT * FROM ops_admission_v2.creation_authority_associations WHERE network_key=$1`, scope.Network[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := d.db.owner.Exec(t.Context(), `DELETE FROM ops_admission_v2.creation_authority_associations WHERE network_key=$1`, scope.Network[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadAddressAssociations(t.Context(), node.child); err == nil {
		t.Fatal("present malformed join became empty positive source")
	}
	if _, err := d.db.owner.Exec(t.Context(), `INSERT INTO ops_admission_v2.creation_authority_associations SELECT * FROM saved_current_associations`); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadAddressAssociations(t.Context(), node.child); err != nil {
		t.Fatal("restored exact source", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := reader.ReadAddressAssociations(ctx, node.child); err == nil {
		t.Fatal("cancelled read supplied facts")
	}
	// A changed current generation never relabels old provenance or falls back.
	wrong := binding
	wrong.State.Generation = "11111111-1111-1111-1111-111111111111"
	stale, err := admissionsql.NewAddressReader(d.facts, wrong)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stale.ReadAddressAssociations(t.Context(), node.child); err == nil {
		t.Fatal("wrong current generation supplied facts")
	}
	if _, err := d.db.owner.Exec(t.Context(), `INSERT INTO ops_admission_v2.revoked_creation_capture_epochs(network_key,capture_epoch,witness_tx_hash,witness_seed_digest,reason,revoked_at) SELECT DISTINCT ON(capture_epoch) network_key,capture_epoch,tx_hash,seed_digest,'freshness-unproven',clock_timestamp() FROM ops_admission_v2.creation_capture_coverage WHERE network_key=$1 ORDER BY capture_epoch,tx_hash,seed_digest`, scope.Network[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadAddressAssociations(t.Context(), node.child); err == nil {
		t.Fatal("revoked original capture became current authority")
	}
}

// This test-only observer reports the actual concrete SQL return; it cannot
// substitute a positive verdict for the real scoped reader.
type observedAddressReader struct {
	reader    *admissionsql.AddressReader
	rechecked chan error
}

func (r *observedAddressReader) Metadata() f.AddressReaderMetadata { return r.reader.Metadata() }
func (r *observedAddressReader) ReadAddressAssociations(ctx context.Context, target common.Address) (*f.AddressAssociations, error) {
	return r.reader.ReadAddressAssociations(ctx, target)
}
func (r *observedAddressReader) RecheckAddressAssociations(ctx context.Context, pass *f.AddressAssociations) error {
	err := r.reader.RecheckAddressAssociations(ctx, pass)
	r.rechecked <- err
	return err
}
