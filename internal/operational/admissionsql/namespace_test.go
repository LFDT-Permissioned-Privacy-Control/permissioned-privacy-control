package admissionsql_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	a "privacy-proxy/internal/admission"
	h "privacy-proxy/internal/historynamespace"
	"privacy-proxy/internal/networkidentity"
	"privacy-proxy/internal/operational/admissionsql"
)

func namespaceDBSetup(t *testing.T) (*observerDatabase, string) {
	t.Helper()
	d := setupObserver(t)
	if _, err := d.db.owner.Exec(t.Context(), `CREATE ROLE namespace_reader LOGIN PASSWORD 'admission-test-only'`); err != nil {
		t.Fatal(err)
	}
	if err := admissionsql.MigrateNamespace(t.Context(), d.db.ownerDSN, "namespace_reader", true); err != nil {
		t.Fatal("namespace migration", err)
	}
	u, _ := url.Parse(d.db.ownerDSN)
	u.User = url.UserPassword("namespace_reader", "admission-test-only")
	return d, u.String()
}

func namespaceFinite(address byte) map[string]any {
	return map[string]any{"kind": "prague-finite", "address": h.Address{address}.String(), "runtimeHash": h.Hash{9}.String(), "runtimeLength": 1,
		"initial": map[string]any{"kind": "org", "organizationId": "12345678-1234-4234-8234-123456789abc"}, "physical": map[string]any{"kind": "preexisting"},
		"start": h.Cut{Number: 100, Hash: h.Hash{1}, Index: 0}, "end": h.Cut{Number: 150, Hash: h.Hash{2}, Index: 1}}
}

func namespaceArtifactFile(t *testing.T, binding a.NetworkBinding, era h.ModelEra, cohort string, statements ...any) (string, h.Digest) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"apiVersion": h.ArtifactAPIVersion, "modelId": h.ModelID, "network": networkidentity.Binding{Environment: binding.Environment, ChainID: binding.ChainID, GenesisHash: binding.GenesisHash, DeploymentID: binding.DeploymentID}, "era": era, "cohortId": cohort, "statements": statements})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "namespace.json")
	if os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("write artifact")
	}
	return path, h.Digest(sha256.Sum256(raw))
}

func TestNamespaceImportActualPostgresOriginalCohortAndAtomicCaps(t *testing.T) {
	d, _ := namespaceDBSetup(t)
	binding, scope := creationScope(t, d.db)
	era := h.ModelEra{EntryNumber: 100, EntryHash: h.Hash{1}, EntryTimestamp: 1000, EndTimestampExclusive: 2000}
	limits := h.DefaultCapacityLimits()
	limits.Lifetimes, limits.Cohorts = 1, 1
	if err := admissionsql.BootstrapNamespace(t.Context(), d.db.ownerDSN, binding, scope.State.Generation, era, limits, true, true); err != nil {
		t.Fatal(err)
	}
	m, err := admissionsql.ReadNamespaceOwnerMetadata(t.Context(), d.db.ownerDSN, binding)
	if err != nil {
		t.Fatal(err)
	}
	cohort := uuid.NewString()
	path, pin := namespaceArtifactFile(t, binding, era, cohort, namespaceFinite(0x20))
	first, err := admissionsql.ImportNamespace(t.Context(), d.db.ownerDSN, binding, m.State, path, pin, nil, true)
	if err != nil || first.Duplicate || first.CohortID != cohort || first.State.Revision != 2 {
		t.Fatal("first typed import", first, err)
	}
	duplicatePath, duplicatePin := namespaceArtifactFile(t, binding, era, uuid.NewString(), namespaceFinite(0x20))
	duplicate, err := admissionsql.ImportNamespace(t.Context(), d.db.ownerDSN, binding, first.State, duplicatePath, duplicatePin, nil, true)
	if err != nil || !duplicate.Duplicate || duplicate.CohortID != first.CohortID || duplicate.OriginalRaw != first.OriginalRaw || duplicate.State != first.State {
		t.Fatal("whole semantic retry at capacity changed first provenance", duplicate, err)
	}
	reusedIDPath, reusedIDPin := namespaceArtifactFile(t, binding, era, cohort, namespaceFinite(0x21))
	if _, err := admissionsql.ImportNamespace(t.Context(), d.db.ownerDSN, binding, first.State, reusedIDPath, reusedIDPin, nil, true); !errors.Is(err, h.ErrConflict) {
		t.Fatal("same cohort UUID accepted different statements", err)
	}
	mixedPath, mixedPin := namespaceArtifactFile(t, binding, era, uuid.NewString(), namespaceFinite(0x20), namespaceFinite(0x21))
	if _, err := admissionsql.ImportNamespace(t.Context(), d.db.ownerDSN, binding, first.State, mixedPath, mixedPin, nil, true); !errors.Is(err, h.ErrConflict) {
		t.Fatal("mixed old/new cohort was partially saved", err)
	}
	newPath, newPin := namespaceArtifactFile(t, binding, era, uuid.NewString(), namespaceFinite(0x21))
	if _, err := admissionsql.ImportNamespace(t.Context(), d.db.ownerDSN, binding, first.State, newPath, newPin, nil, true); !errors.Is(err, h.ErrTooBroad) {
		t.Fatal("growth cap allowed a new cohort", err)
	}
	if err := admissionsql.RevokeNamespaceCohorts(t.Context(), d.db.ownerDSN, binding, first.State, []string{cohort}, "source-compromise", true); err != nil {
		t.Fatal("append original deny", err)
	}
	m, err = admissionsql.ReadNamespaceOwnerMetadata(t.Context(), d.db.ownerDSN, binding)
	if err != nil {
		t.Fatal(err)
	}
	denied, err := admissionsql.ImportNamespace(t.Context(), d.db.ownerDSN, binding, m.State, duplicatePath, duplicatePin, nil, true)
	if err != nil || !denied.Duplicate || !denied.Revoked || denied.CohortID != cohort || denied.State != m.State {
		t.Fatal("revoked retry became a fresh approval", denied, err)
	}
	var lives, cohorts, denies int
	if err := d.db.owner.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM ops_history_namespace_v1.legacy_contract_lifetimes WHERE network_key=$1),(SELECT count(*)FROM ops_history_namespace_v1.namespace_cohorts WHERE network_key=$1),(SELECT count(*)FROM ops_history_namespace_v1.revoked_namespace_cohorts WHERE network_key=$1)`, scope.Network[:]).Scan(&lives, &cohorts, &denies); err != nil || lives != 1 || cohorts != 1 || denies != 1 {
		t.Fatal("failed import had partial effects", lives, cohorts, denies, err)
	}
}

func TestNamespaceRecoveryActualPostgresValidationAndSeparateGeneration(t *testing.T) {
	d, readerDSN := namespaceDBSetup(t)
	binding, scope := creationScope(t, d.db)
	era := h.ModelEra{EntryNumber: 100, EntryHash: h.Hash{1}, EntryTimestamp: 1000, EndTimestampExclusive: 2000}
	if err := admissionsql.BootstrapNamespace(t.Context(), d.db.ownerDSN, binding, scope.State.Generation, era, h.DefaultCapacityLimits(), true, true); err != nil {
		t.Fatal(err)
	}
	m, _ := admissionsql.ReadNamespaceOwnerMetadata(t.Context(), d.db.ownerDSN, binding)
	path, pin := namespaceArtifactFile(t, binding, era, uuid.NewString(), namespaceFinite(0x20))
	imported, err := admissionsql.ImportNamespace(t.Context(), d.db.ownerDSN, binding, m.State, path, pin, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range []struct {
		complete bool
		seconds  int64
	}{{false, 600}, {true, 1801}} {
		if err := admissionsql.FinalizeNamespaceRecovery(t.Context(), d.db.ownerDSN, binding, imported.State, h.Digest{7}, true, args.complete, args.seconds); !errors.Is(err, h.ErrInvalid) {
			t.Fatal("unbounded/incomplete recovery accepted", err)
		}
	}
	if err := admissionsql.FinalizeNamespaceRecovery(t.Context(), d.db.ownerDSN, binding, imported.State, h.Digest{7}, true, true, 600); err != nil {
		t.Fatal("present archive finalize", err)
	}
	reader, err := admissionsql.OpenNamespaceReader(t.Context(), readerDSN, binding, scope.State.Generation, era)
	if err != nil {
		t.Fatal("validated minimal reader startup", err)
	}
	m, err = reader.Metadata(t.Context())
	if err != nil || !m.Ready {
		t.Fatal("validated source metadata", m, err)
	}
	reader.Close()
	if err := admissionsql.BeginNamespaceRecovery(t.Context(), d.db.ownerDSN, binding, m.State, scope.State.Generation, true); err != nil {
		t.Fatal(err)
	}
	m, _ = admissionsql.ReadNamespaceOwnerMetadata(t.Context(), d.db.ownerDSN, binding)
	if _, err := d.db.owner.Exec(t.Context(), `UPDATE ops_history_namespace_v1.legacy_contract_lifetimes SET runtime_hash=$2 WHERE network_key=$1`, scope.Network[:], make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if err := admissionsql.FinalizeNamespaceRecovery(t.Context(), d.db.ownerDSN, binding, m.State, h.Digest{7}, true, true, 600); err == nil {
		t.Fatal("corrupt retained row became ready")
	}
	after, _ := admissionsql.ReadNamespaceOwnerMetadata(t.Context(), d.db.ownerDSN, binding)
	if after.SourceReady || after.State != m.State {
		t.Fatal("failed finalize changed persisted unready boundary")
	}
	originalHash := h.Hash{9}
	if _, err := d.db.owner.Exec(t.Context(), `UPDATE ops_history_namespace_v1.legacy_contract_lifetimes SET runtime_hash=$2 WHERE network_key=$1`, scope.Network[:], originalHash[:]); err != nil {
		t.Fatal(err)
	}
	if err := admissionsql.FinalizeNamespaceRecovery(t.Context(), d.db.ownerDSN, binding, m.State, h.Digest{7}, true, true, 600); err != nil {
		t.Fatal("restored original row", err)
	}
	m, _ = admissionsql.ReadNamespaceOwnerMetadata(t.Context(), d.db.ownerDSN, binding)
	newGeneration := uuid.NewString()
	if err := admissionsql.BeginRecovery(t.Context(), d.db.ownerDSN, binding, newGeneration); err != nil {
		t.Fatal(err)
	}
	if err := admissionsql.FinalizeRecovery(t.Context(), d.db.ownerDSN, binding, a.ExpectedState{Generation: newGeneration, Coverage: admissionsql.EmptyCoverage()}, true); err != nil {
		t.Fatal("actual old admission finalize", err)
	}
	if r, err := admissionsql.OpenNamespaceReader(t.Context(), readerDSN, binding, newGeneration, era); err == nil || r != nil {
		t.Fatal("old admission finalize certified namespace archive", err)
	}
	if err := admissionsql.BeginNamespaceRecovery(t.Context(), d.db.ownerDSN, binding, m.State, newGeneration, true); err != nil {
		t.Fatal("separate generation boundary", err)
	}
	m, _ = admissionsql.ReadNamespaceOwnerMetadata(t.Context(), d.db.ownerDSN, binding)
	if err := admissionsql.FinalizeNamespaceRecovery(t.Context(), d.db.ownerDSN, binding, m.State, h.Digest{8}, true, true, 600); err != nil {
		t.Fatal("separate archive validation", err)
	}
	reader, err = admissionsql.OpenNamespaceReader(t.Context(), readerDSN, binding, newGeneration, era)
	if err != nil {
		t.Fatal(err)
	}
	reader.Close()
}

func TestNamespaceTransfersActualPostgresOldParentAndRestoreClosure(t *testing.T) {
	d, _ := namespaceDBSetup(t)
	binding, scope := creationScope(t, d.db)
	era := h.ModelEra{EntryNumber: 100, EntryHash: h.Hash{1}, EntryTimestamp: 1000, EndTimestampExclusive: 2000}
	if err := admissionsql.BootstrapNamespace(t.Context(), d.db.ownerDSN, binding, scope.State.Generation, era, h.DefaultCapacityLimits(), true, true); err != nil {
		t.Fatal(err)
	}
	m, _ := admissionsql.ReadNamespaceOwnerMetadata(t.Context(), d.db.ownerDSN, binding)
	path, pin := namespaceArtifactFile(t, binding, era, uuid.NewString(), namespaceFinite(0x20))
	original, err := admissionsql.ImportNamespace(t.Context(), d.db.ownerDSN, binding, m.State, path, pin, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	initial := map[string]any{"kind": "org", "organizationId": "12345678-1234-4234-8234-123456789abc"}
	public := map[string]any{"kind": "public"}
	nextOrg := map[string]any{"kind": "org", "organizationId": "12345678-1234-4234-8234-123456789abd"}
	first := map[string]any{"kind": "transfer", "address": h.Address{0x20}.String(), "segmentKind": "prague", "segment": original.LifetimeSegments[0].String(), "initial": initial, "previous": initial, "new": public, "effectiveFrom": h.Cut{Number: 120, Hash: h.Hash{3}, Index: 0}}
	path, pin = namespaceArtifactFile(t, binding, era, uuid.NewString(), first)
	parent, err := admissionsql.ImportNamespace(t.Context(), d.db.ownerDSN, binding, original.State, path, pin, nil, true)
	if err != nil || len(parent.TransferIDs) != 1 {
		t.Fatal("new transfer referencing old basis", parent, err)
	}
	child := map[string]any{"kind": "transfer", "address": h.Address{0x20}.String(), "segmentKind": "prague", "segment": original.LifetimeSegments[0].String(), "initial": initial, "parent": parent.TransferIDs[0].String(), "previous": public, "new": nextOrg, "effectiveFrom": h.Cut{Number: 130, Hash: h.Hash{4}, Index: 1}}
	path, pin = namespaceArtifactFile(t, binding, era, uuid.NewString(), child)
	last, err := admissionsql.ImportNamespace(t.Context(), d.db.ownerDSN, binding, parent.State, path, pin, nil, true)
	if err != nil {
		t.Fatal("new transfer referencing old parent", err)
	}
	child["previous"], child["effectiveFrom"] = initial, h.Cut{Number: 140, Hash: h.Hash{5}, Index: 0}
	path, pin = namespaceArtifactFile(t, binding, era, uuid.NewString(), child)
	if _, err := admissionsql.ImportNamespace(t.Context(), d.db.ownerDSN, binding, last.State, path, pin, nil, true); !errors.Is(err, h.ErrConflict) {
		t.Fatal("broken previous label accepted", err)
	}
	if err := admissionsql.FinalizeNamespaceRecovery(t.Context(), d.db.ownerDSN, binding, last.State, h.Digest{7}, true, true, 600); err != nil {
		t.Fatal("complete parent/initial archive closure", err)
	}
}

func TestNamespaceReaderActualPostgresEffectiveACLFailures(t *testing.T) {
	d, readerDSN := namespaceDBSetup(t)
	binding, scope := creationScope(t, d.db)
	era := h.ModelEra{EntryNumber: 100, EntryHash: h.Hash{1}, EntryTimestamp: 1000, EndTimestampExclusive: 2000}
	if err := admissionsql.BootstrapNamespace(t.Context(), d.db.ownerDSN, binding, scope.State.Generation, era, h.DefaultCapacityLimits(), true, true); err != nil {
		t.Fatal(err)
	}
	m, _ := admissionsql.ReadNamespaceOwnerMetadata(t.Context(), d.db.ownerDSN, binding)
	if err := admissionsql.FinalizeNamespaceRecovery(t.Context(), d.db.ownerDSN, binding, m.State, h.Digest{7}, true, true, 600); err != nil {
		t.Fatal(err)
	}
	if _, err := d.db.owner.Exec(t.Context(), `CREATE SCHEMA unrelated_empty`); err != nil {
		t.Fatal(err)
	}
	// Ordinary database TEMP remains usable without granting persistent DDL.
	temporary, err := pgx.Connect(t.Context(), readerDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer temporary.Close(t.Context())
	if _, err := temporary.Exec(t.Context(), `CREATE TEMP TABLE namespace_temp_control(payload text);INSERT INTO namespace_temp_control VALUES(repeat('x',10000))`); err != nil {
		t.Fatal("normal TEMP topology", err)
	}
	for _, mutation := range []struct{ name, apply, undo string }{
		{"PUBLIC", `GRANT SELECT ON ops_history_namespace_v1.legacy_contract_lifetimes TO PUBLIC`, `REVOKE SELECT ON ops_history_namespace_v1.legacy_contract_lifetimes FROM PUBLIC`},
		{"column write", `GRANT UPDATE(ready)ON ops_history_namespace_v1.namespace_network_state TO namespace_reader`, `REVOKE UPDATE(ready)ON ops_history_namespace_v1.namespace_network_state FROM namespace_reader`},
		{"inherited writer", `GRANT admission_app TO namespace_reader`, `REVOKE admission_app FROM namespace_reader`},
		{"RLS", `ALTER TABLE ops_history_namespace_v1.namespace_cohorts ENABLE ROW LEVEL SECURITY`, `ALTER TABLE ops_history_namespace_v1.namespace_cohorts DISABLE ROW LEVEL SECURITY`},
		{"unrelated schema CREATE", `GRANT CREATE ON SCHEMA unrelated_empty TO namespace_reader`, `REVOKE CREATE ON SCHEMA unrelated_empty FROM namespace_reader`},
		{"PUBLIC unrelated schema CREATE", `GRANT CREATE ON SCHEMA unrelated_empty TO PUBLIC`, `REVOKE CREATE ON SCHEMA unrelated_empty FROM PUBLIC`},
		{"database CREATE", `GRANT CREATE ON DATABASE admission_test TO namespace_reader`, `REVOKE CREATE ON DATABASE admission_test FROM namespace_reader`},
		{"PUBLIC database CREATE", `GRANT CREATE ON DATABASE admission_test TO PUBLIC`, `REVOKE CREATE ON DATABASE admission_test FROM PUBLIC`},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			if _, err := d.db.owner.Exec(t.Context(), mutation.apply); err != nil {
				t.Fatal(err)
			}
			reader, err := admissionsql.OpenNamespaceReader(t.Context(), readerDSN, binding, scope.State.Generation, era)
			if reader != nil {
				reader.Close()
			}
			if err == nil {
				t.Fatal("unsafe reader startup accepted")
			}
			if _, err := d.db.owner.Exec(t.Context(), mutation.undo); err != nil {
				t.Fatal(err)
			}
			reader, err = admissionsql.OpenNamespaceReader(t.Context(), readerDSN, binding, scope.State.Generation, era)
			if err != nil {
				t.Fatal("restored exact role/schema", err)
			}
			reader.Close()
		})
	}
}

func TestNamespaceImportActualPostgresCancellationRollsBackCohort(t *testing.T) {
	d, _ := namespaceDBSetup(t)
	binding, scope := creationScope(t, d.db)
	era := h.ModelEra{EntryNumber: 100, EntryHash: h.Hash{1}, EntryTimestamp: 1000, EndTimestampExclusive: 2000}
	if err := admissionsql.BootstrapNamespace(t.Context(), d.db.ownerDSN, binding, scope.State.Generation, era, h.DefaultCapacityLimits(), true, true); err != nil {
		t.Fatal(err)
	}
	m, _ := admissionsql.ReadNamespaceOwnerMetadata(t.Context(), d.db.ownerDSN, binding)
	path, pin := namespaceArtifactFile(t, binding, era, uuid.NewString(), namespaceFinite(0x20))
	blocker, err := pgx.Connect(t.Context(), d.db.ownerDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close(t.Context())
	blocked, err := blocker.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Rollback(t.Context())
	if _, err := blocked.Exec(t.Context(), `LOCK TABLE ops_history_namespace_v1.legacy_contract_lifetimes IN SHARE MODE`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := admissionsql.ImportNamespace(ctx, d.db.ownerDSN, binding, m.State, path, pin, nil, true)
		done <- err
	}()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	waiting := false
	for !waiting {
		if d.db.owner.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE relation='ops_history_namespace_v1.legacy_contract_lifetimes'::regclass AND mode='RowExclusiveLock' AND NOT granted)`).Scan(&waiting) != nil {
			t.Fatal("inspect actual insert lock")
		}
		if waiting {
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("import did not reach blocked lifetime insert")
		case <-tick.C:
		}
	}
	// The awaited relation lock proves the preceding cohort INSERT executed
	// inside the transaction. Cancellation, not a sleep, orders the fault.
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled import committed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled import did not release its transaction")
	}
	if err := blocked.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	var count int
	if d.db.owner.QueryRow(t.Context(), `SELECT count(*)FROM ops_history_namespace_v1.namespace_cohorts WHERE network_key=$1`, scope.Network[:]).Scan(&count) != nil || count != 0 {
		t.Fatal("cancelled import left a cohort")
	}
	current, _ := admissionsql.ReadNamespaceOwnerMetadata(t.Context(), d.db.ownerDSN, binding)
	if current.State != m.State {
		t.Fatal("cancelled import advanced revision")
	}
	if _, err := admissionsql.ImportNamespace(t.Context(), d.db.ownerDSN, binding, m.State, path, pin, nil, true); err != nil {
		t.Fatal("exact retry after rollback failed", err)
	}
}

func TestNamespaceImportActualPostgresMaximumCohort(t *testing.T) {
	d, _ := namespaceDBSetup(t)
	binding, scope := creationScope(t, d.db)
	era := h.ModelEra{EntryNumber: 100, EntryHash: h.Hash{1}, EntryTimestamp: 1000, EndTimestampExclusive: 2000}
	if err := admissionsql.BootstrapNamespace(t.Context(), d.db.ownerDSN, binding, scope.State.Generation, era, h.DefaultCapacityLimits(), true, true); err != nil {
		t.Fatal(err)
	}
	statements := make([]any, h.MaxStatements)
	for i := range statements {
		value := namespaceFinite(0x20)
		address := h.Address{0x20}
		address[18], address[19] = byte(i>>8), byte(i)
		value["address"] = address.String()
		statements[i] = value
	}
	path, pin := namespaceArtifactFile(t, binding, era, uuid.NewString(), statements...)
	m, _ := admissionsql.ReadNamespaceOwnerMetadata(t.Context(), d.db.ownerDSN, binding)
	imported, err := admissionsql.ImportNamespace(t.Context(), d.db.ownerDSN, binding, m.State, path, pin, nil, true)
	if err != nil || len(imported.LifetimeIDs) != h.MaxStatements {
		t.Fatal("maximum bounded cohort", len(imported.LifetimeIDs), err)
	}
	if err := admissionsql.FinalizeNamespaceRecovery(t.Context(), d.db.ownerDSN, binding, imported.State, h.Digest{7}, true, true, 600); err != nil {
		t.Fatal("maximum cohort bounded archive validation", err)
	}
	tooMany, tooManyPin := namespaceArtifactFile(t, binding, era, uuid.NewString(), append(statements, namespaceFinite(0x21))...)
	if _, err := admissionsql.ImportNamespace(t.Context(), d.db.ownerDSN, binding, imported.State, tooMany, tooManyPin, nil, true); err == nil {
		t.Fatal("one-over statement limit reached storage")
	}
}

func TestNamespacePreEraActualPostgresBasisAndCounterRecovery(t *testing.T) {
	d, _ := namespaceDBSetup(t)
	binding, scope := creationScope(t, d.db)
	era := h.ModelEra{EntryNumber: 100, EntryHash: h.Hash{1}, EntryTimestamp: 1000, EndTimestampExclusive: 2000}
	if err := admissionsql.BootstrapNamespace(t.Context(), d.db.ownerDSN, binding, scope.State.Generation, era, h.DefaultCapacityLimits(), true, true); err != nil {
		t.Fatal(err)
	}
	m, _ := admissionsql.ReadNamespaceOwnerMetadata(t.Context(), d.db.ownerDSN, binding)
	finite := namespaceFinite(0x20)
	finite["kind"], finite["lifetimeId"] = "pre-era-finite", uuid.NewString()
	finite["start"], finite["end"] = h.Cut{Number: 90, Hash: h.Hash{7}, Index: 0}, h.Cut{Number: 100, Hash: h.Hash{1}, Index: 0}
	delete(finite, "physical")
	path, pin := namespaceArtifactFile(t, binding, era, uuid.NewString(), finite)
	original, err := admissionsql.ImportNamespace(t.Context(), d.db.ownerDSN, binding, m.State, path, pin, nil, true)
	if err != nil {
		t.Fatal("pre-era physical row", err)
	}
	initial := map[string]any{"kind": "org", "organizationId": "12345678-1234-4234-8234-123456789abc"}
	transfer := map[string]any{"kind": "transfer", "address": h.Address{0x20}.String(), "segmentKind": "legacy", "segment": original.LifetimeSegments[0].String(), "legacyBasis": original.LifetimeIDs[0].String(), "initial": initial, "previous": initial, "new": map[string]any{"kind": "public"}, "effectiveFrom": h.Cut{Number: 95, Hash: h.Hash{8}, Index: 0}}
	path, pin = namespaceArtifactFile(t, binding, era, uuid.NewString(), transfer)
	imported, err := admissionsql.ImportNamespace(t.Context(), d.db.ownerDSN, binding, original.State, path, pin, nil, true)
	if err != nil {
		t.Fatal("actual pre-era original basis FK", err)
	}
	if err := admissionsql.FinalizeNamespaceRecovery(t.Context(), d.db.ownerDSN, binding, imported.State, h.Digest{7}, true, true, 600); err != nil {
		t.Fatal("pre-era archive closure", err)
	}
	m, _ = admissionsql.ReadNamespaceOwnerMetadata(t.Context(), d.db.ownerDSN, binding)
	if err := admissionsql.BeginNamespaceRecovery(t.Context(), d.db.ownerDSN, binding, m.State, scope.State.Generation, true); err != nil {
		t.Fatal(err)
	}
	m, _ = admissionsql.ReadNamespaceOwnerMetadata(t.Context(), d.db.ownerDSN, binding)
	if _, err := d.db.owner.Exec(t.Context(), `UPDATE ops_history_namespace_v1.namespace_network_state SET lifetime_count=lifetime_count+1 WHERE network_key=$1`, scope.Network[:]); err != nil {
		t.Fatal(err)
	}
	if err := admissionsql.FinalizeNamespaceRecovery(t.Context(), d.db.ownerDSN, binding, m.State, h.Digest{7}, true, true, 600); err == nil {
		t.Fatal("incorrect capacity count certified")
	}
	after, _ := admissionsql.ReadNamespaceOwnerMetadata(t.Context(), d.db.ownerDSN, binding)
	if after.SourceReady || after.State != m.State {
		t.Fatal("counter fault changed unready boundary")
	}
}

func TestNamespaceSchemaActualPostgresRoleAndBootstrapBoundary(t *testing.T) {
	d, readerDSN := namespaceDBSetup(t)
	if err := admissionsql.MigrateNamespace(t.Context(), d.db.ownerDSN, "namespace_reader", true); err != nil {
		t.Fatal("idempotent migration", err)
	}
	for _, role := range []string{"admission_app", "creation_observer", "creation_facts"} {
		if err := admissionsql.MigrateNamespace(t.Context(), d.db.ownerDSN, role, true); err == nil {
			t.Fatal("existing operational role was upgraded", role)
		}
	}
	old, err := admissionsql.OpenCreationFacts(t.Context(), d.factsDSN)
	if err != nil {
		t.Fatal("old facts role/constructor changed", err)
	}
	old.Close()
	reader, err := pgx.Connect(t.Context(), readerDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close(t.Context())
	for _, query := range []string{
		`SELECT count(*)FROM ops_history_namespace_v1.legacy_contract_lifetimes`,
		`SELECT count(*)FROM ops_admission_v2.creation_births`,
	} {
		var count int
		if err := reader.QueryRow(t.Context(), query).Scan(&count); err != nil {
			t.Fatal("required exact reader grant missing", err)
		}
	}
	for _, query := range []string{
		`SELECT * FROM public.users`, `SELECT * FROM ops_admission_v2.travel_records`,
		`UPDATE ops_history_namespace_v1.namespace_network_state SET ready=true`,
		`UPDATE ops_admission_v2.creation_observer_state SET ready=true`,
		`TRUNCATE ops_history_namespace_v1.namespace_cohorts`,
	} {
		if _, err := reader.Exec(t.Context(), query); err == nil {
			t.Fatal("reader has excess privilege", query)
		}
	}
	binding, scope := creationScope(t, d.db)
	era := h.ModelEra{EntryNumber: 100, EntryHash: h.Hash{1}, EntryTimestamp: 1000, EndTimestampExclusive: 2000}
	if err := admissionsql.BootstrapNamespace(t.Context(), d.db.ownerDSN, binding, scope.State.Generation, era, h.DefaultCapacityLimits(), true, false); !errors.Is(err, h.ErrInvalid) {
		t.Fatal("missing never-initialized attestation accepted", err)
	}
	if err := admissionsql.BootstrapNamespace(t.Context(), d.db.ownerDSN, binding, scope.State.Generation, era, h.DefaultCapacityLimits(), true, true); err != nil {
		t.Fatal("fresh source bootstrap", err)
	}
	m, err := admissionsql.ReadNamespaceOwnerMetadata(t.Context(), d.db.ownerDSN, binding)
	if err != nil || m.Ready || m.SourceReady || !m.BaseReady || m.State.Revision != 1 {
		t.Fatal("fresh source looked ready", m, err)
	}
	if r, err := admissionsql.OpenNamespaceReader(t.Context(), readerDSN, binding, scope.State.Generation, era); err == nil || r != nil {
		t.Fatal("unvalidated source opened", err)
	}
	if err := admissionsql.BootstrapNamespace(t.Context(), d.db.ownerDSN, binding, scope.State.Generation, era, h.DefaultCapacityLimits(), true, true); !errors.Is(err, h.ErrConflict) {
		t.Fatal("existing source was re-bootstrapped", err)
	}
	if err := admissionsql.BeginNamespaceRecovery(t.Context(), d.db.ownerDSN, binding, m.State, uuid.NewString(), true); !errors.Is(err, h.ErrConflict) {
		t.Fatal("wrong base generation accepted", err)
	}
}
