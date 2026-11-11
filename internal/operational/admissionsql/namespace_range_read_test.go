package admissionsql_test

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	h "privacy-proxy/internal/historynamespace"
	"privacy-proxy/internal/operational/admissionsql"
)

func TestNamespaceRangesActualPostgresPurposeRecoveryAndCommitBudget(t *testing.T) {
	d, dsn := namespaceDBSetup(t)
	binding, base := creationScope(t, d.db)
	era := h.ModelEra{EntryNumber: 100, EntryHash: h.Hash{1}, EntryTimestamp: 1000, EndTimestampExclusive: 2000}
	if err := admissionsql.BootstrapNamespace(t.Context(), d.db.ownerDSN, binding, base.State.Generation, era, h.DefaultCapacityLimits(), true, true); err != nil {
		t.Fatal(err)
	}
	metadata, err := admissionsql.ReadNamespaceOwnerMetadata(t.Context(), d.db.ownerDSN, binding)
	if err != nil {
		t.Fatal(err)
	}
	cohort := uuid.NewString()
	path, pin := namespaceArtifactFile(t, binding, era, cohort, namespaceFinite(0x20))
	imported, err := admissionsql.ImportNamespace(t.Context(), d.db.ownerDSN, binding, metadata.State, path, pin, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := admissionsql.FinalizeNamespaceRecovery(t.Context(), d.db.ownerDSN, binding, imported.State, h.Digest{7}, true, true, 600); err != nil {
		t.Fatal(err)
	}
	first, err := admissionsql.OpenNamespaceReader(t.Context(), dsn, binding, base.State.Generation, era)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := admissionsql.OpenNamespaceReader(t.Context(), dsn, binding, base.State.Generation, era)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	point, blocks := namespaceReadScope(binding, era)
	input := h.TrustedRangeScope{Network: point.Network, Era: era, CanonicalViewID: point.CanonicalViewID, Head: point.Head,
		FromNumber: 100, ThroughNumber: 120, Addresses: []h.Address{{0x20}}}
	req, err := first.DiscoverRangeRequirements(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	pass := h.TrustedRangePass{Scope: input, CanonicalBlocks: blocks, ExpectedScopeDigest: req.ScopeDigest(), ExpectedRequirementsDigest: req.Digest()}
	t.Run("two-real-reader-pools", func(t *testing.T) {
		out, err := second.ResolveRangePass(t.Context(), pass)
		if err != nil || out == nil || len(out.Intervals()) != 1 || out.Intervals()[0].Kind != h.KnownOrg || *out.Intervals()[0].OrganizationID != "12345678-1234-4234-8234-123456789abc" {
			t.Fatalf("actual range result: %v %+v", err, out)
		}
		again, err := first.ResolveRangePass(t.Context(), pass)
		if err != nil || again.AuthorityDigest() != out.AuthorityDigest() {
			t.Fatal("same source purpose changed across pools", err)
		}
	})
	t.Run("known-commit-command-slot", func(t *testing.T) {
		limits := h.DefaultReadLimits()
		limits.MaxQueries = 8
		limited, err := admissionsql.OpenNamespaceReaderWithLimits(t.Context(), dsn, binding, base.State.Generation, era, limits)
		if err != nil {
			t.Fatal(err)
		}
		defer limited.Close()
		if out, err := limited.DiscoverRangeRequirements(t.Context(), input); !errors.Is(err, h.ErrTooBroad) || out != nil {
			t.Fatal("range reset SQL/commit budget", err)
		}
	})
	t.Run("drained-recovery-and-revocation", func(t *testing.T) {
		m, err := admissionsql.ReadNamespaceOwnerMetadata(t.Context(), d.db.ownerDSN, binding)
		if err != nil {
			t.Fatal(err)
		}
		if err := admissionsql.BeginNamespaceRecovery(t.Context(), d.db.ownerDSN, binding, m.State, base.State.Generation, true); err != nil {
			t.Fatal(err)
		}
		if out, err := second.ResolveRangePass(t.Context(), pass); !errors.Is(err, h.ErrUnavailable) || out != nil {
			t.Fatal("unready source returned prior positive", err)
		}
		m, err = admissionsql.ReadNamespaceOwnerMetadata(t.Context(), d.db.ownerDSN, binding)
		if err != nil {
			t.Fatal(err)
		}
		if err := admissionsql.RevokeNamespaceCohorts(t.Context(), d.db.ownerDSN, binding, m.State, []string{cohort}, "source-compromise", true); err != nil {
			t.Fatal(err)
		}
		m, err = admissionsql.ReadNamespaceOwnerMetadata(t.Context(), d.db.ownerDSN, binding)
		if err != nil {
			t.Fatal(err)
		}
		if err := admissionsql.FinalizeNamespaceRecovery(t.Context(), d.db.ownerDSN, binding, m.State, h.Digest{9}, true, true, 600); err != nil {
			t.Fatal(err)
		}
		if out, err := first.ResolveRangePass(t.Context(), pass); !errors.Is(err, h.ErrUnavailable) || out != nil {
			t.Fatal("restored/revoked source reused old requirements", err)
		}
		fresh, err := first.DiscoverRangeRequirements(t.Context(), input)
		if err != nil {
			t.Fatal(err)
		}
		pass.ExpectedScopeDigest, pass.ExpectedRequirementsDigest = fresh.ScopeDigest(), fresh.Digest()
		out, err := second.ResolveRangePass(t.Context(), pass)
		if err != nil || out == nil {
			t.Fatal("fresh revoked-source query", err)
		}
		for _, cell := range out.Intervals() {
			if cell.Kind != h.Unknown || cell.OrganizationID != nil {
				t.Fatal("revoked original still grants organization", cell)
			}
		}
	})
}
