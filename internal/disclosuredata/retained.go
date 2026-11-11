package disclosuredata

import (
	"context"
	"math"
	"slices"
	"strconv"
	"strings"

	p "privacy-proxy/internal/disclosurepolicy"
)

const RetainedSourceProfile = "ops.disclosure.retained-data-sources/v1"
const RetainedHistoryPopulation = "RETAINED_AND_POSITIVELY_ATTRIBUTED_WALLET_HISTORY"
const SealedRequestPopulation = "SEALED_REQUEST_COMPLETIONS_AS_OF_CHAIN_HEAD"

// RetainedSources is a separately selected operational assembly. Its original
// anchor cannot be reconstructed from an opaque SourceRef digest. A nil basis
// starts a read; a continuation supplies the authenticated original selection.
// Sources must independently qualify it against the selected actual node.
type RetainedSources interface {
	Plan() SourcePlan
	OpenRetained(context.Context, ReadScope, []SourceRef, *RetainedBasis, *Position) (RetainedSnapshot, error)
}

type RetainedSnapshot interface {
	Snapshot
	Basis() RetainedBasis
}

type RetainedAnchor struct {
	Number       Count   `json:"number"`
	Hash         string  `json:"hash"`
	ParentHash   string  `json:"parentHash"`
	Timestamp    Count   `json:"timestamp"`
	Transactions *uint32 `json:"transactions,omitempty"`
}

// RetainedBasis is bounded selection metadata, not a ROOT, permission, restore
// marker or completeness certificate. A real count may be supplied only by an
// actual qualified block acquisition. The source rechecks canonical identity.
type RetainedBasis struct {
	Version         uint8          `json:"v"`
	NetworkKey      Digest         `json:"network"`
	NodeSource      Digest         `json:"node"`
	IndexSource     Digest         `json:"index"`
	Schema          Digest         `json:"schema"`
	ConfiguredEpoch string         `json:"epoch"`
	Upper           RetainedAnchor `json:"upper"`
}

func canonicalHash(s string) bool {
	if len(s) != 66 || !strings.HasPrefix(s, "0x") {
		return false
	}
	for _, c := range s[2:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func (b RetainedBasis) Valid() bool {
	if b.Version != 1 || !digestValid(b.NetworkKey) || !digestValid(b.NodeSource) || !digestValid(b.IndexSource) || !digestValid(b.Schema) || len(b.ConfiguredEpoch) != 36 || !uuidValid(b.ConfiguredEpoch) || !canonicalHash(b.Upper.Hash) || b.Upper.Hash == "0x"+strings.Repeat("0", 64) || !canonicalHash(b.Upper.ParentHash) || len(b.Upper.Number) > 19 || len(b.Upper.Timestamp) > 12 {
		return false
	}
	number, err := strconv.ParseUint(string(b.Upper.Number), 10, 63)
	if err != nil || strconv.FormatUint(number, 10) != string(b.Upper.Number) || number > math.MaxInt64 {
		return false
	}
	timestamp, err := strconv.ParseUint(string(b.Upper.Timestamp), 10, 64)
	return err == nil && strconv.FormatUint(timestamp, 10) == string(b.Upper.Timestamp) && timestamp <= uint64(p.MaxUnixSeconds)
}

func (b RetainedBasis) Clone() RetainedBasis {
	if b.Upper.Transactions != nil {
		count := *b.Upper.Transactions
		b.Upper.Transactions = &count
	}
	return b
}

func (b RetainedBasis) Equal(other RetainedBasis) bool {
	left, right := b.Upper.Transactions, other.Upper.Transactions
	b.Upper.Transactions, other.Upper.Transactions = nil, nil
	return b == other && (left == nil && right == nil || left != nil && right != nil && *left == *right)
}

// Immutable-only resources have no indexed history anchor. This is a closed
// resource choice, not a permission to omit an anchor for retained history.
func BasisForResource(resource p.Resource, b RetainedBasis) error {
	kinds, err := RequiredKinds(resource)
	if err != nil {
		return err
	}
	if slices.Contains(kinds, HistorySource) {
		if !b.Valid() {
			return ErrInvalid
		}
	} else if b != (RetainedBasis{}) {
		return ErrInvalid
	}
	return nil
}

func ValidRetainedPlan(plan SourcePlan) bool {
	if plan.Version != 2 || plan.Profile != RetainedSourceProfile || !digestValid(plan.BundleDigest) || !digestValid(plan.NetworkKey) || !digestValid(plan.PlanDigest) || len(plan.Resources) < 1 || len(plan.Resources) > 6 {
		return false
	}
	for i, resource := range plan.Resources {
		if _, err := RequiredKinds(resource); err != nil || i > 0 && plan.Resources[i-1] >= resource {
			return false
		}
	}
	return true
}

func retainedPopulation(kind SourceKind) (uint8, string) {
	switch kind {
	case HistorySource:
		return 2, RetainedHistoryPopulation
	case ActivitySource:
		return 2, SealedRequestPopulation
	default:
		return 1, population(kind)
	}
}

// SourceReferencesRetained accepts only the explicitly selected per-kind
// versions/populations. The original SourceReferences remains Version1-only.
func SourceReferencesRetained(plan SourcePlan, descriptors []SourceDescriptor) ([]SourceRef, error) {
	if !ValidRetainedPlan(plan) || len(descriptors) < 1 || len(descriptors) > 5 {
		return nil, ErrUnavailable
	}
	refs := make([]SourceRef, 0, len(descriptors))
	for i, d := range descriptors {
		version, population := retainedPopulation(d.Kind)
		if population == "" || d.Version != version || d.Population != population || d.NetworkKey != plan.NetworkKey || d.PlanDigest != plan.PlanDigest || !digestValid(d.Reference) || !digestValid(d.Epoch) || !digestValid(d.FormatDigest) || !digestValid(d.CoverageDigest) || !uuidValid(d.Generation) || !utc(d.AsOf) || i > 0 && descriptors[i-1].Kind >= d.Kind {
			return nil, ErrUnavailable
		}
		refs = append(refs, SourceRef{d.Kind, d.Reference})
	}
	return refs, nil
}

func SourceSetDigestRetained(plan SourcePlan, descriptors []SourceDescriptor, resource p.Resource, view View) (Digest, error) {
	refs, err := SourceReferencesRetained(plan, descriptors)
	if err != nil {
		return "", err
	}
	if !slices.Contains(plan.Resources, resource) {
		return "", ErrUnsupported
	}
	return sourceSetDigest(descriptors, resource, view, refs, 2, "ops.disclosure.source-set/v2")
}

func ValidateFactsRetained(plan SourcePlan, scope ReadScope, descriptors []SourceDescriptor, facts Facts, after *Position) error {
	if scope.BundleDigest != plan.BundleDigest {
		return ErrUnavailable
	}
	if _, err := SourceSetDigestRetained(plan, descriptors, scope.Query.Resource(), scope.Query.View()); err != nil {
		return err
	}
	_, err := validateFactsForHistory(scope, descriptors, facts, after, RetainedHistoryPopulation)
	return err
}
