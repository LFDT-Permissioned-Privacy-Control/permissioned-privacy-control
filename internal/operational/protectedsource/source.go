package protectedsource

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	f "privacy-proxy/internal/admissionsharedata"
	d "privacy-proxy/internal/disclosuredata"
	p "privacy-proxy/internal/disclosurepolicy"
	"privacy-proxy/internal/disclosurewallet"
	"privacy-proxy/internal/operational/activitysource"
	"privacy-proxy/internal/operational/admissionsql"
	x "privacy-proxy/internal/operational/explorerindex"
)

type snapshot struct {
	mu                 sync.Mutex
	owner              *Sources
	scope              d.ReadScope
	after              *d.Position
	basis              d.RetainedBasis
	fence              f.Fence
	descriptors        []d.SourceDescriptor
	facts              d.Facts
	qualifiedAddresses []d.AddressFact
	wallet             *disclosurewallet.Snapshot
	finance            *admissionsql.FinanceSnapshot
	activity           *activitysource.RetainedPartSnapshot
	index              *x.ProtectedRead
	node               *nodeRead
	namespace          *namespaceRead
	read, closed       bool
}

func referenceMap(resource p.Resource, refs []d.SourceRef) (map[d.SourceKind]*d.SourceRef, error) {
	kinds, err := d.RequiredKinds(resource)
	if err != nil {
		return nil, err
	}
	if len(refs) != 0 && len(refs) != len(kinds) {
		return nil, d.ErrInvalid
	}
	out := map[d.SourceKind]*d.SourceRef{}
	for i, ref := range refs {
		if ref.Kind != kinds[i] || len(ref.ID) != 71 {
			return nil, d.ErrInvalid
		}
		raw, err := hex.DecodeString(string(ref.ID)[7:])
		if err != nil || len(raw) != 32 || "sha256:"+hex.EncodeToString(raw) != string(ref.ID) {
			return nil, d.ErrInvalid
		}
		copy := ref
		out[ref.Kind] = &copy
	}
	return out, nil
}

func equalPosition(a, b *d.Position) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	n, err := d.ComparePositions(*a, *b)
	return err == nil && n == 0
}
func sameRead(a, b d.ReadScope) bool {
	return a.Namespace == b.Namespace && a.CaseID == b.CaseID && a.CaseVersion == b.CaseVersion && a.RecipientActorID == b.RecipientActorID && a.DataOrganizationID == b.DataOrganizationID && a.BundleDigest == b.BundleDigest && a.RuleDigest == b.RuleDigest && a.EffectiveUntil.Equal(b.EffectiveUntil) && a.Query.Digest() == b.Query.Digest()
}
func indexError(err error) error {
	if errors.Is(err, x.ErrTooBroad) {
		return d.ErrTooBroad
	}
	if errors.Is(err, x.ErrConflict) {
		return d.ErrConflict
	}
	return d.ErrUnavailable
}

func (s *Sources) OpenRetained(ctx context.Context, scope d.ReadScope, refs []d.SourceRef, basis *d.RetainedBasis, after *d.Position) (d.RetainedSnapshot, error) {
	if s == nil || ctx == nil || scope.BundleDigest != s.plan.BundleDigest || !slices.Contains(s.plan.Resources, scope.Query.Resource()) || d.PositionForQuery(scope.Query, after) != nil || basis != nil && d.BasisForResource(scope.Query.Resource(), *basis) != nil {
		return nil, d.ErrInvalid
	}
	expected, err := referenceMap(scope.Query.Resource(), refs)
	if err != nil {
		return nil, err
	}
	fence, err := f.NewFence(ctx, 5*time.Second)
	if err != nil {
		return nil, d.ErrUnavailable
	}
	read := &snapshot{owner: s, scope: scope, after: d.ClonePosition(after), fence: fence, descriptors: []d.SourceDescriptor{}}
	complete := false
	defer func() {
		if !complete {
			read.Close()
		}
	}()
	kinds, _ := d.RequiredKinds(scope.Query.Resource())
	if slices.Contains(kinds, d.ActivitySource) {
		read.activity, err = s.activity.Open(ctx, scope, expected[d.ActivitySource], d.ClonePosition(after))
		if err != nil {
			return nil, err
		}
		read.descriptors = append(read.descriptors, read.activity.Descriptor())
		read.facts, err = read.activity.Facts()
		if err != nil {
			return nil, err
		}
	}
	if slices.Contains(kinds, d.WalletSource) {
		read.wallet, err = s.wallet.Open(ctx, scope, expected[d.WalletSource])
		if err != nil {
			return nil, err
		}
		read.descriptors = append(read.descriptors, read.wallet.Descriptor())
		read.facts.Wallets = read.wallet.Wallets()
	}
	if slices.Contains(kinds, d.FinanceSource) {
		read.finance, err = s.finance.Open(ctx, scope, expected[d.FinanceSource])
		if err != nil {
			return nil, err
		}
		read.descriptors = append(read.descriptors, read.finance.Descriptor())
	}
	if slices.Contains(kinds, d.HistorySource) {
		if err = read.openHistory(ctx, basis, expected[d.HistorySource]); err != nil {
			return nil, err
		}
	} else if basis != nil && !basis.Equal(d.RetainedBasis{}) {
		return nil, d.ErrInvalid
	}
	if slices.Contains(kinds, d.SanctionsSource) {
		if err = read.projectSanctions(ctx); err != nil {
			return nil, err
		}
	}
	slices.SortFunc(read.descriptors, func(a, b d.SourceDescriptor) int {
		if a.Kind < b.Kind {
			return -1
		}
		if a.Kind > b.Kind {
			return 1
		}
		return 0
	})
	actual, err := d.SourceReferencesRetained(s.plan, read.descriptors)
	if err != nil {
		return nil, err
	}
	if len(refs) > 0 && !slices.Equal(actual, refs) {
		return nil, d.ErrConflict
	}
	if err = d.ValidateFactsRetained(s.plan, scope, read.descriptors, read.facts, after); err != nil {
		return nil, err
	}
	if fence.Check() != nil {
		return nil, d.ErrUnavailable
	}
	complete = true
	return read, nil
}

func (read *snapshot) openHistory(ctx context.Context, original *d.RetainedBasis, expected *d.SourceRef) error {
	s := read.owner
	config, ok := s.nodes[read.scope.DataOrganizationID]
	if !ok {
		return d.ErrUnavailable
	}
	node, err := newNodeRead(config)
	if err != nil {
		return err
	}
	read.node = node
	upper, err := node.upper(ctx, original)
	if err != nil {
		return err
	}
	metadata := s.index.Metadata()
	if metadata != s.indexMetadata {
		return d.ErrConflict
	}
	read.basis = d.RetainedBasis{Version: 1, NetworkKey: s.plan.NetworkKey, NodeSource: d.Digest(config.Source.Digest().String()), IndexSource: digestArray(metadata.Binding.SourceReference), Schema: digestArray(metadata.Binding.SchemaDigest), ConfiguredEpoch: metadata.Binding.ConfiguredEpoch, Upper: d.RetainedAnchor{Number: d.Count(strconv.FormatUint(upper.Number, 10)), Hash: upper.Hash.String(), ParentHash: upper.ParentHash.String(), Timestamp: d.Count(strconv.FormatUint(upper.Timestamp, 10))}}
	if !read.basis.Valid() {
		return d.ErrUnavailable
	}
	if original != nil && !read.basis.Equal(*original) {
		return d.ErrConflict
	}
	targets, actors, err := targetWallets(read.scope, read.facts.Wallets)
	if err != nil {
		return err
	}
	var selectedAddress *[20]byte
	if read.scope.Query.Resource() == p.Transactions && read.scope.Query.View() == d.List && read.scope.Query.AddressID() != "" {
		address, err := d.ResolveAddressLocator(d.RenderContext{PreparedAt: s.now(), Namespace: read.scope.Namespace, CaseID: read.scope.CaseID, DataOrganizationID: read.scope.DataOrganizationID, RecipientActorID: read.scope.RecipientActorID, Keys: s.render, Query: read.scope.Query, EffectiveUntil: read.scope.EffectiveUntil}, read.scope.Query.AddressID(), targets)
		if err != nil {
			return err
		}
		selectedAddress = &address
		targets = [][20]byte{address}
	}
	qscope := read.scope.Query.Scope()
	index, err := s.index.BeginProtected(ctx, x.ProtectedSelection{Expected: s.indexMetadata, Targets: targets, FromTime: uint64(qscope.DataTime.Start), ThroughTime: uint64(qscope.DataTime.End), FromNumber: s.namespaceMetadata.Era.EntryNumber, ThroughNumber: upper.Number})
	if err != nil {
		return indexError(err)
	}
	read.index = index
	destinations, err := index.ReadDestinations(ctx)
	if err != nil {
		return indexError(err)
	}
	namespace, err := newNamespaceRead(ctx, s.namespace, node, upper, destinations)
	if err != nil {
		return err
	}
	read.namespace = namespace
	predicate, err := namespace.predicate(read.scope.DataOrganizationID)
	if err != nil {
		return err
	}
	ref := digestParts("ops.disclosure.retained-history-basis/v1", read.scope.Namespace, read.scope.CaseID, read.scope.CaseVersion, read.scope.RecipientActorID, read.scope.DataOrganizationID, read.scope.RuleDigest, read.scope.Query.Digest(), read.basis, read.wallet.Descriptor().Reference, namespace.rangePass.AuthorityDigest(), namespace.rangePass.RequirementsDigest(), destinations)
	if expected != nil && expected.ID != ref {
		return d.ErrConflict
	}
	epoch := digestParts("ops.disclosure.retained-history-epoch/v1", read.basis.NetworkKey, read.basis.NodeSource, read.basis.IndexSource, read.basis.Schema, read.basis.ConfiguredEpoch)
	descriptor := d.SourceDescriptor{Version: 2, Kind: d.HistorySource, Reference: ref, NetworkKey: s.plan.NetworkKey, Epoch: epoch, Generation: namespace.rangePass.Generation(), PlanDigest: s.plan.PlanDigest, FormatDigest: digestParts("ops.disclosure.retained-history-format/v1"), CoverageDigest: d.Digest(namespace.rangePass.AuthorityDigest().String()), AsOf: s.now(), Population: d.RetainedHistoryPopulation}
	read.descriptors = append(read.descriptors, descriptor)
	if read.scope.Query.Resource() == p.Transactions {
		query := x.ProtectedTransactionQuery{Limit: read.scope.Query.Limit(), Address: selectedAddress}
		if read.after != nil {
			position := read.after.Transaction
			number, _ := strconv.ParseUint(string(position.BlockNumber), 10, 63)
			query.After = &x.ProtectedPosition{Number: number, Index: position.TransactionIndex, Hash: position.Hash}
		}
		full := read.scope.Query.View() == d.Detail
		if full {
			query.Limit = 1
			hash, err := hex.DecodeString(read.scope.Query.TransactionHash()[2:])
			if err != nil || len(hash) != 32 {
				return d.ErrInvalid
			}
			var value [32]byte
			copy(value[:], hash)
			query.Hash = &value
		}
		witnessRows := []x.ProtectedRow{}
		if selectedAddress != nil {
			witnesses, err := index.ReadWitnesses(ctx, predicate)
			if err != nil {
				return indexError(err)
			}
			if len(witnesses) != 1 || witnesses[0].Address != *selectedAddress {
				return d.ErrNotFound
			}
			witnessRows = append(witnessRows, witnesses[0].Row)
		}
		rows, end, err := index.ReadTransactions(ctx, predicate, query)
		if err != nil {
			return indexError(err)
		}
		if full && len(rows) == 0 {
			return d.ErrNotFound
		}
		allRows := append(witnessRows, rows...)
		qualified, err := node.qualify(ctx, allRows, full)
		if err != nil {
			return err
		}
		if err = namespace.qualify(ctx, qualified, read.scope.DataOrganizationID); err != nil {
			return err
		}
		if selectedAddress != nil {
			witness := qualified[0].fact
			if witness.From != *selectedAddress && (witness.To == nil || *witness.To != *selectedAddress) {
				return d.ErrUnavailable
			}
		}
		read.facts.Transactions = []d.TransactionFact{}
		read.facts.End = end
		for _, root := range qualified[len(witnessRows):] {
			fact, err := transactionFact(read.scope, ref, actors, root.fact)
			if err != nil {
				return err
			}
			read.facts.Transactions = append(read.facts.Transactions, fact)
		}
		if !end {
			last := rows[len(rows)-1]
			read.facts.Next = &d.Position{Kind: d.HistorySource, Transaction: &d.TransactionPosition{BlockNumber: d.Count(strconv.FormatUint(last.Position.Number, 10)), TransactionIndex: last.Position.Index, Hash: last.Position.Hash}}
		}
	} else {
		witnesses, err := index.ReadWitnesses(ctx, predicate)
		if err != nil {
			return indexError(err)
		}
		rows := make([]x.ProtectedRow, len(witnesses))
		for i, witness := range witnesses {
			rows[i] = witness.Row
		}
		qualified, err := node.qualify(ctx, rows, false)
		if err != nil {
			return err
		}
		if err = namespace.qualify(ctx, qualified, read.scope.DataOrganizationID); err != nil {
			return err
		}
		eligible := make([]d.AddressFact, 0, len(witnesses))
		for i, witness := range witnesses {
			actual := qualified[i].fact
			if witness.Address != actual.From && (actual.To == nil || witness.Address != *actual.To) || len(actors[witness.Address]) == 0 {
				return d.ErrUnavailable
			}
			eligible = append(eligible, d.AddressFact{Address: witness.Address, Provenance: d.Provenance{Source: ref, DataOrganizationID: read.scope.DataOrganizationID, TargetActorIDs: slices.Clone(actors[witness.Address]), Kind: d.RetainedHistoryPopulation}})
		}
		read.qualifiedAddresses = eligible
		if read.scope.Query.Resource() == p.AddressHistory {
			page := eligible
			if read.scope.Query.View() == d.List {
				if read.after != nil {
					at := slices.IndexFunc(page, func(a d.AddressFact) bool { return bytes.Compare(a.Address[:], read.after.Address.Address[:]) > 0 })
					if at < 0 {
						page = []d.AddressFact{}
					} else {
						page = page[at:]
					}
				}
				limit := int(read.scope.Query.Limit())
				read.facts.End = len(page) <= limit
				if !read.facts.End {
					page = page[:limit]
					last := page[len(page)-1]
					read.facts.Next = &d.Position{Kind: d.WalletSource, Address: &d.AddressPosition{Address: last.Address}}
				}
			} else {
				read.facts.End = true
			}
			read.facts.Addresses = page
		}
	}
	return nil
}

func (read *snapshot) projectSanctions(ctx context.Context) error {
	addresses := make([][20]byte, len(read.qualifiedAddresses))
	for i, fact := range read.qualifiedAddresses {
		addresses[i] = fact.Address
	}
	projection, err := read.owner.sanctions.Match(ctx, read.scope.DataOrganizationID, addresses)
	if err != nil {
		return err
	}
	if projection.BundleDigest != read.owner.plan.BundleDigest || projection.CatalogDigest != read.owner.sanctionsDigest {
		return d.ErrUnavailable
	}
	ref := projection.CatalogDigest
	epoch := digestParts("ops.disclosure.approved-sanctions-epoch/v1", read.owner.plan.BundleDigest, ref)
	raw := sha256.Sum256([]byte("ops.disclosure.sanctions-content-generation/v1:" + string(ref)))
	generation, _ := uuid.FromBytes(raw[:16])
	descriptor := d.SourceDescriptor{Version: 1, Kind: d.SanctionsSource, Reference: ref, NetworkKey: read.owner.plan.NetworkKey, Epoch: epoch, Generation: generation.String(), PlanDigest: read.owner.plan.PlanDigest, FormatDigest: digestParts("ops.disclosure.approved-sanctions-format/v1"), CoverageDigest: ref, AsOf: read.owner.now(), Population: "CURRENT_APPROVED_SANCTIONS"}
	read.descriptors = append(read.descriptors, descriptor)
	status := "clear"
	if len(addresses) == 0 {
		status = "not-applicable"
	} else if len(projection.Matches) > 0 {
		status = "hit"
	}
	aggregate := d.SanctionsAggregate{Status: status, Matches: projection.Matches, ScopedAddressCount: uint16(len(addresses)), SourceDigest: ref, CheckedAt: read.owner.now()}
	if read.scope.Query.Resource() == p.ComplianceReport {
		if read.facts.ActivitySummary == nil || read.finance == nil {
			return d.ErrUnavailable
		}
		read.facts.Compliance = &d.ComplianceAggregate{Activity: *read.facts.ActivitySummary, Sanctions: aggregate, Evidence: read.finance.Evidence(), KYC: "not_evaluated"}
		read.facts.ActivitySummary = nil
	} else {
		read.facts.Sanctions = &aggregate
	}
	read.facts.End = true
	return nil
}

func (read *snapshot) Descriptors() []d.SourceDescriptor {
	read.mu.Lock()
	defer read.mu.Unlock()
	return slices.Clone(read.descriptors)
}
func (read *snapshot) Basis() d.RetainedBasis {
	read.mu.Lock()
	defer read.mu.Unlock()
	return read.basis.Clone()
}
func (read *snapshot) Read(ctx context.Context, scope d.ReadScope, after *d.Position) (d.Facts, error) {
	read.mu.Lock()
	defer read.mu.Unlock()
	if read.closed || read.read || ctx == nil || ctx.Err() != nil || read.fence.Check() != nil || !sameRead(read.scope, scope) || !equalPosition(read.after, after) {
		return d.Facts{}, d.ErrInvalid
	}
	read.read = true
	return d.DetachFacts(read.facts)
}
func (read *snapshot) CheckCurrent(ctx context.Context) error {
	read.mu.Lock()
	defer read.mu.Unlock()
	if read.closed || !read.read || read.fence.Check() != nil {
		return d.ErrUnavailable
	}
	if read.index != nil {
		if err := read.index.Recheck(ctx); err != nil {
			return indexError(err)
		}
	}
	if read.namespace != nil {
		if err := read.namespace.check(ctx); err != nil {
			return err
		}
	}
	if read.wallet != nil {
		if err := read.wallet.CheckCurrent(ctx); err != nil {
			return err
		}
	}
	if read.finance != nil {
		if err := read.finance.CheckCurrent(ctx); err != nil {
			return err
		}
	}
	if read.activity != nil {
		if err := read.activity.CheckCurrent(ctx); err != nil {
			return err
		}
	}
	if read.node != nil {
		if err := read.node.check(ctx); err != nil {
			return err
		}
	}
	if read.fence.Check() != nil {
		return d.ErrUnavailable
	}
	return nil
}
func (read *snapshot) Close() {
	if read == nil {
		return
	}
	read.mu.Lock()
	defer read.mu.Unlock()
	if read.closed {
		return
	}
	read.closed = true
	if read.index != nil {
		read.index.Close()
	}
	if read.wallet != nil {
		read.wallet.Close()
	}
	if read.finance != nil {
		read.finance.Close()
	}
	if read.activity != nil {
		read.activity.Close()
	}
}
