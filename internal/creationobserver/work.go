package creationobserver

import (
	"bytes"
	"encoding/json"
	"sort"
	"time"

	"github.com/ethereum/go-ethereum/common"
	a "privacy-proxy/internal/admission"
	f "privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/nativeadmission"
	"privacy-proxy/internal/rpcexecution"
)

const MaxWorkReferences = 16
const MaxWorkPayloadBytes = 1 << 20
const MaxQualifiedEntries = 2048

// StoredPlan/StoredReference are trusted adapter output, never permission
// capabilities or public request DTOs. The compiler below checks the complete
// bounded immutable metadata; SQL publication rechecks the selected rows.
type StoredPlan struct {
	Digest                   a.Digest
	Version, EntryCount      int
	Payload                  []byte
	RootOrg, Chain, Evidence string
	Manifest, Runtime        a.Digest
	CreatedAt                time.Time
}
type StoredReference struct {
	Seed, Plan               a.Digest
	Kind                     string
	Branch                   int
	WalletActor, WalletOrg   string
	Witness                  a.Witness
	OriginActor, OriginOrg   string
	Anchor                   f.Header
	Profile                  string
	Manifest, Runtime        a.Digest
	CapturedAt               time.Time
	Coverage                 *f.CoverageRecord
	Revoked, AnchorCanonical bool
}
type StoredWork struct {
	Network    f.Network
	Before     f.ObserverSnapshot
	Hash       common.Hash
	Generation int64
	Plans      []StoredPlan
	References []StoredReference
}
type workPlan struct {
	stored  StoredPlan
	decoded nativeadmission.CreationPlanData
}
type WorkSnapshot struct {
	network    f.Network
	before     f.ObserverSnapshot
	hash       common.Hash
	generation int64
	plans      map[a.Digest]workPlan
	refs       []StoredReference
	digest     f.Digest
}

func canonicalNetwork(n f.Network) bool {
	key, err := (a.NetworkBinding{Environment: n.Environment, ChainID: n.ChainID, GenesisHash: n.Genesis.Hex(), DeploymentID: n.Deployment}).Key()
	return n.Valid() && err == nil && f.Digest(key) == n.Key
}
func validObservationSnapshot(s f.ObserverSnapshot) bool {
	l, state := s.Lease, s.State
	return l.Valid() && state.Network == l.Network && state.ObserverEpoch == l.ObserverEpoch && state.CaptureEpoch == l.CaptureEpoch && state.LeaseOwner == l.Owner && state.LeaseFence == l.Fence && state.SourceSet == l.SourceSet && state.Reference == l.Reference && state.Ready && state.Quarantine == "none" && state.Floor.Valid() && state.Head.Valid() && state.Floor.Number <= state.Head.Number && state.HeaderVersion > 0 && state.ReorgEpoch >= 0
}
func validAuditTime(t time.Time) bool {
	return !t.IsZero() && t.Unix() >= 0 && t.Unix() <= 253402300799
}
func auditTime(t time.Time) time.Time { return t.UTC().Truncate(time.Microsecond) }

// CompileStoredWork copies one bounded read snapshot. Mutable current
// revocation/canonical flags are excluded from its immutable-input digest;
// publication filters/checks those again under the capture fence.
func CompileStoredWork(input StoredWork) (*WorkSnapshot, error) {
	if !canonicalNetwork(input.Network) || !validObservationSnapshot(input.Before) || input.Before.Lease.Network != input.Network.Key || input.Hash == (common.Hash{}) || input.Generation < 1 || len(input.Plans) < 1 || len(input.Plans) > MaxWorkReferences || len(input.References) < 1 || len(input.References) > MaxWorkReferences {
		return nil, a.ErrCoverage
	}
	s := &WorkSnapshot{network: input.Network, before: input.Before, hash: input.Hash, generation: input.Generation, plans: map[a.Digest]workPlan{}, refs: make([]StoredReference, 0, len(input.References))}
	total := 0
	for _, raw := range input.Plans {
		if len(raw.Payload) == 0 || len(raw.Payload) > nativeadmission.MaxCreationPlanBytes || len(raw.Payload) > MaxWorkPayloadBytes-total || !validAuditTime(raw.CreatedAt) {
			return nil, a.ErrCoverage
		}
		total += len(raw.Payload)
		if _, ok := s.plans[raw.Digest]; ok {
			return nil, a.ErrCoverage
		}
		raw.Payload = bytes.Clone(raw.Payload)
		raw.CreatedAt = auditTime(raw.CreatedAt)
		var p nativeadmission.CreationPlanData
		var err error
		if raw.Version == 1 {
			p, err = a.DecodeCreationPlan(raw.Payload, raw.Digest)
		} else if raw.Version == 2 {
			p, err = a.DecodeCapturedCreationPlan(raw.Payload, raw.Digest)
		} else {
			return nil, a.ErrCoverage
		}
		if err != nil || p.Hash != input.Hash || p.RootOrg != raw.RootOrg || p.Chain != raw.Chain || p.Chain != input.Network.ChainID || p.Evidence != raw.Evidence || len(p.Entries) != raw.EntryCount {
			return nil, a.ErrCoverage
		}
		manifest, _ := a.ParseDigest(p.Manifest)
		runtime, _ := a.ParseDigest(p.Runtime)
		if manifest != raw.Manifest || runtime != raw.Runtime {
			return nil, a.ErrCoverage
		}
		s.plans[raw.Digest] = workPlan{stored: raw, decoded: p}
	}
	seen := map[a.Digest]bool{}
	branches := map[string]map[int]bool{"WALLET": {}, "FACTORY": {}}
	used := map[a.Digest]bool{}
	for _, r := range input.References {
		plan, ok := s.plans[r.Plan]
		if !ok || seen[r.Seed] || r.Branch < 1 || r.Branch > a.MaxCreationRefsPerBranch || !validAuditTime(r.CapturedAt) || !r.Anchor.Valid() || r.Profile != plan.decoded.Evidence || r.Manifest != plan.stored.Manifest || r.Runtime != plan.stored.Runtime {
			return nil, a.ErrCoverage
		}
		if r.Kind != "WALLET" && r.Kind != "FACTORY" {
			return nil, a.ErrCoverage
		}
		if branches[r.Kind][r.Branch] {
			return nil, a.ErrCoverage
		}
		branches[r.Kind][r.Branch] = true
		seen[r.Seed] = true
		used[r.Plan] = true
		r.CapturedAt = auditTime(r.CapturedAt)
		i := a.CreationIntent{Plan: plan.stored.Payload, PlanDigest: r.Plan, CapturedAt: r.CapturedAt, Factory: r.Kind == "FACTORY", Anchor: rpcexecution.Anchor{Hash: r.Anchor.Hash, Number: r.Anchor.Number, Timestamp: r.Anchor.Timestamp, ChainID: input.Network.ChainID, OrganizationID: plan.decoded.RootOrg, Profile: r.Profile}}
		if r.Kind == "WALLET" {
			if !identity.ValidActorID(r.WalletActor) || r.WalletActor != r.OriginActor || r.WalletOrg != r.OriginOrg || r.WalletOrg != plan.decoded.RootOrg || !r.Witness.Valid() || r.Witness.AnchorHash != r.Anchor.Hash || r.Witness.AnchorNumber != r.Anchor.Number || r.Witness.AnchorTimestamp != r.Anchor.Timestamp || r.Witness.EvidenceProfile != r.Profile {
				return nil, a.ErrCoverage
			}
			i.Wallet = &a.CreationWalletAuthority{Actor: r.WalletActor, Organization: r.WalletOrg, Witness: r.Witness.ID}
		} else if r.WalletActor != "" || r.WalletOrg != "" || r.Witness != (a.Witness{}) || len(plan.decoded.FactoryRoots) == 0 {
			return nil, a.ErrCoverage
		}
		if _, err := func() (nativeadmission.CreationPlanData, error) {
			if plan.stored.Version == 1 {
				return i.PlanData()
			}
			return i.CapturedPlanData()
		}(); err != nil || i.SeedDigest(r.Kind) != r.Seed {
			return nil, a.ErrCoverage
		}
		if plan.stored.Version == 1 {
			if r.Coverage != nil || r.Revoked {
				return nil, a.ErrCoverage
			}
		} else {
			if r.Coverage == nil {
				return nil, a.ErrCoverage
			}
			c := *r.Coverage
			if _, err := c.Canonical(); err != nil || c.Network != input.Network.Key || c.HighWater.Number > r.Anchor.Number || c.Latest.Number < r.Anchor.Number || c.HighWater.Number == r.Anchor.Number && c.HighWater.Hash != r.Anchor.Hash {
				return nil, a.ErrCoverage
			}
			c.ProbeStarted, c.ProbeFinished, c.ValidUntil = auditTime(c.ProbeStarted), auditTime(c.ProbeFinished), auditTime(c.ValidUntil)
			r.Coverage = &c
		}
		r.Witness.DecisionAt = auditTime(r.Witness.DecisionAt)
		r.Witness.WalletEvidenceAt = auditTime(r.Witness.WalletEvidenceAt)
		s.refs = append(s.refs, r)
	}
	if len(used) != len(s.plans) {
		return nil, a.ErrCoverage
	}
	wallets, factories := len(branches["WALLET"]), len(branches["FACTORY"])
	for _, kind := range []string{"WALLET", "FACTORY"} {
		for i := 1; i <= len(branches[kind]); i++ {
			if !branches[kind][i] {
				return nil, a.ErrCoverage
			}
		}
	}
	if input.Generation < int64(max(wallets, factories)) || input.Generation > int64(wallets+factories) {
		return nil, a.ErrCoverage
	}
	sort.Slice(s.refs, func(i, j int) bool { return bytes.Compare(s.refs[i].Seed[:], s.refs[j].Seed[:]) < 0 })
	plans := make([]StoredPlan, 0, len(s.plans))
	for _, p := range s.plans {
		semanticPlan := p.stored
		// The canonical version-specific payload was already checked against
		// its digest. Bind that digest instead of base64-copying up to1MiB of
		// owned payload into another JSON work document.
		semanticPlan.Payload = nil
		plans = append(plans, semanticPlan)
	}
	sort.Slice(plans, func(i, j int) bool { return bytes.Compare(plans[i].Digest[:], plans[j].Digest[:]) < 0 })
	semanticRefs := append([]StoredReference{}, s.refs...)
	for i := range semanticRefs {
		semanticRefs[i].Revoked = false
		semanticRefs[i].AnchorCanonical = false
	}
	semantic := struct {
		Network    f.Network
		Hash       common.Hash
		Generation int64
		Plans      []StoredPlan
		References []StoredReference
	}{s.network, s.hash, s.generation, plans, semanticRefs}
	encoded, err := json.Marshal(semantic)
	if err != nil {
		return nil, a.ErrCoverage
	}
	s.digest = f.Hash("ops-creation-work-input/v1", encoded)
	return s, nil
}
func (s *WorkSnapshot) Hash() common.Hash {
	if s == nil {
		return common.Hash{}
	}
	return s.hash
}
func (s *WorkSnapshot) Network() f.Network {
	if s == nil {
		return f.Network{}
	}
	return s.network
}
func (s *WorkSnapshot) Generation() int64 {
	if s == nil {
		return 0
	}
	return s.generation
}
func (s *WorkSnapshot) Digest() f.Digest {
	if s == nil {
		return f.Digest{}
	}
	return s.digest
}
func (s *WorkSnapshot) Before() f.ObserverSnapshot {
	if s == nil {
		return f.ObserverSnapshot{}
	}
	return s.before
}
func (s *WorkSnapshot) HasEligibleCoverage() bool {
	if s == nil {
		return false
	}
	for _, r := range s.refs {
		if r.Coverage != nil && !r.Revoked && r.AnchorCanonical {
			return true
		}
	}
	return false
}
func (s *WorkSnapshot) Seeds() []a.Digest {
	if s == nil {
		return nil
	}
	out := make([]a.Digest, len(s.refs))
	for i, r := range s.refs {
		out[i] = r.Seed
	}
	return out
}

// RequireCurrent checks only the originally captured immutable subset. A1 may
// append new refs while the node proof is in flight; those stay due at their
// newer generation. Current revocation/branch flags are checked separately.
func (s *WorkSnapshot) RequireCurrent(current *WorkSnapshot) error {
	if s == nil || current == nil || current.network != s.network || current.hash != s.hash || current.generation < s.generation {
		return a.ErrCoverage
	}
	raw := StoredWork{Network: s.network, Before: s.before, Hash: s.hash, Generation: s.generation}
	for digest := range s.plans {
		p, ok := current.plans[digest]
		if !ok {
			return a.ErrCoverage
		}
		raw.Plans = append(raw.Plans, p.stored)
	}
	bySeed := map[a.Digest]StoredReference{}
	for _, r := range current.refs {
		bySeed[r.Seed] = r
	}
	for _, r := range s.refs {
		c, ok := bySeed[r.Seed]
		if !ok {
			return a.ErrCoverage
		}
		raw.References = append(raw.References, c)
	}
	compiled, err := CompileStoredWork(raw)
	if err != nil || compiled.digest != s.digest {
		return a.ErrCoverage
	}
	return nil
}
func (s *WorkSnapshot) CurrentlyEligible(seed a.Digest) bool {
	if s == nil {
		return false
	}
	for _, r := range s.refs {
		if r.Seed == seed {
			return r.Coverage != nil && !r.Revoked && r.AnchorCanonical
		}
	}
	return false
}
