package creationobserver

import (
	"encoding/json"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	a "privacy-proxy/internal/admission"
	f "privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/nativeadmission"
	"privacy-proxy/internal/rpcexecution"
)

// Birth has no winning organization or actor. Authority is kept separately in
// append-only associations and is useful only with original capture coverage
// and a current canonical-prefix check.
type Birth struct {
	Record, Parent, Depth   int
	Address, Creator        common.Address
	Kind                    string
	TupleDigest, OutputHash common.Hash
	OutputLength            int
}
type Association struct {
	Record, Entry                int
	Seed                         a.Digest
	Namespace, Kind, WalletActor string
	FactoryRoot                  int
	Qualification                f.Digest
}
type ObservationData struct {
	Inclusion    f.Header
	Index        uint32
	Proof        common.Hash
	Births       []Birth
	Associations []Association
}

// QualifiedObservation can be constructed only from independently acquired
// included evidence and a checked immutable work snapshot. It is a historical
// association proposal, never a native permission result.
type QualifiedObservation struct {
	work *WorkSnapshot
	data ObservationData
}

func (q *QualifiedObservation) Work() *WorkSnapshot {
	if q == nil {
		return nil
	}
	return q.work
}
func (q *QualifiedObservation) Data() ObservationData {
	if q == nil {
		return ObservationData{}
	}
	d := q.data
	d.Births = append([]Birth{}, d.Births...)
	d.Associations = append([]Association{}, d.Associations...)
	return d
}

type creationTuple struct {
	Address, Creator, Caller common.Address
	Kind                     string
	Input                    common.Hash
	Value                    string
	Depth                    int
}

func actualTuple(c rpcexecution.IncludedCreationRecord) creationTuple {
	return creationTuple{c.Address, c.Creator, c.Caller, c.Kind, c.InputHash, c.Value, c.Depth}
}
func plannedTuple(c nativeadmission.CreationEntry) creationTuple {
	return creationTuple{c.Address, c.Creator, c.Caller, c.Kind, c.InputHash, c.Value, c.Depth}
}
func tupleDigest(t creationTuple) common.Hash {
	digest, _, _ := boundedTupleDigest(t, 2000000)
	return digest
}
func boundedTupleDigest(t creationTuple, remaining int) (common.Hash, int, error) {
	b, _ := json.Marshal(t)
	if len(b) > remaining {
		return common.Hash{}, 0, a.ErrCoverage
	}
	return common.Hash(f.Hash("ops-included-creation-tuple/v1", b)), len(b), nil
}

// ValidateStoredAssociation checks bounded PRESENT immutable metadata during
// offline recovery. It does not reacquire/replay a historical trace or prove
// completeness; the original included proof digest remains first-writer
// evidence under the separately acknowledged node/store trust boundary.
func ValidateStoredAssociation(proof common.Hash, birth Birth, as Association, plan nativeadmission.CreationPlanData, referenceKind, referenceActor string) error {
	if as.Record != birth.Record || as.Entry < 0 || as.Entry >= len(plan.Entries) || as.Kind != referenceKind || proof == (common.Hash{}) {
		return a.ErrCoverage
	}
	e := plan.Entries[as.Entry]
	birth.Depth = e.Depth
	if birth.Address != e.Address || birth.Creator != e.Creator || birth.Kind != e.Kind || birth.TupleDigest != tupleDigest(plannedTuple(e)) || birth.Parent < -1 || (e.CreationParent < 0) != (birth.Parent < 0) || as.Namespace != e.Namespace {
		return a.ErrCoverage
	}
	if as.Kind == "WALLET" {
		if as.WalletActor != referenceActor || as.WalletActor == "" || as.FactoryRoot != -1 {
			return a.ErrCoverage
		}
	} else if as.Kind == "FACTORY" {
		if as.WalletActor != "" || as.FactoryRoot < 0 || as.FactoryRoot != e.FactoryRoot || as.FactoryRoot >= len(plan.FactoryRoots) {
			return a.ErrCoverage
		}
		root := plan.FactoryRoots[as.FactoryRoot]
		if root.Declaration < 0 || root.Declaration >= len(plan.Declarations) || plan.Declarations[root.Declaration].OrganizationID != e.Namespace {
			return a.ErrCoverage
		}
	} else {
		return a.ErrCoverage
	}
	want, err := AssociationDigest(proof, birth, as.Seed, as.Entry, plan, as.Kind)
	if err != nil || want != as.Qualification {
		return a.ErrCoverage
	}
	return nil
}

// AssociationDigest binds the full planned creation path, not the diagnostic
// preflight record ordinal. It is shared with offline present-row validation.
func AssociationDigest(proof common.Hash, birth Birth, seed a.Digest, entry int, plan nativeadmission.CreationPlanData, kind string) (f.Digest, error) {
	if entry < 0 || entry >= len(plan.Entries) || kind != "WALLET" && kind != "FACTORY" {
		return f.Digest{}, a.ErrCoverage
	}
	paths, _, err := creationPaths(plan, 2000000)
	if err != nil {
		return f.Digest{}, err
	}
	digest, _, err := associationDigest(proof, birth, seed, entry, kind, paths[entry], 2000000)
	return digest, err
}
func creationPaths(plan nativeadmission.CreationPlanData, remaining int) ([]f.Digest, int, error) {
	if len(plan.Entries) > nativeadmission.MaxCreationEntries {
		return nil, 0, a.ErrCoverage
	}
	paths := make([]f.Digest, len(plan.Entries))
	work := 0
	for i, e := range plan.Entries {
		if e.CreationParent < -1 || e.CreationParent >= i {
			return nil, 0, a.ErrCoverage
		}
		parent := f.Hash("ops-creation-planned-root/v1", nil)
		if e.CreationParent >= 0 {
			parent = paths[e.CreationParent]
		}
		e.Record = 0 // diagnostic only; never part of included identity
		raw, err := json.Marshal(struct {
			Index  int
			Parent f.Digest
			Entry  nativeadmission.CreationEntry
		}{i, parent, e})
		if err != nil {
			return nil, 0, a.ErrCoverage
		}
		if len(raw) > remaining-work {
			return nil, 0, a.ErrCoverage
		}
		work += len(raw)
		paths[i] = f.Hash("ops-creation-planned-path/v1", raw)
	}
	return paths, work, nil
}
func associationDigest(proof common.Hash, birth Birth, seed a.Digest, entry int, kind string, path f.Digest, remaining int) (f.Digest, int, error) {
	raw, err := json.Marshal(struct {
		Proof common.Hash
		Birth Birth
		Seed  a.Digest
		Entry int
		Kind  string
		Path  f.Digest
	}{proof, birth, seed, entry, kind, path})
	if err != nil {
		return f.Digest{}, 0, a.ErrCoverage
	}
	if len(raw) > remaining {
		return f.Digest{}, 0, a.ErrCoverage
	}
	return f.Hash("ops-creation-authority-qualification/v1", raw), len(raw), nil
}

func QualifyIncluded(work *WorkSnapshot, proof *rpcexecution.IncludedCreationProof) (*QualifiedObservation, error) {
	if work == nil || proof == nil || proof.Digest() == (common.Hash{}) || !proof.Transaction().Valid() || proof.Transaction().Hash() != work.hash || proof.Transaction().ChainID() != work.network.ChainID || proof.Source().Network != work.network || proof.Source().Digest() != work.before.Lease.Reference || proof.Source().Profile != rpcexecution.IncludedProfileID {
		return nil, a.ErrCoverage
	}
	header, index := proof.Inclusion()
	if !header.Valid() || header.Number < work.before.State.Floor.Number || header.Number > work.before.State.Head.Number || header.Number == work.before.State.Head.Number && header.Hash != work.before.State.Head.Hash {
		return nil, a.ErrCoverage
	}
	data, err := matchCreations(work, proof.Creations(), proof.Digest(), header, index)
	if err != nil {
		return nil, err
	}
	return &QualifiedObservation{work: work, data: data}, nil
}

// matchCreations does no policy evaluation. Each plan entry has at most one
// indexed tuple match, then one parent/root check. Unmatched ancestry removes
// only that entry and its creation descendants from the association set.
func matchCreations(work *WorkSnapshot, actual []rpcexecution.IncludedCreationRecord, proof common.Hash, header f.Header, index uint32) (ObservationData, error) {
	out := ObservationData{Inclusion: header, Index: index, Proof: proof, Births: []Birth{}, Associations: []Association{}}
	if len(actual) > 4096 {
		return out, a.ErrCoverage
	}
	byTuple := map[creationTuple]int{}
	byRecord := map[int]rpcexecution.IncludedCreationRecord{}
	workUsed := len(actual)
	birthTemplates := map[int]Birth{}
	for i, c := range actual {
		if c.Record < 0 || c.Record >= 4096 || c.Parent >= c.Record || c.Parent < -1 || c.Depth < 0 || c.Depth > 256 {
			return out, a.ErrCoverage
		}
		if _, exists := byRecord[c.Record]; exists {
			return out, a.ErrCoverage
		}
		if i > 0 && actual[i-1].Record >= c.Record {
			return out, a.ErrCoverage
		}
		if c.Parent >= 0 {
			if _, ok := byRecord[c.Parent]; !ok {
				return out, a.ErrCoverage
			}
		}
		byRecord[c.Record] = c
		if c.Survives {
			if c.Failed || c.AncestorFailed || !c.AddressKnown || !c.CallerKnown || c.OutputLength < 1 || c.OutputLength > 1<<20 {
				return out, a.ErrCoverage
			}
			digest, cost, err := boundedTupleDigest(actualTuple(c), 2000000-workUsed)
			if err != nil {
				return out, err
			}
			workUsed += cost
			birthTemplates[c.Record] = Birth{Record: c.Record, Parent: c.Parent, Depth: c.Depth, Address: c.Address, Creator: c.Creator, Kind: c.Kind, TupleDigest: digest, OutputHash: c.OutputHash, OutputLength: c.OutputLength}
		}
		if c.Failed || c.AncestorFailed || !c.AddressKnown || !c.CallerKnown {
			continue
		}
		t := actualTuple(c)
		if _, exists := byTuple[t]; exists {
			byTuple[t] = -1
		} else {
			byTuple[t] = c.Record
		}
	}
	// Work counts serialized hash input plus bounded index records. No
	// per-entry ancestor traversal or per-rule scan occurs in this path.
	type planMatches struct {
		records []int
		paths   []f.Digest
	}
	matches := map[a.Digest]planMatches{}
	for digest, p := range work.plans {
		if len(p.stored.Payload) > 2000000-workUsed {
			return out, a.ErrCoverage
		}
		workUsed += len(p.stored.Payload)
		paths, pathWork, err := creationPaths(p.decoded, 2000000-workUsed)
		if err != nil {
			return out, err
		}
		workUsed += pathWork
		if workUsed > 2000000 {
			return out, a.ErrCoverage
		}
		mapped := make([]int, len(p.decoded.Entries))
		for i, e := range p.decoded.Entries {
			mapped[i] = -1
			record, ok := byTuple[plannedTuple(e)]
			if !ok || record < 0 {
				continue
			}
			c := byRecord[record]
			if e.CreationParent < 0 {
				if c.Parent >= 0 {
					continue
				}
			} else if e.CreationParent >= i || mapped[e.CreationParent] < 0 || c.Parent != mapped[e.CreationParent] {
				continue
			}
			mapped[i] = record
		}
		matches[digest] = planMatches{mapped, paths}
	}
	births := map[int]Birth{}
	for _, r := range work.refs {
		if r.Coverage == nil || r.Revoked || !r.AnchorCanonical || r.Anchor.Number < work.before.State.Floor.Number || r.Anchor.Number >= header.Number {
			continue
		}
		p := work.plans[r.Plan].decoded
		mapped := matches[r.Plan].records
		for i, record := range mapped {
			if record < 0 {
				continue
			}
			c := byRecord[record]
			if !c.Survives {
				continue
			}
			e := p.Entries[i]
			root := -1
			if r.Kind == "FACTORY" {
				root = e.FactoryRoot
				if root < 0 || root >= len(p.FactoryRoots) {
					continue
				}
				froot := p.FactoryRoots[root]
				if froot.Entry < 0 || froot.Entry >= len(mapped) || mapped[froot.Entry] < 0 || froot.Declaration < 0 || froot.Declaration >= len(p.Declarations) || e.Namespace != p.Declarations[froot.Declaration].OrganizationID {
					continue
				}
			}
			b := birthTemplates[record]
			qualification, hashWork, err := associationDigest(proof, b, r.Seed, i, r.Kind, matches[r.Plan].paths[i], 2000000-workUsed)
			if err != nil {
				return out, err
			}
			workUsed += hashWork
			if workUsed > 2000000 {
				return out, a.ErrCoverage
			}
			if len(out.Associations) >= MaxQualifiedEntries {
				return out, a.ErrCoverage
			}
			actor := ""
			if r.Kind == "WALLET" {
				actor = r.WalletActor
			}
			out.Associations = append(out.Associations, Association{Record: record, Entry: i, Seed: r.Seed, Namespace: e.Namespace, Kind: r.Kind, WalletActor: actor, FactoryRoot: root, Qualification: qualification})
			births[record] = b
		}
	}
	for _, b := range births {
		out.Births = append(out.Births, b)
	}
	sort.Slice(out.Births, func(i, j int) bool { return out.Births[i].Record < out.Births[j].Record })
	return out, nil
}
