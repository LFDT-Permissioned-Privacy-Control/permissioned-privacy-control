package historynamespace

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"math"
	"slices"

	"privacy-proxy/internal/networkidentity"
	"privacy-proxy/internal/strictjson"
)

// Lifetime is a normalized immutable assertion. Canonicality and transaction
// counts are independently qualified by the later reader, not by this DTO.
type Lifetime struct {
	Kind          string         `json:"kind"`
	Address       Address        `json:"address"`
	Segment       Digest         `json:"segment"`
	LifetimeID    *string        `json:"lifetimeId,omitempty"`
	RuntimeHash   Hash           `json:"runtimeHash"`
	RuntimeLength uint32         `json:"runtimeLength"`
	Initial       Label          `json:"initial"`
	Physical      *PhysicalStart `json:"physical,omitempty"`
	Start         *Cut           `json:"start,omitempty"`
	End           *Cut           `json:"end,omitempty"`
	Checkpoint    *CheckpointRef `json:"checkpoint,omitempty"`
	ProofDigest   *Digest        `json:"proofDigest,omitempty"`
}

func (l Lifetime) Detached() Lifetime {
	l.Initial = l.Initial.Detached()
	if l.LifetimeID != nil {
		id := *l.LifetimeID
		l.LifetimeID = &id
	}
	if l.Physical != nil {
		p := l.Physical.Detached()
		l.Physical = &p
	}
	for _, field := range []**Cut{&l.Start, &l.End} {
		if *field != nil {
			value := **field
			*field = &value
		}
	}
	if l.Checkpoint != nil {
		point := *l.Checkpoint
		l.Checkpoint = &point
	}
	if l.ProofDigest != nil {
		d := *l.ProofDigest
		l.ProofDigest = &d
	}
	return l
}

type Transfer struct {
	Kind          string  `json:"kind"`
	Address       Address `json:"address"`
	SegmentKind   string  `json:"segmentKind"`
	Segment       Digest  `json:"segment"`
	LegacyBasis   *Digest `json:"legacyBasis,omitempty" optional:"true"`
	Initial       Label   `json:"initial"`
	Parent        *Digest `json:"parent,omitempty" optional:"true"`
	Previous      Label   `json:"previous"`
	New           Label   `json:"new"`
	EffectiveFrom Cut     `json:"effectiveFrom"`
}

func (t Transfer) Valid() bool {
	return t.Kind == "transfer" && t.Segment != (Digest{}) && t.Initial.Valid() && t.Previous.Valid() && t.New.Valid() && !t.Previous.Equal(t.New) &&
		t.EffectiveFrom.Valid() && (t.Parent == nil || *t.Parent != (Digest{})) &&
		(t.SegmentKind == "legacy" && t.LegacyBasis != nil && *t.LegacyBasis != (Digest{}) || t.SegmentKind == "prague" && t.LegacyBasis == nil)
}
func (t Transfer) Detached() Transfer {
	t.Initial, t.Previous, t.New = t.Initial.Detached(), t.Previous.Detached(), t.New.Detached()
	for _, field := range []**Digest{&t.LegacyBasis, &t.Parent} {
		if *field != nil {
			d := **field
			*field = &d
		}
	}
	return t
}

// CheckpointRef identifies END-of-block code observation, not transaction
// boundary zero. Its cut support requires the independently qualified TxCount.
type CheckpointRef struct {
	Number uint64 `json:"number"`
	Hash   Hash   `json:"hash"`
}

func (c CheckpointRef) Valid() bool { return c.Number <= math.MaxInt64 && c.Hash != (Hash{}) }

type lifetimeWire struct {
	Kind          string         `json:"kind"`
	Address       Address        `json:"address"`
	RuntimeHash   Hash           `json:"runtimeHash"`
	RuntimeLength uint32         `json:"runtimeLength"`
	Initial       Label          `json:"initial"`
	LifetimeID    *string        `json:"lifetimeId,omitempty" optional:"true"`
	Physical      *PhysicalStart `json:"physical,omitempty" optional:"true"`
	Start         *Cut           `json:"start,omitempty" optional:"true"`
	End           *Cut           `json:"end,omitempty" optional:"true"`
	Checkpoint    *CheckpointRef `json:"checkpoint,omitempty" optional:"true"`
}

type artifactWire struct {
	APIVersion string                  `json:"apiVersion"`
	CohortID   string                  `json:"cohortId"`
	Network    networkidentity.Binding `json:"network"`
	ModelID    string                  `json:"modelId"`
	Era        ModelEra                `json:"era"`
	Statements []json.RawMessage       `json:"statements"`
}

// Artifact is an opaque bounded source document. Its digest identifies exact
// approval bytes; it does not prove Git approval or a historical namespace.
type Artifact struct {
	network       networkidentity.Binding
	networkKey    Digest
	era           ModelEra
	cohortID      string
	rawDigest     Digest
	lifetimes     []Lifetime
	transfers     []Transfer
	checkpointSet []Address
	checkpoint    CheckpointRef
}

func ParseArtifact(raw []byte) (*Artifact, error) {
	if len(raw) == 0 || len(raw) > MaxArtifactBytes {
		return nil, ErrTooBroad
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, err := strictjson.ReadValue(d, 0, 12)
	if err != nil {
		return nil, ErrInvalid
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrInvalid
	}
	var wire artifactWire
	if strictjson.ExactDecode(v, &wire) != nil || wire.APIVersion != ArtifactAPIVersion || wire.ModelID != ModelID || !wire.Era.Valid() || !UUID(wire.CohortID) {
		return nil, ErrInvalid
	}
	if len(wire.Statements) == 0 || len(wire.Statements) > MaxStatements {
		return nil, ErrTooBroad
	}
	network, err := NetworkKey(wire.Network)
	if err != nil {
		return nil, ErrInvalid
	}
	a := &Artifact{network: wire.Network, networkKey: network, era: wire.Era, cohortID: wire.CohortID, rawDigest: Digest(sha256.Sum256(raw))}
	seen := map[Digest]bool{}
	checkpointAddresses := map[Address]bool{}
	for _, statement := range wire.Statements {
		decoder := json.NewDecoder(bytes.NewReader(statement))
		decoder.UseNumber()
		value, err := strictjson.ReadValue(decoder, 0, 12)
		if err != nil {
			return nil, ErrInvalid
		}
		object, ok := value.(map[string]any)
		if !ok {
			return nil, ErrInvalid
		}
		kind, ok := object["kind"].(string)
		if !ok {
			return nil, ErrInvalid
		}
		var identity Digest
		if kind == "transfer" {
			var t Transfer
			if strictjson.ExactDecode(value, &t) != nil || !t.Valid() {
				return nil, ErrInvalid
			}
			identity, _ = semanticDigest("ops-history-transfer-input/v1", t)
			a.transfers = append(a.transfers, t)
		} else {
			var w lifetimeWire
			if strictjson.ExactDecode(value, &w) != nil {
				return nil, ErrInvalid
			}
			l, err := normalizeLifetime(network, wire.Era, w)
			if err != nil {
				return nil, err
			}
			identity, _ = semanticDigest("ops-history-lifetime-input/v1", l)
			if kind == "prague-checkpoint" {
				if len(checkpointAddresses) >= MaxCheckpointAddresses || checkpointAddresses[l.Address] || len(checkpointAddresses) > 0 && a.checkpoint != *l.Checkpoint {
					return nil, ErrInvalid
				}
				checkpointAddresses[l.Address] = true
				a.checkpoint = *l.Checkpoint
				a.checkpointSet = append(a.checkpointSet, l.Address)
			}
			a.lifetimes = append(a.lifetimes, l)
		}
		if seen[identity] {
			return nil, ErrInvalid
		}
		seen[identity] = true
	}
	slices.SortFunc(a.checkpointSet, func(a, b Address) int { return bytes.Compare(a[:], b[:]) })
	return a, nil
}

func normalizeLifetime(network Digest, era ModelEra, w lifetimeWire) (Lifetime, error) {
	l := Lifetime{Kind: w.Kind, Address: w.Address, RuntimeHash: w.RuntimeHash, RuntimeLength: w.RuntimeLength, Initial: w.Initial, LifetimeID: w.LifetimeID, Physical: w.Physical, Start: w.Start, End: w.End, Checkpoint: w.Checkpoint}
	if !l.Initial.Valid() || l.RuntimeHash == (Hash{}) || l.RuntimeLength == 0 || l.RuntimeLength > MaxRuntimeBytes {
		return Lifetime{}, ErrInvalid
	}
	if l.Kind == "pre-era-finite" {
		if l.LifetimeID == nil || !UUID(*l.LifetimeID) || l.Physical != nil || l.Checkpoint != nil || l.Start == nil || l.End == nil || !l.Start.Valid() || !l.End.Valid() || CompareCuts(*l.Start, *l.End) >= 0 || l.Start.Number == l.End.Number && l.Start.Hash != l.End.Hash || l.Start.Number >= era.EntryNumber || l.End.Number > era.EntryNumber || l.End.Number == era.EntryNumber && (l.End.Index != 0 || l.End.Hash != era.EntryHash) {
			return Lifetime{}, ErrInvalid
		}
		l.Segment, _ = PreEraSegmentKey(network, l.Address, *l.LifetimeID)
		return l, nil
	}
	if l.LifetimeID != nil || l.Physical == nil || !l.Physical.Valid(era) {
		return Lifetime{}, ErrInvalid
	}
	l.Segment, _ = PragueSegmentKey(network, l.Address, l.RuntimeHash, l.RuntimeLength)
	switch l.Kind {
	case "prague-finite":
		if l.Start == nil || l.End == nil || l.Checkpoint != nil || !l.Start.Valid() || !l.End.Valid() || CompareCuts(*l.Start, *l.End) >= 0 || l.Start.Number == l.End.Number && l.Start.Hash != l.End.Hash || l.Start.Number < era.EntryNumber || l.Start.Number == era.EntryNumber && l.Start.Hash != era.EntryHash {
			return Lifetime{}, ErrInvalid
		}
		if b := l.Physical.Birth; b != nil && (CompareCuts(*l.Start, Cut{b.Number, b.Hash, b.Index}) <= 0 || l.Start.Number == b.Number && l.Start.Hash != b.Hash || l.End.Number == b.Number && l.End.Hash != b.Hash) {
			return Lifetime{}, ErrInvalid
		}
	case "prague-checkpoint":
		if l.Start != nil || l.End != nil || l.Checkpoint == nil || !l.Checkpoint.Valid() || l.Checkpoint.Number < era.EntryNumber || l.Checkpoint.Number == era.EntryNumber && l.Checkpoint.Hash != era.EntryHash || l.Physical.Birth != nil && (l.Physical.Birth.Number > l.Checkpoint.Number || l.Physical.Birth.Number == l.Checkpoint.Number && l.Physical.Birth.Hash != l.Checkpoint.Hash) {
			return Lifetime{}, ErrInvalid
		}
	default:
		return Lifetime{}, ErrInvalid
	}
	return l, nil
}

func (a *Artifact) Network() networkidentity.Binding { return a.network }
func (a *Artifact) NetworkKey() Digest               { return a.networkKey }
func (a *Artifact) Era() ModelEra                    { return a.era }
func (a *Artifact) CohortID() string                 { return a.cohortID }
func (a *Artifact) RawDigest() Digest                { return a.rawDigest }
func (a *Artifact) CheckpointRequest() (CheckpointRef, []Address, bool) {
	return a.checkpoint, append([]Address(nil), a.checkpointSet...), len(a.checkpointSet) > 0
}

type QualifiedCode struct {
	Address       Address `json:"address"`
	RuntimeHash   Hash    `json:"runtimeHash"`
	RuntimeLength uint32  `json:"runtimeLength"`
}

// CheckpointFacts are detached metadata, not proof of an owned RPC client.
// The SQL import boundary requires the actual opaque rpcexecution proof first.
type CheckpointFacts struct {
	Network   Digest          `json:"network"`
	Source    Digest          `json:"source"`
	Era       ModelEra        `json:"era"`
	Number    uint64          `json:"number"`
	Hash      Hash            `json:"hash"`
	Timestamp uint64          `json:"timestamp"`
	Codes     []QualifiedCode `json:"codes"`
}

func CheckpointFactsDigest(f CheckpointFacts) (Digest, error) {
	if f.Network == (Digest{}) || f.Source == (Digest{}) || !f.Era.Valid() || f.Number < f.Era.EntryNumber || f.Number > math.MaxInt64 || f.Hash == (Hash{}) || f.Timestamp < f.Era.EntryTimestamp || f.Timestamp >= f.Era.EndTimestampExclusive || len(f.Codes) == 0 || len(f.Codes) > MaxCheckpointAddresses {
		return Digest{}, ErrInvalid
	}
	var total uint64
	for i, c := range f.Codes {
		if c.RuntimeHash == (Hash{}) || c.RuntimeLength == 0 || c.RuntimeLength > MaxRuntimeBytes || i > 0 && bytes.Compare(f.Codes[i-1].Address[:], c.Address[:]) >= 0 {
			return Digest{}, ErrInvalid
		}
		total += uint64(c.RuntimeLength)
		if total > 8<<20 {
			return Digest{}, ErrTooBroad
		}
	}
	return semanticDigest("ops-history-checkpoint-proof/v1", f)
}

type CompiledCohort struct {
	network     Digest
	era         ModelEra
	cohortID    string
	rawDigest   Digest
	digest      Digest
	lifetimes   []Lifetime
	transfers   []Transfer
	lifeIDs     []Digest
	transferIDs []Digest
	bytes       int
}

// LifetimeDigest validates stored normalized shape before recomputing its
// immutable identity. A proof digest is a retained witness, not trace replay.
func LifetimeDigest(network Digest, era ModelEra, l Lifetime) (Digest, error) {
	if network == (Digest{}) || !era.Valid() || l.Kind == "prague-checkpoint" && (l.ProofDigest == nil || *l.ProofDigest == (Digest{})) || l.Kind != "prague-checkpoint" && l.ProofDigest != nil {
		return Digest{}, ErrInvalid
	}
	n, err := normalizeLifetime(network, era, lifetimeWire{Kind: l.Kind, Address: l.Address, RuntimeHash: l.RuntimeHash, RuntimeLength: l.RuntimeLength, Initial: l.Initial, LifetimeID: l.LifetimeID, Physical: l.Physical, Start: l.Start, End: l.End, Checkpoint: l.Checkpoint})
	if err != nil || n.Segment != l.Segment {
		return Digest{}, ErrInvalid
	}
	return semanticDigest("ops-history-lifetime/v1", struct {
		Network Digest
		Era     ModelEra
		Value   Lifetime
	}{network, era, l})
}

func TransferDigest(network Digest, era ModelEra, t Transfer) (Digest, error) {
	if network == (Digest{}) || !era.Valid() || !t.Valid() {
		return Digest{}, ErrInvalid
	}
	id, err := semanticDigest("ops-history-transfer/v1", struct {
		Network Digest
		Era     ModelEra
		Value   Transfer
	}{network, era, t})
	if err != nil || t.Parent != nil && *t.Parent == id {
		return Digest{}, ErrInvalid
	}
	return id, nil
}

func CohortDigest(network Digest, era ModelEra, lifetimes, transfers []Digest) (Digest, error) {
	if network == (Digest{}) || !era.Valid() || len(lifetimes)+len(transfers) == 0 || len(lifetimes)+len(transfers) > MaxStatements {
		return Digest{}, ErrInvalid
	}
	lifetimes, transfers = append([]Digest(nil), lifetimes...), append([]Digest(nil), transfers...)
	for _, values := range [][]Digest{lifetimes, transfers} {
		slices.SortFunc(values, compareDigest)
		for i, v := range values {
			if v == (Digest{}) || i > 0 && values[i-1] == v {
				return Digest{}, ErrInvalid
			}
		}
	}
	return semanticDigest("ops-history-cohort/v1", struct {
		Network   Digest
		Era       ModelEra
		Lifetimes []Digest
		Transfers []Digest
	}{network, era, lifetimes, transfers})
}

func CanonicalCohortBytes(network Digest, era ModelEra, lifetimes []Lifetime, transfers []Transfer) (int, error) {
	if network == (Digest{}) || !era.Valid() || len(lifetimes) > MaxStatements || len(transfers) > MaxStatements || len(lifetimes)+len(transfers) == 0 || len(lifetimes)+len(transfers) > MaxStatements {
		return 0, ErrInvalid
	}
	for _, l := range lifetimes {
		if _, err := LifetimeDigest(network, era, l); err != nil {
			return 0, err
		}
	}
	for _, t := range transfers {
		if _, err := TransferDigest(network, era, t); err != nil {
			return 0, err
		}
	}
	if len(lifetimes) == 0 {
		lifetimes = nil
	}
	if len(transfers) == 0 {
		transfers = nil
	}
	raw, err := json.Marshal(struct {
		Network   Digest
		Era       ModelEra
		Lifetimes []Lifetime
		Transfers []Transfer
	}{network, era, lifetimes, transfers})
	if err != nil || len(raw) > MaxArtifactBytes {
		return 0, ErrTooBroad
	}
	return len(raw), nil
}

// Compile normalizes attested source data. It does not qualify canonical cuts,
// original basis at transfer edges, or grant any historical namespace authority.
func (a *Artifact) Compile(facts *CheckpointFacts) (*CompiledCohort, error) {
	if a == nil || (len(a.checkpointSet) == 0) != (facts == nil) {
		return nil, ErrInvalid
	}
	var proofDigest Digest
	if facts != nil {
		if len(facts.Codes) > MaxCheckpointAddresses {
			return nil, ErrTooBroad
		}
		copyOfFacts := *facts
		copyOfFacts.Codes = append([]QualifiedCode(nil), facts.Codes...)
		facts = &copyOfFacts
		var err error
		proofDigest, err = CheckpointFactsDigest(*facts)
		if err != nil || facts.Network != a.networkKey || facts.Era != a.era || facts.Number != a.checkpoint.Number || facts.Hash != a.checkpoint.Hash || len(facts.Codes) != len(a.checkpointSet) {
			return nil, ErrInvalid
		}
		for i, address := range a.checkpointSet {
			if facts.Codes[i].Address != address {
				return nil, ErrInvalid
			}
		}
	}
	c := &CompiledCohort{network: a.networkKey, era: a.era, cohortID: a.cohortID, rawDigest: a.rawDigest}
	for _, input := range a.lifetimes {
		l := input.Detached()
		if l.Kind == "prague-checkpoint" {
			i, _ := slices.BinarySearchFunc(facts.Codes, l.Address, func(c QualifiedCode, address Address) int { return bytes.Compare(c.Address[:], address[:]) })
			if facts.Codes[i].RuntimeHash != l.RuntimeHash || facts.Codes[i].RuntimeLength != l.RuntimeLength {
				return nil, ErrInvalid
			}
			d := proofDigest
			l.ProofDigest = &d
		}
		id, err := LifetimeDigest(a.networkKey, a.era, l)
		if err != nil {
			return nil, err
		}
		c.lifetimes = append(c.lifetimes, l)
		c.lifeIDs = append(c.lifeIDs, id)
	}
	for _, input := range a.transfers {
		t := input.Detached()
		id, err := TransferDigest(a.networkKey, a.era, t)
		if err != nil {
			return nil, err
		}
		c.transfers = append(c.transfers, t)
		c.transferIDs = append(c.transferIDs, id)
	}
	var err error
	c.digest, err = CohortDigest(a.networkKey, a.era, c.lifeIDs, c.transferIDs)
	if err != nil {
		return nil, err
	}
	c.bytes, err = CanonicalCohortBytes(c.network, c.era, c.lifetimes, c.transfers)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (c *CompiledCohort) NetworkKey() Digest  { return c.network }
func (c *CompiledCohort) Era() ModelEra       { return c.era }
func (c *CompiledCohort) CohortID() string    { return c.cohortID }
func (c *CompiledCohort) RawDigest() Digest   { return c.rawDigest }
func (c *CompiledCohort) Digest() Digest      { return c.digest }
func (c *CompiledCohort) CanonicalBytes() int { return c.bytes }
func (c *CompiledCohort) Lifetimes() ([]Lifetime, []Digest) {
	out := make([]Lifetime, len(c.lifetimes))
	for i, l := range c.lifetimes {
		out[i] = l.Detached()
	}
	return out, append([]Digest(nil), c.lifeIDs...)
}
func (c *CompiledCohort) Transfers() ([]Transfer, []Digest) {
	out := make([]Transfer, len(c.transfers))
	for i, t := range c.transfers {
		out[i] = t.Detached()
	}
	return out, append([]Digest(nil), c.transferIDs...)
}
