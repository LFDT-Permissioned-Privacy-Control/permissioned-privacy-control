package admissionsql

import (
	"privacy-proxy/internal/historynamespace"
)

type namespaceScanner interface{ Scan(...any) error }

const namespaceLifetimeColumns = `statement_digest,cohort_id::text,address,evidence_kind,segment_key,lifetime_id::text,runtime_hash,runtime_length,initial_kind,initial_org::text,physical_kind,birth_number,birth_hash,birth_tx_hash,birth_index,birth_record,start_number,start_hash,start_index,end_number,end_hash,end_index,checkpoint_number,checkpoint_hash,proof_digest`
const namespaceTransferColumns = `transfer_digest,cohort_id::text,address,segment_kind,segment_key,legacy_basis_digest,initial_kind,initial_org::text,parent_digest,previous_kind,previous_org::text,new_kind,new_org::text,effective_number,effective_hash,effective_index`

func namespaceLabel(kind int16, organization *string) (historynamespace.Label, bool) {
	l := historynamespace.Label{OrganizationID: organization}
	switch kind {
	case 1:
		l.Kind = "org"
	case 2:
		l.Kind = "public"
	default:
		return l, false
	}
	return l, l.Valid()
}

func namespaceLabelArgs(l historynamespace.Label) (int16, any) {
	if l.Kind == "org" && l.OrganizationID != nil {
		return 1, *l.OrganizationID
	}
	return 2, nil
}

func namespaceDigest(raw []byte) (historynamespace.Digest, bool) {
	var d historynamespace.Digest
	if len(raw) != 32 {
		return d, false
	}
	copy(d[:], raw)
	return d, d != (historynamespace.Digest{})
}
func namespaceHash(raw []byte) (historynamespace.Hash, bool) {
	d, ok := namespaceDigest(raw)
	return historynamespace.Hash(d), ok
}
func nullableNamespaceDigest(raw []byte) (*historynamespace.Digest, bool) {
	if raw == nil {
		return nil, true
	}
	d, ok := namespaceDigest(raw)
	return &d, ok
}

func namespaceCut(number *uint64, hash []byte, index *uint32) (*historynamespace.Cut, bool) {
	if number == nil && hash == nil && index == nil {
		return nil, true
	}
	if number == nil || index == nil {
		return nil, false
	}
	h, ok := namespaceHash(hash)
	cut := &historynamespace.Cut{Number: *number, Hash: h, Index: *index}
	return cut, ok && cut.Valid()
}

func scanNamespaceLifetime(row namespaceScanner, network historynamespace.Digest, era historynamespace.ModelEra) (historynamespace.Lifetime, historynamespace.Digest, string, error) {
	var l historynamespace.Lifetime
	var digest, address, segment, runtime, birthHash, birthTx, startHash, endHash, checkpointHash, proof []byte
	var cohort string
	var kind, initialKind, physicalKind int16
	var organization *string
	var birthNumber, startNumber, endNumber, checkpointNumber *uint64
	var birthIndex, birthRecord, startIndex, endIndex *uint32
	if row.Scan(&digest, &cohort, &address, &kind, &segment, &l.LifetimeID, &runtime, &l.RuntimeLength, &initialKind, &organization, &physicalKind, &birthNumber, &birthHash, &birthTx, &birthIndex, &birthRecord,
		&startNumber, &startHash, &startIndex, &endNumber, &endHash, &endIndex, &checkpointNumber, &checkpointHash, &proof) != nil || len(address) != 20 || !historynamespace.UUID(cohort) {
		return l, historynamespace.Digest{}, "", historynamespace.ErrUnavailable
	}
	id, ok := namespaceDigest(digest)
	if !ok {
		return l, id, "", historynamespace.ErrUnavailable
	}
	copy(l.Address[:], address)
	if l.Segment, ok = namespaceDigest(segment); !ok {
		return l, id, "", historynamespace.ErrUnavailable
	}
	if l.RuntimeHash, ok = namespaceHash(runtime); !ok {
		return l, id, "", historynamespace.ErrUnavailable
	}
	if l.Initial, ok = namespaceLabel(initialKind, organization); !ok {
		return l, id, "", historynamespace.ErrUnavailable
	}
	switch kind {
	case 1:
		l.Kind = "pre-era-finite"
	case 2:
		l.Kind = "prague-finite"
	case 3:
		l.Kind = "prague-checkpoint"
	default:
		return l, id, "", historynamespace.ErrUnavailable
	}
	if physicalKind == 2 {
		if birthNumber == nil || birthIndex == nil || birthRecord == nil {
			return l, id, "", historynamespace.ErrUnavailable
		}
		bh, goodHash := namespaceHash(birthHash)
		bt, goodTx := namespaceHash(birthTx)
		if !goodHash || !goodTx {
			return l, id, "", historynamespace.ErrUnavailable
		}
		l.Physical = &historynamespace.PhysicalStart{Kind: "born", Birth: &historynamespace.BirthCoordinate{Number: *birthNumber, Hash: bh, TransactionHash: bt, Index: *birthIndex, Record: *birthRecord}}
	} else {
		if birthNumber != nil || birthHash != nil || birthTx != nil || birthIndex != nil || birthRecord != nil {
			return l, id, "", historynamespace.ErrUnavailable
		}
		switch physicalKind {
		case 0:
		case 1:
			l.Physical = &historynamespace.PhysicalStart{Kind: "preexisting"}
		default:
			return l, id, "", historynamespace.ErrUnavailable
		}
	}
	if l.Start, ok = namespaceCut(startNumber, startHash, startIndex); !ok {
		return l, id, "", historynamespace.ErrUnavailable
	}
	if l.End, ok = namespaceCut(endNumber, endHash, endIndex); !ok {
		return l, id, "", historynamespace.ErrUnavailable
	}
	if checkpointNumber != nil {
		hash, valid := namespaceHash(checkpointHash)
		if !valid {
			return l, id, "", historynamespace.ErrUnavailable
		}
		l.Checkpoint = &historynamespace.CheckpointRef{Number: *checkpointNumber, Hash: hash}
	} else if checkpointHash != nil {
		return l, id, "", historynamespace.ErrUnavailable
	}
	if l.ProofDigest, ok = nullableNamespaceDigest(proof); !ok {
		return l, id, "", historynamespace.ErrUnavailable
	}
	actual, err := historynamespace.LifetimeDigest(network, era, l)
	if err != nil || actual != id {
		return l, id, "", historynamespace.ErrUnavailable
	}
	return l, id, cohort, nil
}

func scanNamespaceTransfer(row namespaceScanner, network historynamespace.Digest, era historynamespace.ModelEra) (historynamespace.Transfer, historynamespace.Digest, string, error) {
	var t historynamespace.Transfer
	var digest, address, segment, legacy, parent, hash []byte
	var cohort string
	var kind, initialKind, previousKind, newKind int16
	var initialOrg, previousOrg, newOrg *string
	if row.Scan(&digest, &cohort, &address, &kind, &segment, &legacy, &initialKind, &initialOrg, &parent, &previousKind, &previousOrg, &newKind, &newOrg, &t.EffectiveFrom.Number, &hash, &t.EffectiveFrom.Index) != nil || len(address) != 20 || !historynamespace.UUID(cohort) {
		return t, historynamespace.Digest{}, "", historynamespace.ErrUnavailable
	}
	id, ok := namespaceDigest(digest)
	if !ok {
		return t, id, "", historynamespace.ErrUnavailable
	}
	t.Kind = "transfer"
	copy(t.Address[:], address)
	if t.Segment, ok = namespaceDigest(segment); !ok {
		return t, id, "", historynamespace.ErrUnavailable
	}
	if t.LegacyBasis, ok = nullableNamespaceDigest(legacy); !ok {
		return t, id, "", historynamespace.ErrUnavailable
	}
	if t.Parent, ok = nullableNamespaceDigest(parent); !ok {
		return t, id, "", historynamespace.ErrUnavailable
	}
	if t.Initial, ok = namespaceLabel(initialKind, initialOrg); !ok {
		return t, id, "", historynamespace.ErrUnavailable
	}
	if t.Previous, ok = namespaceLabel(previousKind, previousOrg); !ok {
		return t, id, "", historynamespace.ErrUnavailable
	}
	if t.New, ok = namespaceLabel(newKind, newOrg); !ok {
		return t, id, "", historynamespace.ErrUnavailable
	}
	if t.EffectiveFrom.Hash, ok = namespaceHash(hash); !ok {
		return t, id, "", historynamespace.ErrUnavailable
	}
	switch kind {
	case 1:
		t.SegmentKind = "legacy"
	case 2:
		t.SegmentKind = "prague"
	default:
		return t, id, "", historynamespace.ErrUnavailable
	}
	actual, err := historynamespace.TransferDigest(network, era, t)
	if err != nil || actual != id {
		return t, id, "", historynamespace.ErrUnavailable
	}
	return t, id, cohort, nil
}

func namespaceOptionalDigest(d *historynamespace.Digest) any {
	if d == nil {
		return nil
	}
	return d[:]
}

func namespaceLifetimeArgs(network, id historynamespace.Digest, cohort string, l historynamespace.Lifetime) []any {
	kind := int16(1)
	if l.Kind == "prague-finite" {
		kind = 2
	} else if l.Kind == "prague-checkpoint" {
		kind = 3
	}
	initialKind, initialOrg := namespaceLabelArgs(l.Initial)
	var lifetime, birthNumber, birthHash, birthTx, birthIndex, birthRecord, startNumber, startHash, startIndex, endNumber, endHash, endIndex, checkpointNumber, checkpointHash any
	physical := int16(0)
	if l.LifetimeID != nil {
		lifetime = *l.LifetimeID
	}
	if l.Physical != nil {
		physical = 1
		if b := l.Physical.Birth; b != nil {
			physical = 2
			birthNumber, birthHash, birthTx, birthIndex, birthRecord = b.Number, b.Hash[:], b.TransactionHash[:], b.Index, b.Record
		}
	}
	if l.Start != nil {
		startNumber, startHash, startIndex = l.Start.Number, l.Start.Hash[:], l.Start.Index
	}
	if l.End != nil {
		endNumber, endHash, endIndex = l.End.Number, l.End.Hash[:], l.End.Index
	}
	if l.Checkpoint != nil {
		checkpointNumber, checkpointHash = l.Checkpoint.Number, l.Checkpoint.Hash[:]
	}
	return []any{network[:], id[:], cohort, l.Address[:], kind, l.Segment[:], lifetime, l.RuntimeHash[:], l.RuntimeLength, initialKind, initialOrg, physical, birthNumber, birthHash, birthTx, birthIndex, birthRecord,
		startNumber, startHash, startIndex, endNumber, endHash, endIndex, checkpointNumber, checkpointHash, namespaceOptionalDigest(l.ProofDigest)}
}

func namespaceTransferArgs(network, id historynamespace.Digest, cohort string, t historynamespace.Transfer) []any {
	kind := int16(1)
	if t.SegmentKind == "prague" {
		kind = 2
	}
	initialKind, initialOrg := namespaceLabelArgs(t.Initial)
	previousKind, previousOrg := namespaceLabelArgs(t.Previous)
	newKind, newOrg := namespaceLabelArgs(t.New)
	return []any{network[:], id[:], cohort, t.Address[:], kind, t.Segment[:], namespaceOptionalDigest(t.LegacyBasis), initialKind, initialOrg, namespaceOptionalDigest(t.Parent), previousKind, previousOrg, newKind, newOrg, t.EffectiveFrom.Number, t.EffectiveFrom.Hash[:], t.EffectiveFrom.Index}
}
