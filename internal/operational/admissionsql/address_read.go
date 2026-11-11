package admissionsql

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5"
	a "privacy-proxy/internal/admission"
	f "privacy-proxy/internal/creationfacts"
)

// AddressReader borrows the actual facts-role Store and its existing pool.
// Its binding comes independently from startup assembly, never from a read.
type AddressReader struct {
	store *Store
	meta  f.AddressReaderMetadata
}

func NewAddressReader(store *Store, binding f.AddressReadBinding) (*AddressReader, error) {
	if store == nil || store.pool == nil || store.mode != "facts" || store.schemaVersion != 3 || !binding.Valid() {
		return nil, a.ErrInvalid
	}
	// Recompute the same strong network tuple used by admission. Source
	// metadata with a caller-chosen key cannot substitute another deployment.
	n := binding.Network
	key, err := (a.NetworkBinding{Environment: n.Environment, ChainID: n.ChainID, GenesisHash: n.Genesis.Hex(), DeploymentID: n.Deployment}).Key()
	if err != nil || f.Digest(key) != n.Key {
		return nil, a.ErrInvalid
	}
	return &AddressReader{store, f.AddressReaderMetadata{Binding: binding, Identity: f.NewAddressReaderIdentity()}}, nil
}
func (r *AddressReader) Metadata() f.AddressReaderMetadata {
	if r == nil {
		return f.AddressReaderMetadata{}
	}
	return r.meta
}

// Null coverage fields on an outer-joined empty candidate must be distinguishable
// from a present malformed row. pgx's pointer-to-pointer destinations retain
// that distinction without fabricating defaults or weakening coverageScan.
func nullableAddressCoverage(scan *coverageScan) ([]any, func() bool) {
	destinations := scan.destinations()
	wrapped := make([]any, len(destinations))
	for i, destination := range destinations {
		wrapped[i] = reflect.New(reflect.TypeOf(destination)).Interface()
	}
	return wrapped, func() bool {
		for i, destination := range destinations {
			value := reflect.ValueOf(wrapped[i]).Elem()
			if value.IsNil() {
				return false
			}
			reflect.ValueOf(destination).Elem().Set(value.Elem())
		}
		return true
	}
}

type addressCurrentScan struct {
	environment, chain, deployment, generation, epoch, quarantine string
	genesis, coverage, source, reference, floorHash, headHash     []byte
	ready, observerReady                                          bool
	reorg                                                         int64
	floor, head                                                   uint64
	floorTime, headTime                                           string
}

func (s *addressCurrentScan) destinations() []any {
	return []any{&s.environment, &s.chain, &s.genesis, &s.deployment, &s.generation, &s.coverage, &s.ready, &s.observerReady, &s.epoch, &s.quarantine, &s.reorg, &s.source, &s.reference, &s.floor, &s.floorHash, &s.floorTime, &s.head, &s.headHash, &s.headTime}
}
func (s addressCurrentScan) valid(b f.AddressReadBinding) bool {
	ft, e1 := strconv.ParseUint(s.floorTime, 10, 64)
	ht, e2 := strconv.ParseUint(s.headTime, 10, 64)
	return e1 == nil && e2 == nil && ft <= ht && s.ready && s.observerReady && s.quarantine == "none" && f.UUID(s.epoch) && s.reorg >= 0 &&
		s.environment == b.Network.Environment && s.chain == b.Network.ChainID && s.deployment == b.Network.Deployment && len(s.genesis) == 32 && common.BytesToHash(s.genesis) == b.Network.Genesis && s.generation == b.State.Generation && len(s.coverage) == 32 && bytes.Equal(s.coverage, b.State.Coverage[:]) &&
		len(s.source) == 32 && bytes.Equal(s.source, b.SourceSet[:]) && len(s.reference) == 32 && bytes.Equal(s.reference, b.Reference[:]) && s.head >= s.floor && len(s.floorHash) == 32 && common.BytesToHash(s.floorHash) != (common.Hash{}) && len(s.headHash) == 32 && common.BytesToHash(s.headHash) != (common.Hash{})
}

type addressCandidateScan struct {
	address, creator, inclusion, transaction, output, proof, seed, qualification, anchor, plan, manifest, runtime           []byte
	number                                                                                                                  *uint64
	index                                                                                                                   *uint32
	record, length, entry, factoryRoot                                                                                      *int
	kind, namespace, authority, walletActor, referenceKind, referenceActor, referenceOrg, profile, anchorNumber, anchorTime *string
	branch                                                                                                                  *uint8
	anchorCanonical, birthCanonical, revoked                                                                                bool
}

func (s *addressCandidateScan) destinations() []any {
	return []any{&s.address, &s.creator, &s.kind, &s.number, &s.inclusion, &s.transaction, &s.index, &s.record, &s.output, &s.length, &s.proof,
		&s.namespace, &s.authority, &s.walletActor, &s.factoryRoot, &s.seed, &s.entry, &s.qualification, &s.referenceKind, &s.referenceActor, &s.referenceOrg, &s.profile, &s.anchor, &s.anchorNumber, &s.anchorTime, &s.plan, &s.manifest, &s.runtime, &s.branch, &s.anchorCanonical, &s.birthCanonical, &s.revoked}
}
func (s addressCandidateScan) finish(target common.Address, current addressCurrentScan, coverage f.CoverageRecord) (f.AddressAssociation, error) {
	bad := func() (f.AddressAssociation, error) { return f.AddressAssociation{}, a.ErrCoverage }
	if len(s.address) != 20 || common.BytesToAddress(s.address) != target || len(s.creator) != 20 || s.kind == nil || s.number == nil || s.index == nil || s.record == nil || s.length == nil || s.entry == nil || s.namespace == nil || s.authority == nil || s.referenceKind == nil || s.profile == nil || s.anchorNumber == nil || s.anchorTime == nil || s.branch == nil || !s.anchorCanonical || !s.birthCanonical || s.revoked {
		return bad()
	}
	for _, b := range [][]byte{s.inclusion, s.transaction, s.output, s.proof, s.seed, s.qualification, s.anchor, s.plan, s.manifest, s.runtime} {
		if len(b) != 32 {
			return bad()
		}
	}
	anchorNumber, e1 := strconv.ParseUint(*s.anchorNumber, 10, 64)
	anchorTime, e2 := strconv.ParseUint(*s.anchorTime, 10, 64)
	if e1 != nil || e2 != nil || anchorNumber < current.floor || *s.number > current.head || anchorNumber >= *s.number || *s.authority != *s.referenceKind {
		return bad()
	}
	actor := ""
	switch *s.authority {
	case "WALLET":
		if s.walletActor == nil || s.referenceActor == nil || s.referenceOrg == nil || *s.walletActor != *s.referenceActor || *s.namespace != *s.referenceOrg || s.factoryRoot != nil {
			return bad()
		}
		actor = *s.walletActor
	case "FACTORY":
		if s.walletActor != nil || s.factoryRoot == nil || *s.factoryRoot < 0 || *s.factoryRoot >= 128 {
			return bad()
		}
	default:
		return bad()
	}
	return f.AddressAssociation{Namespace: *s.namespace, Kind: *s.authority, WalletActor: actor, Address: target, Creator: common.BytesToAddress(s.creator), CreationKind: *s.kind, Record: *s.record, Index: *s.index, Inclusion: f.Header{Number: *s.number, Hash: common.BytesToHash(s.inclusion)}, TransactionHash: common.BytesToHash(s.transaction), OutputHash: common.BytesToHash(s.output), Proof: common.BytesToHash(s.proof), OutputLength: *s.length, Seed: f.Digest(common.BytesToHash(s.seed)), Plan: f.Digest(common.BytesToHash(s.plan)), Manifest: f.Digest(common.BytesToHash(s.manifest)), Runtime: f.Digest(common.BytesToHash(s.runtime)), Qualification: f.Digest(common.BytesToHash(s.qualification)), PlannedEntry: *s.entry, Branch: *s.branch, OriginalProfile: *s.profile, OriginalAnchor: f.Header{Number: anchorNumber, Hash: common.BytesToHash(s.anchor), Timestamp: anchorTime}, OriginalCoverage: coverage}, nil
}

func (r *AddressReader) ReadAddressAssociations(ctx context.Context, target common.Address) (*f.AddressAssociations, error) {
	if r == nil || r.store == nil || ctx == nil || !r.meta.Binding.Valid() || r.meta.Identity == nil {
		return nil, a.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, r.meta.Binding.Limits.Timeout)
	defer cancel()
	b := r.meta.Binding
	// The OUTER join returns current metadata even for genuinely empty target
	// candidates. Every PRESENT broken join remains a candidate and is denied.
	query := `SELECT n.environment,n.chain_id,n.genesis_hash,n.deployment_id,n.generation::text,n.coverage_digest,n.ready,
 o.ready,o.observer_epoch::text,o.quarantine,o.reorg_epoch,o.source_set_digest,o.reference_binding_digest,
 fh.number,fh.hash,fh.timestamp::text,hh.number,hh.hash,hh.timestamp::text,
 x.address,x.creator,x.creation_kind,x.inclusion_number,x.inclusion_hash,x.tx_hash,x.tx_index,x.actual_creation_record,x.output_hash,x.output_length,x.proof_digest,
 x.namespace,x.authority_kind,x.wallet_actor,x.factory_root,x.seed_digest,x.planned_entry,x.qualification_digest,x.reference_kind,x.reference_actor,x.reference_org,x.reference_profile,x.anchor_hash,x.anchor_number,x.anchor_timestamp,x.plan_digest,x.manifest_digest,x.runtime_digest,x.branch,COALESCE(x.anchor_canonical,false),COALESCE(x.birth_canonical,false),COALESCE(x.revoked,false),
 ` + namespaceQualifiedColumns(coverageColumns, "x") + `
 FROM ops_admission_v2.network_state n
 JOIN ops_admission_v2.creation_observer_state o USING(network_key)
 JOIN ops_admission_v2.creation_headers fh ON fh.network_key=o.network_key AND fh.number=o.floor_number AND fh.hash=o.floor_hash
 JOIN ops_admission_v2.creation_headers hh ON hh.network_key=o.network_key AND hh.number=o.head_number AND hh.hash=o.head_hash
 LEFT JOIN LATERAL(
 SELECT b.address,b.creator,b.kind AS creation_kind,b.inclusion_number,b.inclusion_hash,b.tx_hash,b.tx_index,b.actual_creation_record,b.output_hash,b.output_length,b.proof_digest,
 a.namespace::text,a.kind AS authority_kind,a.wallet_actor,a.factory_root,a.seed_digest,a.planned_entry,a.qualification_digest,r.kind AS reference_kind,r.wallet_actor AS reference_actor,r.wallet_org::text AS reference_org,r.evidence_profile AS reference_profile,r.anchor_hash,r.anchor_number::text AS anchor_number,r.anchor_timestamp::text AS anchor_timestamp,r.plan_digest,r.manifest_digest,r.runtime_digest,r.branch,
 (ah.hash IS NOT NULL AND ah.timestamp=r.anchor_timestamp)AS anchor_canonical,(bh.hash IS NOT NULL)AS birth_canonical,(d.capture_epoch IS NOT NULL)AS revoked,
 ` + namespaceQualifiedColumns(coverageColumns, "c") + `
 FROM ops_admission_v2.creation_births b
 LEFT JOIN ops_admission_v2.creation_authority_associations a USING(network_key,tx_hash,inclusion_hash,actual_creation_record)
 LEFT JOIN ops_admission_v2.creation_authority_refs r USING(network_key,tx_hash,seed_digest)
 LEFT JOIN ops_admission_v2.creation_capture_coverage c USING(network_key,tx_hash,seed_digest)
 LEFT JOIN ops_admission_v2.revoked_creation_capture_epochs d ON d.network_key=c.network_key AND d.capture_epoch=c.capture_epoch
 LEFT JOIN ops_admission_v2.creation_headers ah ON ah.network_key=r.network_key AND ah.number=r.anchor_number AND ah.hash=r.anchor_hash
 LEFT JOIN ops_admission_v2.creation_headers bh ON bh.network_key=b.network_key AND bh.number=b.inclusion_number AND bh.hash=b.inclusion_hash
 WHERE b.network_key=n.network_key AND b.address=$2 ORDER BY b.inclusion_hash,b.actual_creation_record,a.seed_digest,a.planned_entry LIMIT $3
 )x ON true WHERE n.network_key=$1`
	rows, err := r.store.pool.Query(ctx, query, pgx.QueryExecModeExec, b.Network.Key[:], target[:], b.Limits.MaxCandidates+1)
	if err != nil {
		return nil, a.ErrUnavailable
	}
	defer rows.Close()
	var first addressCurrentScan
	facts := []f.AddressAssociation{}
	totalBytes := 0
	seen := false
	for rows.Next() {
		var current addressCurrentScan
		var candidate addressCandidateScan
		var coverage coverageScan
		coverageDest, coveragePresent := nullableAddressCoverage(&coverage)
		dest := append(current.destinations(), candidate.destinations()...)
		dest = append(dest, coverageDest...)
		if rows.Scan(dest...) != nil || !current.valid(b) {
			return nil, a.ErrUnavailable
		}
		if !seen {
			first = current
			seen = true
		}
		if len(candidate.address) == 0 {
			continue
		}
		if len(facts) >= b.Limits.MaxCandidates || !coveragePresent() {
			return nil, a.ErrCoverage
		}
		original, err := coverage.finish()
		if err != nil {
			return nil, a.ErrCoverage
		}
		fact, err := candidate.finish(target, current, original)
		if err != nil {
			return nil, err
		}
		raw, err := json.Marshal(fact)
		if err != nil || len(raw) > b.Limits.MaxBytes-totalBytes {
			return nil, a.ErrCoverage
		}
		totalBytes += len(raw)
		facts = append(facts, fact)
	}
	if rows.Err() != nil || ctx.Err() != nil || !seen {
		return nil, a.ErrUnavailable
	}
	pass, err := f.NewAddressAssociations(r.meta.Identity, b, target, first.epoch, first.reorg, f.Header{Number: first.head, Hash: common.BytesToHash(first.headHash)}, facts)
	if err != nil {
		return nil, a.ErrCoverage
	}
	return pass, nil
}
func (r *AddressReader) RecheckAddressAssociations(ctx context.Context, pass *f.AddressAssociations) error {
	if r == nil || pass == nil || pass.ValidateFor(r.meta.Identity, r.meta.Binding, pass.Target()) != nil {
		return a.ErrInvalid
	}
	current, err := r.ReadAddressAssociations(ctx, pass.Target())
	if err != nil {
		return err
	}
	if !pass.SameCurrent(current) {
		return a.ErrUnavailable
	}
	return nil
}
