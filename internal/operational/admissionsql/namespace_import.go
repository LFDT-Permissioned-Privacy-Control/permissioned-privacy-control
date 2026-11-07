package admissionsql

import (
	"context"
	"slices"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5"
	a "privacy-proxy/internal/admission"
	h "privacy-proxy/internal/historynamespace"
	"privacy-proxy/internal/policycore"
	"privacy-proxy/internal/rpcexecution"
)

type NamespaceImportResult struct {
	CohortID       string
	SemanticDigest h.Digest
	OriginalRaw    h.Digest
	Duplicate      bool
	Revoked        bool
	State          NamespaceExpectedState
	// References follow the submitted artifact's lifetime/transfer split order.
	// They identify original rows; they confer no canonical namespace authority.
	LifetimeIDs      []h.Digest
	LifetimeSegments []h.Digest
	TransferIDs      []h.Digest
	TransferSegments []h.Digest
}

type namespaceCohortRecord struct {
	ID                string
	Semantic, Raw     h.Digest
	Statements, Bytes int
	Revoked           bool
	Lifetimes         []h.Lifetime
	LifeIDs           []h.Digest
	Transfers         []h.Transfer
	TransferIDs       []h.Digest
}

// This bounds metadata considered by one owner operation; a large adversarial
// artifact may be split rather than expanding into an unbounded fact scan.
const namespaceImportCandidates = 32768

func readNamespaceCohort(ctx context.Context, tx pgx.Tx, network h.Digest, era h.ModelEra, id string) (*namespaceCohortRecord, error) {
	r := &namespaceCohortRecord{ID: id}
	var semantic, raw []byte
	if tx.QueryRow(ctx, `SELECT semantic_digest,first_raw_artifact_digest,statement_count,canonical_bytes,EXISTS(SELECT 1 FROM ops_history_namespace_v1.revoked_namespace_cohorts d WHERE d.network_key=c.network_key AND d.cohort_id=c.cohort_id)FROM ops_history_namespace_v1.namespace_cohorts c WHERE network_key=$1 AND cohort_id=$2::uuid`, network[:], id).Scan(&semantic, &raw, &r.Statements, &r.Bytes, &r.Revoked) != nil {
		return nil, h.ErrUnavailable
	}
	var ok bool
	if r.Semantic, ok = namespaceDigest(semantic); !ok {
		return nil, h.ErrUnavailable
	}
	if r.Raw, ok = namespaceDigest(raw); !ok || r.Statements < 1 || r.Statements > h.MaxStatements || r.Bytes < 1 || r.Bytes > h.MaxArtifactBytes {
		return nil, h.ErrUnavailable
	}
	rows, err := tx.Query(ctx, `SELECT `+namespaceLifetimeColumns+` FROM ops_history_namespace_v1.legacy_contract_lifetimes WHERE network_key=$1 AND cohort_id=$2::uuid ORDER BY statement_digest LIMIT 4097`, network[:], id)
	if err != nil {
		return nil, h.ErrUnavailable
	}
	for rows.Next() {
		if len(r.Lifetimes) >= h.MaxStatements {
			rows.Close()
			return nil, h.ErrTooBroad
		}
		l, digest, cohort, err := scanNamespaceLifetime(rows, network, era)
		if err != nil || cohort != id {
			rows.Close()
			return nil, h.ErrUnavailable
		}
		r.Lifetimes, r.LifeIDs = append(r.Lifetimes, l), append(r.LifeIDs, digest)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, h.ErrUnavailable
	}
	rows, err = tx.Query(ctx, `SELECT `+namespaceTransferColumns+` FROM ops_history_namespace_v1.namespace_transfers WHERE network_key=$1 AND cohort_id=$2::uuid ORDER BY transfer_digest LIMIT 4097`, network[:], id)
	if err != nil {
		return nil, h.ErrUnavailable
	}
	for rows.Next() {
		if len(r.Transfers)+len(r.Lifetimes) >= h.MaxStatements {
			rows.Close()
			return nil, h.ErrTooBroad
		}
		t, digest, cohort, err := scanNamespaceTransfer(rows, network, era)
		if err != nil || cohort != id {
			rows.Close()
			return nil, h.ErrUnavailable
		}
		r.Transfers, r.TransferIDs = append(r.Transfers, t), append(r.TransferIDs, digest)
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(r.Lifetimes)+len(r.Transfers) != r.Statements {
		return nil, h.ErrUnavailable
	}
	semanticID, err := h.CohortDigest(network, era, r.LifeIDs, r.TransferIDs)
	if err != nil || semanticID != r.Semantic {
		return nil, h.ErrUnavailable
	}
	counted, err := h.CanonicalCohortBytes(network, era, r.Lifetimes, r.Transfers)
	if err != nil || counted != r.Bytes {
		return nil, h.ErrUnavailable
	}
	return r, nil
}

// ImportNamespace persists approved attestations, not a canonical namespace
// verdict. Only checkpoint runtime is independently node-proved here. C2 must
// qualify actual cuts, alternatives and basis AT every edge before authority.
func ImportNamespace(ctx context.Context, dsn string, binding a.NetworkBinding, expected NamespaceExpectedState, path string, approvedRaw h.Digest, proof *rpcexecution.NamespaceCheckpointProof, acknowledgeDrained bool) (NamespaceImportResult, error) {
	var result NamespaceImportResult
	if ctx == nil || !acknowledgeDrained || !expected.valid() {
		return result, h.ErrInvalid
	}
	artifact, err := h.ReadApprovedArtifact(path, approvedRaw)
	if err != nil {
		return result, err
	}
	key, _, err := bindingValues(binding)
	if err != nil || h.Digest(key) != artifact.NetworkKey() {
		return result, h.ErrInvalid
	}
	var facts *h.CheckpointFacts
	if proof != nil {
		f := proof.Facts()
		digest, err := h.CheckpointFactsDigest(f)
		if err != nil || digest != proof.Digest() || proof.Source().Profile != rpcexecution.IncludedProfileID {
			return result, h.ErrInvalid
		}
		facts = &f
	}
	compiled, err := artifact.Compile(facts)
	if err != nil {
		return result, err
	}
	semantic := compiled.Digest()
	lifetimes, lifeIDs := compiled.Lifetimes()
	transfers, transferIDs := compiled.Transfers()
	for _, l := range lifetimes {
		if l.Kind != "pre-era-finite" && policycore.IsPraguePrecompile(common.Address(l.Address)) {
			return result, h.ErrInvalid
		}
	}
	err = namespaceOffline(ctx, dsn, binding, 60*time.Second, func(ctx context.Context, tx pgx.Tx, network h.Digest) error {
		m, err := lockNamespaceState(ctx, tx, network, expected)
		if err != nil {
			return err
		}
		if m.State.Generation != m.BaseGeneration || m.Era != compiled.Era() {
			return h.ErrConflict
		}
		// Recognize exact retries before growth checks, even at saturation.
		rows, err := tx.Query(ctx, `SELECT cohort_id::text,semantic_digest FROM ops_history_namespace_v1.namespace_cohorts WHERE network_key=$1 AND(cohort_id=$2::uuid OR semantic_digest=$3)ORDER BY cohort_id LIMIT 2`, network[:], compiled.CohortID(), semantic[:])
		if err != nil {
			return h.ErrUnavailable
		}
		duplicate := ""
		for rows.Next() {
			var id string
			var raw []byte
			if rows.Scan(&id, &raw) != nil {
				rows.Close()
				return h.ErrUnavailable
			}
			digest, ok := namespaceDigest(raw)
			if !ok || digest != compiled.Digest() {
				rows.Close()
				return h.ErrConflict
			}
			duplicate = id
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return h.ErrUnavailable
		}
		if duplicate != "" {
			original, err := readNamespaceCohort(ctx, tx, network, m.Era, duplicate)
			if err != nil {
				return err
			}
			result = NamespaceImportResult{CohortID: original.ID, SemanticDigest: original.Semantic, OriginalRaw: original.Raw, Duplicate: true, Revoked: original.Revoked, State: m.State}
			return nil
		}
		if m.SourceReady {
			return h.ErrConflict
		}
		var overlap bool
		if tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ops_history_namespace_v1.legacy_contract_lifetimes WHERE network_key=$1 AND statement_digest=ANY($2::bytea[]))OR EXISTS(SELECT 1 FROM ops_history_namespace_v1.namespace_transfers WHERE network_key=$1 AND transfer_digest=ANY($3::bytea[]))`, network[:], namespaceDigestArray(lifeIDs), namespaceDigestArray(transferIDs)).Scan(&overlap) != nil || overlap {
			// Five tables give one original cohort FK per statement. Never
			// reparent old/denied rows or silently save only part of a cohort.
			return h.ErrConflict
		}
		if err := validateNamespaceGrowth(ctx, tx, network, m.Limits, lifetimes, transfers); err != nil {
			return err
		}
		if err := validateNamespaceImportGraph(ctx, tx, network, m.Era, lifetimes, lifeIDs, transfers, transferIDs); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO ops_history_namespace_v1.namespace_cohorts(network_key,cohort_id,semantic_digest,first_raw_artifact_digest,statement_count,canonical_bytes,recorded_at)VALUES($1,$2::uuid,$3,$4,$5,$6,$7)`, network[:], compiled.CohortID(), semantic[:], approvedRaw[:], len(lifetimes)+len(transfers), compiled.CanonicalBytes(), time.Now().UTC()); err != nil {
			return h.ErrUnavailable
		}
		if err := insertNamespaceStatements(ctx, tx, network, compiled.CohortID(), lifetimes, lifeIDs, transfers, transferIDs); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE ops_history_namespace_v1.namespace_network_state SET lifetime_count=lifetime_count+$2,transfer_count=transfer_count+$3,cohort_count=cohort_count+1,revision=revision+1 WHERE network_key=$1 AND revision=$4`, network[:], len(lifetimes), len(transfers), expected.Revision)
		if err != nil || tag.RowsAffected() != 1 {
			return h.ErrUnavailable
		}
		m.State.Revision++
		result = NamespaceImportResult{CohortID: compiled.CohortID(), SemanticDigest: compiled.Digest(), OriginalRaw: approvedRaw, State: m.State}
		return nil
	})
	if err != nil {
		return NamespaceImportResult{}, err
	}
	result.LifetimeIDs, result.TransferIDs = append([]h.Digest(nil), lifeIDs...), append([]h.Digest(nil), transferIDs...)
	for _, l := range lifetimes {
		result.LifetimeSegments = append(result.LifetimeSegments, l.Segment)
	}
	for _, t := range transfers {
		result.TransferSegments = append(result.TransferSegments, t.Segment)
	}
	return result, nil
}

func namespaceDigestArray(values []h.Digest) [][]byte {
	out := make([][]byte, len(values))
	for i := range values {
		out[i] = values[i][:]
	}
	return out
}

func validateNamespaceGrowth(ctx context.Context, tx pgx.Tx, network h.Digest, limits h.CapacityLimits, lifetimes []h.Lifetime, transfers []h.Transfer) error {
	var lifeCount, transferCount, cohortCount int64
	if tx.QueryRow(ctx, `SELECT lifetime_count,transfer_count,cohort_count FROM ops_history_namespace_v1.namespace_network_state WHERE network_key=$1`, network[:]).Scan(&lifeCount, &transferCount, &cohortCount) != nil {
		return h.ErrUnavailable
	}
	if lifeCount > limits.Lifetimes-int64(len(lifetimes)) || transferCount > limits.Transfers-int64(len(transfers)) || cohortCount >= limits.Cohorts {
		return h.ErrTooBroad
	}
	addresses := map[h.Address]int{}
	for _, l := range lifetimes {
		addresses[l.Address]++
	}
	for address, growth := range addresses {
		var count int
		if tx.QueryRow(ctx, `SELECT count(*)FROM ops_history_namespace_v1.legacy_contract_lifetimes WHERE network_key=$1 AND address=$2`, network[:], address[:]).Scan(&count) != nil {
			return h.ErrUnavailable
		}
		if count > limits.LifetimesPerAddress-growth {
			return h.ErrTooBroad
		}
	}
	segments := map[h.Digest]int{}
	for _, t := range transfers {
		segments[t.Segment]++
	}
	for segment, growth := range segments {
		var count int
		if tx.QueryRow(ctx, `SELECT count(*)FROM ops_history_namespace_v1.namespace_transfers WHERE network_key=$1 AND segment_key=$2`, network[:], segment[:]).Scan(&count) != nil {
			return h.ErrUnavailable
		}
		if count > limits.TransfersPerSegment-growth {
			return h.ErrTooBroad
		}
	}
	return nil
}

func validateNamespaceImportGraph(ctx context.Context, tx pgx.Tx, network h.Digest, era h.ModelEra, lifetimes []h.Lifetime, lifeIDs []h.Digest, transfers []h.Transfer, transferIDs []h.Digest) error {
	type originalKey struct {
		Address h.Address
		Segment h.Digest
		Label   string
	}
	labelKey := func(l h.Label) string {
		if l.OrganizationID != nil {
			return l.Kind + ":" + *l.OrganizationID
		}
		return l.Kind
	}
	presentOriginals := map[originalKey]bool{}
	lives := map[h.Digest]h.Lifetime{}
	for i, l := range lifetimes {
		lives[lifeIDs[i]] = l
		if l.Kind != "pre-era-finite" {
			presentOriginals[originalKey{l.Address, l.Segment, labelKey(l.Initial)}] = true
		}
	}
	edges := map[h.Digest]h.Transfer{}
	for i, t := range transfers {
		edges[transferIDs[i]] = t
	}
	work := 0
	getEdge := func(id h.Digest) (h.Transfer, error) {
		if t, ok := edges[id]; ok {
			return t, nil
		}
		work++
		if work > namespaceImportCandidates {
			return h.Transfer{}, h.ErrTooBroad
		}
		t, _, _, err := scanNamespaceTransfer(tx.QueryRow(ctx, `SELECT `+namespaceTransferColumns+` FROM ops_history_namespace_v1.namespace_transfers WHERE network_key=$1 AND transfer_digest=$2`, network[:], id[:]), network, era)
		if err == nil {
			edges[id] = t
		}
		return t, err
	}
	for _, t := range transfers {
		if t.SegmentKind == "legacy" {
			l, exists := lives[*t.LegacyBasis]
			if !exists {
				work++
				if work > namespaceImportCandidates {
					return h.ErrTooBroad
				}
				var err error
				l, _, _, err = scanNamespaceLifetime(tx.QueryRow(ctx, `SELECT `+namespaceLifetimeColumns+` FROM ops_history_namespace_v1.legacy_contract_lifetimes WHERE network_key=$1 AND statement_digest=$2`, network[:], (*t.LegacyBasis)[:]), network, era)
				if err != nil {
					return h.ErrConflict
				}
				lives[*t.LegacyBasis] = l
			}
			if l.Kind != "pre-era-finite" || l.Address != t.Address || l.Segment != t.Segment || !l.Initial.Equal(t.Initial) {
				return h.ErrConflict
			}
		} else {
			present := presentOriginals[originalKey{t.Address, t.Segment, labelKey(t.Initial)}]
			if !present {
				rows, err := tx.Query(ctx, `SELECT `+namespaceLifetimeColumns+` FROM ops_history_namespace_v1.legacy_contract_lifetimes WHERE network_key=$1 AND address=$2 AND segment_key=$3 ORDER BY statement_digest LIMIT 33`, network[:], t.Address[:], t.Segment[:])
				if err != nil {
					return h.ErrUnavailable
				}
				for rows.Next() {
					work++
					l, _, _, err := scanNamespaceLifetime(rows, network, era)
					if err != nil || work > namespaceImportCandidates {
						rows.Close()
						return h.ErrTooBroad
					}
					present = present || l.Kind != "pre-era-finite" && l.Initial.Equal(t.Initial)
				}
				err = rows.Err()
				rows.Close()
				if err != nil {
					return h.ErrUnavailable
				}
			}
			if !present && t.Initial.Kind == "org" {
				// Presence is not canonical/eligible authority. The later C2
				// pass must qualify original coverage, all alternatives and
				// the basis AT each edge; never infer that from this query.
				rows, err := tx.Query(ctx, `SELECT DISTINCT b.output_hash,b.output_length,a.namespace::text FROM ops_admission_v2.creation_births b JOIN ops_admission_v2.creation_authority_associations a USING(network_key,tx_hash,inclusion_hash,actual_creation_record)WHERE b.network_key=$1 AND b.address=$2 ORDER BY b.output_hash,b.output_length,a.namespace::text LIMIT 2049`, network[:], t.Address[:])
				if err != nil {
					return h.ErrUnavailable
				}
				for rows.Next() {
					work++
					var raw []byte
					var length uint32
					var org string
					if rows.Scan(&raw, &length, &org) != nil || work > namespaceImportCandidates {
						rows.Close()
						return h.ErrTooBroad
					}
					hash, ok := namespaceHash(raw)
					segment, err := h.PragueSegmentKey(network, t.Address, hash, length)
					if !ok || err != nil || !h.UUID(org) {
						rows.Close()
						return h.ErrUnavailable
					}
					present = present || segment == t.Segment && org == *t.Initial.OrganizationID
				}
				err = rows.Err()
				rows.Close()
				if err != nil {
					return h.ErrUnavailable
				}
			}
			if !present {
				return h.ErrConflict
			}
			presentOriginals[originalKey{t.Address, t.Segment, labelKey(t.Initial)}] = true
		}
		current := t
		for depth := 0; ; depth++ {
			if depth >= 64 {
				return h.ErrTooBroad
			}
			if current.Parent == nil {
				if !current.Previous.Equal(current.Initial) {
					return h.ErrConflict
				}
				break
			}
			parent, err := getEdge(*current.Parent)
			if err != nil || parent.Address != current.Address || parent.SegmentKind != current.SegmentKind || parent.Segment != current.Segment || !parent.Initial.Equal(current.Initial) || !parent.New.Equal(current.Previous) || h.CompareCuts(parent.EffectiveFrom, current.EffectiveFrom) >= 0 || parent.EffectiveFrom.Number == current.EffectiveFrom.Number && parent.EffectiveFrom.Hash != current.EffectiveFrom.Hash {
				return h.ErrConflict
			}
			current = parent
		}
	}
	return nil
}

func insertNamespaceStatements(ctx context.Context, tx pgx.Tx, network h.Digest, cohort string, lifetimes []h.Lifetime, lifeIDs []h.Digest, transfers []h.Transfer, transferIDs []h.Digest) error {
	batch := &pgx.Batch{}
	flush := func() error {
		if batch.Len() == 0 {
			return nil
		}
		count := batch.Len()
		results := tx.SendBatch(ctx, batch)
		for range count {
			if tag, err := results.Exec(); err != nil || tag.RowsAffected() != 1 {
				_ = results.Close()
				return h.ErrUnavailable
			}
		}
		if results.Close() != nil {
			return h.ErrUnavailable
		}
		batch = &pgx.Batch{}
		return nil
	}
	for i, l := range lifetimes {
		batch.Queue(`INSERT INTO ops_history_namespace_v1.legacy_contract_lifetimes(network_key,statement_digest,cohort_id,address,evidence_kind,segment_key,lifetime_id,runtime_hash,runtime_length,initial_kind,initial_org,physical_kind,birth_number,birth_hash,birth_tx_hash,birth_index,birth_record,start_number,start_hash,start_index,end_number,end_hash,end_index,checkpoint_number,checkpoint_hash,proof_digest)VALUES($1,$2,$3::uuid,$4,$5,$6,$7::uuid,$8,$9,$10,$11::uuid,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26)`, namespaceLifetimeArgs(network, lifeIDs[i], cohort, l)...)
		if batch.Len() == 128 {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	if err := flush(); err != nil {
		return err
	}
	order := make([]int, len(transfers))
	for i := range order {
		order[i] = i
	}
	slices.SortFunc(order, func(a, b int) int { return h.CompareCuts(transfers[a].EffectiveFrom, transfers[b].EffectiveFrom) })
	for _, i := range order {
		batch.Queue(`INSERT INTO ops_history_namespace_v1.namespace_transfers(network_key,transfer_digest,cohort_id,address,segment_kind,segment_key,legacy_basis_digest,initial_kind,initial_org,parent_digest,previous_kind,previous_org,new_kind,new_org,effective_number,effective_hash,effective_index)VALUES($1,$2,$3::uuid,$4,$5,$6,$7,$8,$9::uuid,$10,$11,$12::uuid,$13,$14::uuid,$15,$16,$17)`, namespaceTransferArgs(network, transferIDs[i], cohort, transfers[i])...)
		if batch.Len() == 128 {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	return flush()
}
