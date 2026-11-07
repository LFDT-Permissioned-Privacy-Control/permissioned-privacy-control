package admissionsql

import (
	"context"

	"github.com/jackc/pgx/v5"
	a "privacy-proxy/internal/admission"
	h "privacy-proxy/internal/historynamespace"
)

// FinalizeNamespaceRecovery validates all PRESENT supplemental facts. It cannot
// reconstruct missing archives, historical runtime or original node responses;
// completeness is an explicit drained-operator attestation. Failure leaves the
// earlier Begin's persisted unready state intact.
func FinalizeNamespaceRecovery(ctx context.Context, dsn string, binding a.NetworkBinding, expected NamespaceExpectedState, completeness h.Digest, acknowledgeDrained, acknowledgeComplete bool, timeoutSeconds int64) error {
	timeout, err := h.OfflineTimeout(timeoutSeconds)
	if err != nil || !acknowledgeDrained || !acknowledgeComplete || completeness == (h.Digest{}) || !expected.valid() {
		return h.ErrInvalid
	}
	return namespaceOffline(ctx, dsn, binding, timeout, func(ctx context.Context, tx pgx.Tx, network h.Digest) error {
		m, err := lockNamespaceState(ctx, tx, network, expected)
		if err != nil {
			return err
		}
		if m.BaseGeneration != expected.Generation {
			return h.ErrConflict
		}
		if m.SourceReady {
			if m.Completeness == completeness {
				return nil
			}
			return h.ErrConflict
		}
		if err := validateNamespaceArchive(ctx, tx, network, m); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE ops_history_namespace_v1.namespace_network_state SET ready=true,completeness_digest=$2,revision=revision+1 WHERE network_key=$1 AND revision=$3 AND NOT ready`, network[:], completeness[:], expected.Revision)
		if err != nil || tag.RowsAffected() != 1 {
			return h.ErrUnavailable
		}
		return nil
	})
}

func validateNamespaceArchive(ctx context.Context, tx pgx.Tx, network h.Digest, m NamespaceMetadata) error {
	var lifeCount, transferCount, cohortCount, revokedCount int64
	var counters bool
	if tx.QueryRow(ctx, `SELECT s.lifetime_count,s.transfer_count,s.cohort_count,s.revoked_cohort_count,
 s.lifetime_count=(SELECT count(*)FROM ops_history_namespace_v1.legacy_contract_lifetimes WHERE network_key=$1)
 AND s.transfer_count=(SELECT count(*)FROM ops_history_namespace_v1.namespace_transfers WHERE network_key=$1)
 AND s.cohort_count=(SELECT count(*)FROM ops_history_namespace_v1.namespace_cohorts WHERE network_key=$1)
 AND s.revoked_cohort_count=(SELECT count(*)FROM ops_history_namespace_v1.revoked_namespace_cohorts WHERE network_key=$1)
 FROM ops_history_namespace_v1.namespace_network_state s WHERE s.network_key=$1`, network[:]).Scan(&lifeCount, &transferCount, &cohortCount, &revokedCount, &counters) != nil || !counters || lifeCount > m.Limits.Lifetimes || transferCount > m.Limits.Transfers || cohortCount > m.Limits.Cohorts || revokedCount > m.Limits.RevokedCohorts {
		return h.ErrUnavailable
	}
	var bad bool
	if tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ops_history_namespace_v1.legacy_contract_lifetimes WHERE network_key=$1 GROUP BY address HAVING count(*)>$2)
 OR EXISTS(SELECT 1 FROM ops_history_namespace_v1.namespace_transfers WHERE network_key=$1 GROUP BY segment_key HAVING count(*)>$3)
 OR EXISTS(SELECT 1 FROM ops_history_namespace_v1.revoked_namespace_cohorts r LEFT JOIN ops_history_namespace_v1.namespace_cohorts c USING(network_key,cohort_id)WHERE r.network_key=$1 AND c.cohort_id IS NULL)
 OR EXISTS(SELECT 1 FROM ops_history_namespace_v1.namespace_transfers c LEFT JOIN ops_history_namespace_v1.namespace_transfers p ON p.network_key=c.network_key AND p.transfer_digest=c.parent_digest WHERE c.network_key=$1 AND(
  (c.parent_digest IS NULL AND(c.previous_kind<>c.initial_kind OR c.previous_org IS DISTINCT FROM c.initial_org))OR
  (c.parent_digest IS NOT NULL AND(p.transfer_digest IS NULL OR p.address<>c.address OR p.segment_kind<>c.segment_kind OR p.segment_key<>c.segment_key OR p.initial_kind<>c.initial_kind OR p.initial_org IS DISTINCT FROM c.initial_org OR p.new_kind<>c.previous_kind OR p.new_org IS DISTINCT FROM c.previous_org OR(p.effective_number,p.effective_index)>=(c.effective_number,c.effective_index)OR(p.effective_number=c.effective_number AND p.effective_hash<>c.effective_hash)))))
 OR EXISTS(SELECT 1 FROM ops_history_namespace_v1.namespace_transfers t LEFT JOIN ops_history_namespace_v1.legacy_contract_lifetimes l ON l.network_key=t.network_key AND l.statement_digest=t.legacy_basis_digest WHERE t.network_key=$1 AND t.segment_kind=1 AND(l.statement_digest IS NULL OR l.evidence_kind<>1 OR l.address<>t.address OR l.segment_key<>t.segment_key OR l.initial_kind<>t.initial_kind OR l.initial_org IS DISTINCT FROM t.initial_org))`, network[:], m.Limits.LifetimesPerAddress, m.Limits.TransfersPerSegment).Scan(&bad) != nil || bad {
		return h.ErrUnavailable
	}
	// Strict parent-cut descent validates the full DAG without serializing every
	// ancestor path or issuing a query per ancestor. Every row is hashed below.
	var cursor *string
	var seenLife, seenTransfers, seenCohorts int64
	for {
		rows, err := tx.Query(ctx, `SELECT cohort_id::text FROM ops_history_namespace_v1.namespace_cohorts WHERE network_key=$1 AND($2::uuid IS NULL OR cohort_id>$2::uuid)ORDER BY cohort_id LIMIT 256`, network[:], cursor)
		if err != nil {
			return h.ErrUnavailable
		}
		page := []string{}
		for rows.Next() {
			var id string
			if rows.Scan(&id) != nil || !h.UUID(id) {
				rows.Close()
				return h.ErrUnavailable
			}
			page = append(page, id)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return h.ErrUnavailable
		}
		if len(page) == 0 {
			break
		}
		// Close the pgx page BEFORE any dependent queries. Only one bounded
		// <=4096-row/4MiB cohort is retained at a time, never all payloads.
		for _, id := range page {
			r, err := readNamespaceCohort(ctx, tx, network, m.Era, id)
			if err != nil {
				return err
			}
			seenLife += int64(len(r.Lifetimes))
			seenTransfers += int64(len(r.Transfers))
			seenCohorts++
			if seenLife > lifeCount || seenTransfers > transferCount || seenCohorts > cohortCount {
				return h.ErrUnavailable
			}
		}
		last := page[len(page)-1]
		cursor = &last
	}
	if seenLife != lifeCount || seenTransfers != transferCount || seenCohorts != cohortCount {
		return h.ErrUnavailable
	}
	return validateNamespacePraguePresence(ctx, tx, network)
}

type namespacePresenceKey struct {
	Address h.Address
	Segment h.Digest
	Org     string
}

func validateNamespacePraguePresence(ctx context.Context, tx pgx.Tx, network h.Digest) error {
	var cursorSegment []byte
	var cursorKind int16
	var cursorOrg string
	for {
		// Legacy-backed segments are covered by complete row rehashing. Only
		// unmatched original A2-presence requests require this metadata pass.
		rows, err := tx.Query(ctx, `SELECT DISTINCT t.segment_key,t.address,t.initial_kind,COALESCE(t.initial_org::text,'')FROM ops_history_namespace_v1.namespace_transfers t
 WHERE t.network_key=$1 AND t.segment_kind=2 AND($2::bytea IS NULL OR(t.segment_key,t.initial_kind,COALESCE(t.initial_org::text,''))>($2::bytea,$3::smallint,$4::text))
 AND NOT EXISTS(SELECT 1 FROM ops_history_namespace_v1.legacy_contract_lifetimes l WHERE l.network_key=t.network_key AND l.address=t.address AND l.segment_key=t.segment_key AND l.evidence_kind IN(2,3)AND l.initial_kind=t.initial_kind AND l.initial_org IS NOT DISTINCT FROM t.initial_org)
 ORDER BY t.segment_key,t.initial_kind,COALESCE(t.initial_org::text,'')LIMIT 256`, network[:], cursorSegment, cursorKind, cursorOrg)
		if err != nil {
			return h.ErrUnavailable
		}
		wanted := map[namespacePresenceKey]bool{}
		addresses := map[h.Address]bool{}
		count := 0
		for rows.Next() {
			var segment, address []byte
			var kind int16
			var org string
			if rows.Scan(&segment, &address, &kind, &org) != nil || kind != 1 || !h.UUID(org) || len(address) != 20 {
				rows.Close()
				return h.ErrUnavailable
			}
			digest, ok := namespaceDigest(segment)
			if !ok {
				rows.Close()
				return h.ErrUnavailable
			}
			var a h.Address
			copy(a[:], address)
			wanted[namespacePresenceKey{a, digest, org}] = false
			addresses[a] = true
			cursorSegment, cursorKind, cursorOrg = append([]byte(nil), segment...), kind, org
			count++
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return h.ErrUnavailable
		}
		if count == 0 {
			return nil
		}
		values := make([][]byte, 0, len(addresses))
		for address := range addresses {
			a := address
			values = append(values, a[:])
		}
		rows, err = tx.Query(ctx, `SELECT DISTINCT b.address,b.output_hash,b.output_length,a.namespace::text FROM ops_admission_v2.creation_births b JOIN ops_admission_v2.creation_authority_associations a USING(network_key,tx_hash,inclusion_hash,actual_creation_record)WHERE b.network_key=$1 AND b.address=ANY($2::bytea[])ORDER BY b.address,b.output_hash,b.output_length,a.namespace::text LIMIT 32769`, network[:], values)
		if err != nil {
			return h.ErrUnavailable
		}
		candidates := 0
		for rows.Next() {
			candidates++
			var address, runtime []byte
			var length uint32
			var org string
			if candidates > namespaceImportCandidates || rows.Scan(&address, &runtime, &length, &org) != nil || len(address) != 20 || !h.UUID(org) {
				rows.Close()
				return h.ErrTooBroad
			}
			hash, ok := namespaceHash(runtime)
			if !ok {
				rows.Close()
				return h.ErrUnavailable
			}
			var a h.Address
			copy(a[:], address)
			segment, err := h.PragueSegmentKey(network, a, hash, length)
			if err != nil {
				rows.Close()
				return h.ErrUnavailable
			}
			key := namespacePresenceKey{a, segment, org}
			if _, exists := wanted[key]; exists {
				wanted[key] = true
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return h.ErrUnavailable
		}
		for _, present := range wanted {
			if !present {
				return h.ErrUnavailable
			}
		}
	}
}
