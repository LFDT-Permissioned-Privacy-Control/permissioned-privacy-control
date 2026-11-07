package admissionsql

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5"
	a "privacy-proxy/internal/admission"
	"privacy-proxy/internal/identity"
)

type recoveryPlanKey struct {
	hash   common.Hash
	digest a.Digest
}
type recoveryPlanSummary struct {
	rootOrg, chain, evidence string
	manifest, runtime        a.Digest
	factory                  bool
}

// Only one <=64KiB payload is decoded at a time. A page retains 256 small
// summaries, closes pgx.Rows, then checks its bounded joined authority rows.
// No whole-history payload map or nested queries on an open pgx result exists.
func validateRestoredCreations(ctx context.Context, tx pgx.Tx, network a.Digest) error {
	var networkChain string
	if err := tx.QueryRow(ctx, `SELECT chain_id FROM ops_admission_v2.network_state WHERE network_key=$1`, network[:]).Scan(&networkChain); err != nil {
		return a.ErrCoverage
	}
	var bad bool
	if err := tx.QueryRow(ctx, `SELECT
 NOT EXISTS(SELECT 1 FROM ops_admission_v2.creation_capacity WHERE network_key=$1)
 OR EXISTS(SELECT 1 FROM ops_admission_v2.creation_plans p WHERE p.network_key=$1 AND(NOT EXISTS(SELECT 1 FROM ops_admission_v2.creation_authority_refs r WHERE r.network_key=p.network_key AND r.tx_hash=p.tx_hash AND r.plan_digest=p.plan_digest) OR NOT EXISTS(SELECT 1 FROM ops_admission_v2.creation_work w WHERE w.network_key=p.network_key AND w.tx_hash=p.tx_hash)))
 OR EXISTS(SELECT 1 FROM ops_admission_v2.creation_work w WHERE w.network_key=$1 AND(NOT EXISTS(SELECT 1 FROM ops_admission_v2.creation_authority_refs r WHERE r.network_key=w.network_key AND r.tx_hash=w.tx_hash) OR NOT isfinite(w.created_at) OR NOT isfinite(w.updated_at) OR w.created_at<'1970-01-01 UTC'::timestamptz OR w.updated_at>='10000-01-01 UTC'::timestamptz))
 OR EXISTS(SELECT 1 FROM ops_admission_v2.creation_authority_refs r WHERE r.network_key=$1 GROUP BY tx_hash,kind HAVING min(branch)<>1 OR max(branch)<>count(*) OR count(*)>8)
 OR EXISTS(SELECT 1 FROM ops_admission_v2.creation_work w JOIN(SELECT tx_hash,count(*)total,count(*)FILTER(WHERE kind='WALLET')wallets,count(*)FILTER(WHERE kind='FACTORY')factories FROM ops_admission_v2.creation_authority_refs WHERE network_key=$1 GROUP BY tx_hash)r ON r.tx_hash=w.tx_hash WHERE w.network_key=$1 AND(w.generation<GREATEST(r.wallets,r.factories)OR w.generation>r.total))`, network[:]).Scan(&bad); err != nil || bad {
		return a.ErrCoverage
	}
	var counters bool
	if err := tx.QueryRow(ctx, `SELECT
 work_count=(SELECT count(*)FROM ops_admission_v2.creation_work WHERE network_key=$1)
 AND plan_count=(SELECT count(*)FROM ops_admission_v2.creation_plans WHERE network_key=$1)
 AND plan_bytes=(SELECT COALESCE(sum(octet_length(payload)::bigint),0)FROM ops_admission_v2.creation_plans WHERE network_key=$1)
 AND wallet_ref_count=(SELECT count(*)FROM ops_admission_v2.creation_authority_refs WHERE network_key=$1 AND kind='WALLET')
 AND factory_ref_count=(SELECT count(*)FROM ops_admission_v2.creation_authority_refs WHERE network_key=$1 AND kind='FACTORY')
 FROM ops_admission_v2.creation_capacity WHERE network_key=$1`, network[:]).Scan(&counters); err != nil || !counters {
		return a.ErrCoverage
	}
	var lastHash, lastDigest []byte
	for {
		rows, err := tx.Query(ctx, `SELECT tx_hash,plan_digest,CASE WHEN octet_length(payload)<=65536 THEN payload ELSE NULL END,entry_count,root_org::text,manifest_digest,runtime_digest,chain_id,evidence_profile,created_at,version FROM ops_admission_v2.creation_plans WHERE network_key=$1 AND($2::bytea IS NULL OR(tx_hash,plan_digest)>($2::bytea,$3::bytea)) ORDER BY tx_hash,plan_digest LIMIT 256`, network[:], lastHash, lastDigest)
		if err != nil {
			return a.ErrUnavailable
		}
		summaries := map[recoveryPlanKey]recoveryPlanSummary{}
		hashes, digests := [][]byte{}, [][]byte{}
		for rows.Next() {
			var hash, digest, payload, manifest, runtime []byte
			var count int
			var version int
			var org, chain, evidence string
			var created time.Time
			if rows.Scan(&hash, &digest, &payload, &count, &org, &manifest, &runtime, &chain, &evidence, &created, &version) != nil || len(hash) != 32 || len(digest) != 32 || len(manifest) != 32 || len(runtime) != 32 || created.IsZero() || created.Unix() < 0 || created.Unix() > 253402300799 || (version != 1 && version != 2) {
				rows.Close()
				return a.ErrCoverage
			}
			key := recoveryPlanKey{hash: common.BytesToHash(hash)}
			copy(key.digest[:], digest)
			p, err := a.DecodeCreationPlan(payload, key.digest)
			if version == 2 {
				p, err = a.DecodeCapturedCreationPlan(payload, key.digest)
			}
			if err != nil || p.Hash != key.hash || p.RootOrg != org || p.Chain != chain || chain != networkChain || p.Evidence != evidence || len(p.Entries) != count {
				rows.Close()
				return a.ErrCoverage
			}
			m, _ := a.ParseDigest(p.Manifest)
			r, _ := a.ParseDigest(p.Runtime)
			if string(m[:]) != string(manifest) || string(r[:]) != string(runtime) {
				rows.Close()
				return a.ErrCoverage
			}
			summaries[key] = recoveryPlanSummary{rootOrg: org, chain: chain, evidence: evidence, manifest: m, runtime: r, factory: len(p.FactoryRoots) > 0}
			hashes = append(hashes, hash)
			digests = append(digests, digest)
			lastHash, lastDigest = hash, digest
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return a.ErrUnavailable
		}
		if len(summaries) == 0 {
			return nil
		}
		if err := validateRecoveryRefs(ctx, tx, network, summaries, hashes, digests); err != nil {
			return err
		}
	}
}

type recoveryWitness struct {
	id, anchor, wallet, manifest, compliance []byte
	number, timestamp, profile               *string
	at, evidenceAt                           *time.Time
}

func (w *recoveryWitness) destinations() []any {
	return []any{&w.id, &w.anchor, &w.number, &w.timestamp, &w.profile, &w.wallet, &w.at, &w.manifest, &w.compliance, &w.evidenceAt}
}
func (w recoveryWitness) decode() (a.Witness, error) {
	var out a.Witness
	if len(w.id) != 32 || len(w.anchor) != 32 || len(w.wallet) != 32 || len(w.manifest) != 32 || len(w.compliance) != 32 || w.number == nil || w.timestamp == nil || w.profile == nil || w.at == nil || w.evidenceAt == nil {
		return out, a.ErrCoverage
	}
	copy(out.ID[:], w.id)
	copy(out.AnchorHash[:], w.anchor)
	copy(out.WalletVersion[:], w.wallet)
	copy(out.ManifestDigest[:], w.manifest)
	copy(out.ComplianceDigest[:], w.compliance)
	var err error
	out.AnchorNumber, err = strconv.ParseUint(*w.number, 10, 64)
	if err != nil {
		return out, a.ErrCoverage
	}
	out.AnchorTimestamp, err = strconv.ParseUint(*w.timestamp, 10, 64)
	if err != nil {
		return out, a.ErrCoverage
	}
	out.EvidenceProfile = *w.profile
	out.DecisionAt = *w.at
	out.WalletEvidenceAt = *w.evidenceAt
	if !out.Valid() {
		return out, a.ErrCoverage
	}
	return out, nil
}

func validateRecoveryRefs(ctx context.Context, tx pgx.Tx, network a.Digest, summaries map[recoveryPlanKey]recoveryPlanSummary, hashes, digests [][]byte) error {
	witnessFields := []string{}
	for _, name := range []string{"witness_id", "anchor_hash", "anchor_number", "anchor_timestamp", "evidence_profile", "wallet_version", "decision_at", "manifest_digest", "compliance_digest", "wallet_evidence_at"} {
		field := "(CASE WHEN o.witness_id=r.witness_id THEN o." + name + " ELSE w." + name + " END)"
		if name == "anchor_number" || name == "anchor_timestamp" {
			field += "::text"
		}
		witnessFields = append(witnessFields, field)
	}
	query := `SELECT r.tx_hash,r.plan_digest,r.seed_digest,r.kind,r.wallet_actor,r.wallet_org::text,r.witness_id,r.anchor_hash,r.anchor_number::text,r.anchor_timestamp::text,r.evidence_profile,r.manifest_digest,r.runtime_digest,r.captured_at,o.actor_id,o.org_id::text,` + strings.Join(witnessFields, ",") + ` FROM ops_admission_v2.creation_authority_refs r JOIN unnest($2::bytea[],$3::bytea[])k(tx_hash,plan_digest)ON r.tx_hash=k.tx_hash AND r.plan_digest=k.plan_digest LEFT JOIN ops_admission_v2.qualified_tx_origins o ON o.network_key=r.network_key AND o.tx_hash=r.tx_hash LEFT JOIN ops_admission_v2.extra_privacy_witnesses w ON w.network_key=r.network_key AND w.tx_hash=r.tx_hash AND w.witness_id=r.witness_id WHERE r.network_key=$1 ORDER BY r.tx_hash,r.plan_digest,r.kind,r.branch LIMIT 4097`
	rows, err := tx.Query(ctx, query, network[:], hashes, digests)
	if err != nil {
		return a.ErrUnavailable
	}
	defer rows.Close()
	seen := map[recoveryPlanKey]int{}
	count := 0
	for rows.Next() {
		count++
		if count > 4096 {
			return a.ErrCoverage
		}
		var hash, plan, seed, witness, anchor, manifest, runtime []byte
		var kind, number, timestamp, profile string
		var actor, org, originActor, originOrg *string
		var at time.Time
		var observed recoveryWitness
		dest := []any{&hash, &plan, &seed, &kind, &actor, &org, &witness, &anchor, &number, &timestamp, &profile, &manifest, &runtime, &at, &originActor, &originOrg}
		dest = append(dest, observed.destinations()...)
		if rows.Scan(dest...) != nil || len(hash) != 32 || len(plan) != 32 || len(seed) != 32 || len(anchor) != 32 || len(manifest) != 32 || len(runtime) != 32 || at.IsZero() || at.Unix() < 0 || at.Unix() > 253402300799 {
			return a.ErrCoverage
		}
		key := recoveryPlanKey{hash: common.BytesToHash(hash)}
		copy(key.digest[:], plan)
		p, found := summaries[key]
		if !found || profile != p.evidence || string(manifest) != string(p.manifest[:]) || string(runtime) != string(p.runtime[:]) {
			return a.ErrCoverage
		}
		i := a.CreationIntent{PlanDigest: key.digest, CapturedAt: at}
		i.Anchor.Hash = common.BytesToHash(anchor)
		i.Anchor.Profile = profile
		i.Anchor.Number, err = strconv.ParseUint(number, 10, 64)
		if err != nil {
			return a.ErrCoverage
		}
		i.Anchor.Timestamp, err = strconv.ParseUint(timestamp, 10, 64)
		if err != nil {
			return a.ErrCoverage
		}
		if i.Anchor.Hash == (common.Hash{}) {
			return a.ErrCoverage
		}
		if kind == "WALLET" {
			if actor == nil || org == nil || !identity.ValidActorID(*actor) || originActor == nil || originOrg == nil || *org != p.rootOrg || *actor != *originActor || *org != *originOrg || len(witness) != 32 {
				return a.ErrCoverage
			}
			var id a.Digest
			copy(id[:], witness)
			i.Wallet = &a.CreationWalletAuthority{Actor: *actor, Organization: *org, Witness: id}
			w, err := observed.decode()
			if err != nil || w.ID != id || w.AnchorHash != i.Anchor.Hash || w.AnchorNumber != i.Anchor.Number || w.AnchorTimestamp != i.Anchor.Timestamp || w.EvidenceProfile != profile {
				return a.ErrCoverage
			}
			// Found witness source/time remains M1 even when plan is current M2.
		} else if kind != "FACTORY" || !p.factory || actor != nil || org != nil || len(witness) != 0 {
			return a.ErrCoverage
		}
		want := i.SeedDigest(kind)
		if string(want[:]) != string(seed) {
			return a.ErrCoverage
		}
		seen[key]++
	}
	if rows.Err() != nil {
		return a.ErrUnavailable
	}
	if len(seen) != len(summaries) {
		return a.ErrCoverage
	}
	return nil
}
