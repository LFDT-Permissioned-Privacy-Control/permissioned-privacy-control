package admissionsql

import (
	"context"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5"
	a "privacy-proxy/internal/admission"
	"privacy-proxy/internal/creationobserver"
	"privacy-proxy/internal/policycore"
	"privacy-proxy/internal/rpcexecution"
)

func validateRestoredObservedHistory(ctx context.Context, tx pgx.Tx, network a.Digest) error {
	var bad bool
	if tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ops_admission_v2.creation_births b WHERE b.network_key=$1 AND NOT EXISTS(SELECT 1 FROM ops_admission_v2.creation_authority_associations a WHERE a.network_key=b.network_key AND a.tx_hash=b.tx_hash AND a.inclusion_hash=b.inclusion_hash AND a.actual_creation_record=b.actual_creation_record))
	OR EXISTS(SELECT 1 FROM ops_admission_v2.creation_births WHERE network_key=$1 GROUP BY tx_hash,inclusion_hash HAVING count(DISTINCT proof_digest)<>1 OR count(DISTINCT tx_index)<>1 OR count(DISTINCT inclusion_number)<>1)
 OR EXISTS(SELECT 1 FROM ops_admission_v2.creation_work WHERE network_key=$1 AND(processed_generation>generation OR(last_reorg_epoch<0)OR(next_attempt_at IS NOT NULL AND outcome<>'not-included')))
	 OR EXISTS(SELECT 1 FROM ops_admission_v2.creation_authority_associations a JOIN ops_admission_v2.creation_authority_refs r USING(network_key,tx_hash,seed_digest)JOIN ops_admission_v2.creation_plans p USING(network_key,tx_hash,plan_digest)JOIN ops_admission_v2.creation_births b ON b.network_key=a.network_key AND b.tx_hash=a.tx_hash AND b.inclusion_hash=a.inclusion_hash AND b.actual_creation_record=a.actual_creation_record WHERE a.network_key=$1 AND(p.version<>2 OR a.kind<>r.kind OR r.anchor_number>=b.inclusion_number))`, network[:]).Scan(&bad) != nil || bad {
		return a.ErrCoverage
	}
	var lastHash, lastInclusion, lastSeed []byte
	lastRecord, lastEntry := -1, -1
	for {
		rows, err := tx.Query(ctx, `SELECT a.tx_hash,a.inclusion_hash,a.actual_creation_record,a.seed_digest,a.planned_entry,a.namespace::text,a.kind,a.wallet_actor,a.factory_root,a.qualification_digest,
 b.address,b.creator,b.kind,b.tuple_digest,b.creation_parent,b.output_hash,b.output_length,b.evidence_profile,b.proof_digest,b.inclusion_number,b.tx_index,b.observed_at,
 r.kind,r.wallet_actor,p.plan_digest,CASE WHEN octet_length(p.payload)<=65536 THEN p.payload ELSE NULL END
 FROM ops_admission_v2.creation_authority_associations a JOIN ops_admission_v2.creation_births b USING(network_key,tx_hash,inclusion_hash,actual_creation_record)JOIN ops_admission_v2.creation_authority_refs r USING(network_key,tx_hash,seed_digest)JOIN ops_admission_v2.creation_plans p USING(network_key,tx_hash,plan_digest)
 WHERE a.network_key=$1 AND($2::bytea IS NULL OR(a.tx_hash,a.inclusion_hash,a.actual_creation_record,a.seed_digest,a.planned_entry)>($2::bytea,$3::bytea,$4::integer,$5::bytea,$6::smallint))ORDER BY a.tx_hash,a.inclusion_hash,a.actual_creation_record,a.seed_digest,a.planned_entry LIMIT 256`, network[:], lastHash, lastInclusion, lastRecord, lastSeed, lastEntry)
		if err != nil {
			return a.ErrUnavailable
		}
		count := 0
		for rows.Next() {
			var hash, inclusion, seed, qualification, address, creator, tuple, output, proof, planDigest, payload []byte
			var as creationobserver.Association
			var b creationobserver.Birth
			var actor, refActor *string
			var root, parent *int
			var profile, refKind string
			var number uint64
			var index uint32
			var observedAt time.Time
			if rows.Scan(&hash, &inclusion, &as.Record, &seed, &as.Entry, &as.Namespace, &as.Kind, &actor, &root, &qualification, &address, &creator, &b.Kind, &tuple, &parent, &output, &b.OutputLength, &profile, &proof, &number, &index, &observedAt, &refKind, &refActor, &planDigest, &payload) != nil {
				rows.Close()
				return a.ErrCoverage
			}
			for _, v := range [][]byte{hash, inclusion, seed, qualification, tuple, output, proof, planDigest} {
				if len(v) != 32 {
					rows.Close()
					return a.ErrCoverage
				}
			}
			if len(address) != 20 || len(creator) != 20 || common.BytesToHash(output) == (common.Hash{}) || common.BytesToHash(proof) == (common.Hash{}) || profile != rpcexecution.IncludedProfileID || b.OutputLength < 1 || b.OutputLength > 1<<20 || policycore.IsPraguePrecompile(common.BytesToAddress(address)) || observedAt.IsZero() || observedAt.Unix() < 0 || observedAt.Unix() > 253402300799 {
				rows.Close()
				return a.ErrCoverage
			}
			b.Record = as.Record
			b.Parent = -1
			if parent != nil {
				b.Parent = *parent
			}
			b.Address = common.BytesToAddress(address)
			b.Creator = common.BytesToAddress(creator)
			b.TupleDigest = common.BytesToHash(tuple)
			b.OutputHash = common.BytesToHash(output)
			copy(as.Seed[:], seed)
			copy(as.Qualification[:], qualification)
			as.FactoryRoot = -1
			if root != nil {
				as.FactoryRoot = *root
			}
			if actor != nil {
				as.WalletActor = *actor
			}
			var digest a.Digest
			copy(digest[:], planDigest)
			plan, err := a.DecodeCapturedCreationPlan(payload, digest)
			originalActor := ""
			if refActor != nil {
				originalActor = *refActor
			}
			if err != nil || plan.Hash != common.BytesToHash(hash) || creationobserver.ValidateStoredAssociation(common.BytesToHash(proof), b, as, plan, refKind, originalActor) != nil {
				rows.Close()
				return a.ErrCoverage
			}
			lastHash, lastInclusion, lastRecord, lastSeed, lastEntry = hash, inclusion, as.Record, seed, as.Entry
			count++
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return a.ErrUnavailable
		}
		if count == 0 {
			return nil
		}
	}
}
