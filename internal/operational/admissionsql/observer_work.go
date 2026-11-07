package admissionsql

import (
	"context"
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5"
	a "privacy-proxy/internal/admission"
	f "privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/creationobserver"
)

func readCreationWork(ctx context.Context, tx pgx.Tx, network f.Network, before f.ObserverSnapshot, hash common.Hash) (*creationobserver.WorkSnapshot, error) {
	input := creationobserver.StoredWork{Network: network, Before: before, Hash: hash}
	var environment, chain, deployment string
	var genesis []byte
	if tx.QueryRow(ctx, `SELECT environment,chain_id,genesis_hash,deployment_id FROM ops_admission_v2.network_state WHERE network_key=$1`, network.Key[:]).Scan(&environment, &chain, &genesis, &deployment) != nil || environment != network.Environment || chain != network.ChainID || len(genesis) != 32 || common.BytesToHash(genesis) != network.Genesis || deployment != network.Deployment {
		return nil, a.ErrCoverage
	}
	if tx.QueryRow(ctx, `SELECT generation FROM ops_admission_v2.creation_work WHERE network_key=$1 AND tx_hash=$2`, network.Key[:], hash[:]).Scan(&input.Generation) != nil {
		return nil, a.ErrCoverage
	}
	rows, err := tx.Query(ctx, `SELECT plan_digest,version,entry_count,CASE WHEN octet_length(payload)<=65536 THEN payload ELSE NULL END,root_org::text,chain_id,evidence_profile,manifest_digest,runtime_digest,created_at FROM ops_admission_v2.creation_plans WHERE network_key=$1 AND tx_hash=$2 ORDER BY plan_digest LIMIT 17`, network.Key[:], hash[:])
	if err != nil {
		return nil, a.ErrUnavailable
	}
	for rows.Next() {
		var p creationobserver.StoredPlan
		var digest, manifest, runtime []byte
		if rows.Scan(&digest, &p.Version, &p.EntryCount, &p.Payload, &p.RootOrg, &p.Chain, &p.Evidence, &manifest, &runtime, &p.CreatedAt) != nil || len(digest) != 32 || len(manifest) != 32 || len(runtime) != 32 || len(input.Plans) >= 16 {
			rows.Close()
			return nil, a.ErrCoverage
		}
		copy(p.Digest[:], digest)
		copy(p.Manifest[:], manifest)
		copy(p.Runtime[:], runtime)
		input.Plans = append(input.Plans, p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, a.ErrUnavailable
	}
	raw := &rawTx{recordReader: recordReader{ctx: ctx, q: tx, scope: a.Scope{Network: a.Digest(network.Key), Hash: hash}}, tx: tx}
	refs, err := raw.creationRefs()
	if err != nil {
		return nil, err
	}
	var origin a.Origin
	for _, r := range refs {
		if r.kind == "WALLET" {
			var found bool
			origin, found, err = raw.GetOrigin()
			if err != nil || !found {
				return nil, a.ErrCoverage
			}
			break
		}
	}
	for _, r := range refs {
		out := creationobserver.StoredReference{Seed: r.seed, Plan: r.plan, Kind: r.kind, Branch: r.branch, Anchor: f.Header{Number: r.number, Hash: r.anchor, Timestamp: r.timestamp}, Profile: r.profile, Manifest: r.manifest, Runtime: r.runtime, CapturedAt: r.at}
		if r.wallet != nil {
			out.OriginActor, out.OriginOrg = origin.Actor, origin.Organization
			out.WalletActor, out.WalletOrg = r.wallet.Actor, r.wallet.Organization
			if origin.Primary.ID == r.wallet.Witness {
				out.Witness = origin.Primary
			} else {
				var scan witnessScan
				if tx.QueryRow(ctx, `SELECT `+witnessColumns+` FROM ops_admission_v2.extra_privacy_witnesses WHERE network_key=$1 AND tx_hash=$2 AND witness_id=$3`, network.Key[:], hash[:], r.wallet.Witness[:]).Scan(scan.destinations()...) != nil {
					return nil, a.ErrCoverage
				}
				out.Witness, err = scan.finish()
				if err != nil {
					return nil, err
				}
			}
		}
		var scan coverageScan
		err = tx.QueryRow(ctx, `SELECT `+coverageColumns+` FROM ops_admission_v2.creation_capture_coverage WHERE network_key=$1 AND tx_hash=$2 AND seed_digest=$3`, network.Key[:], hash[:], r.seed[:]).Scan(scan.destinations()...)
		if err == nil {
			c, e := scan.finish()
			if e != nil {
				return nil, e
			}
			out.Coverage = &c
			if tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ops_admission_v2.revoked_creation_capture_epochs WHERE network_key=$1 AND capture_epoch=$2::uuid)`, network.Key[:], c.CaptureEpoch).Scan(&out.Revoked) != nil {
				return nil, a.ErrUnavailable
			}
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return nil, a.ErrUnavailable
		}
		if tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ops_admission_v2.creation_headers WHERE network_key=$1 AND number=$2 AND hash=$3 AND timestamp=$4::numeric)`, network.Key[:], r.number, r.anchor[:], r.timestamp).Scan(&out.AnchorCanonical) != nil {
			return nil, a.ErrUnavailable
		}
		input.References = append(input.References, out)
	}
	return creationobserver.CompileStoredWork(input)
}

// LoadNextCreationWork captures one bounded immutable journal snapshot. It
// holds no SQL transaction while included evidence is acquired from the node.
func (s *Store) LoadNextCreationWork(ctx context.Context, network f.Network, before f.ObserverSnapshot) (*creationobserver.WorkSnapshot, bool, error) {
	if s == nil || s.mode != "observer" || s.schemaVersion != 3 || network.Key != before.Lease.Network {
		return nil, false, a.ErrInvalid
	}
	ctx, cancel := bounded(ctx)
	defer cancel()
	tx, err := begin(ctx, s.pool, true)
	if err != nil {
		return nil, false, err
	}
	defer rollback(tx)
	current, err := observerLeaseState(ctx, tx, before.Lease, false)
	if err != nil {
		return nil, false, err
	}
	if !current.Ready || current.Quarantine != "none" || !sameObserverVersion(current, before.State) {
		return nil, false, a.ErrUnavailable
	}
	// Each indexed source contributes at most128 candidates. Only one work
	// item is processed per network operation; a new generation wakes a job
	// regardless of its terminal outcome or previous retry timestamp.
	var hash []byte
	err = tx.QueryRow(ctx, `WITH due AS(
 (SELECT tx_hash FROM ops_admission_v2.creation_work WHERE network_key=$1 AND processed_generation<generation ORDER BY tx_hash LIMIT 128)
 UNION (SELECT tx_hash FROM ops_admission_v2.creation_work WHERE network_key=$1 AND next_attempt_at<=clock_timestamp() ORDER BY next_attempt_at,tx_hash LIMIT 128)
 UNION (SELECT tx_hash FROM ops_admission_v2.creation_work WHERE network_key=$1 AND last_reorg_epoch<$2 ORDER BY last_reorg_epoch,tx_hash LIMIT 128))
 SELECT tx_hash FROM due ORDER BY tx_hash LIMIT 1`, network.Key[:], current.ReorgEpoch).Scan(&hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil || len(hash) != 32 {
		return nil, false, a.ErrCoverage
	}
	work, err := readCreationWork(ctx, tx, network, before, common.BytesToHash(hash))
	if err != nil {
		return nil, false, err
	}
	if tx.Commit(ctx) != nil {
		return nil, false, a.ErrUnavailable
	}
	return work, true, nil
}

func observationLock(ctx context.Context, tx pgx.Tx, work *creationobserver.WorkSnapshot) (f.ObserverState, error) {
	before := work.Before()
	first, second := a.HashLock(a.Digest(before.Lease.Network), work.Hash())
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1::integer,$2::integer)`, first, second); err != nil {
		return f.ObserverState{}, a.ErrUnavailable
	}
	current, err := observerLeaseState(ctx, tx, before.Lease, true)
	if err != nil {
		return current, err
	}
	if !current.Ready || current.Quarantine != "none" || !sameObserverVersion(current, before.State) {
		return current, a.ErrConflict
	}
	return current, nil
}

// RecordCreationRetry changes scheduling only. No request/Guard/broadcast can
// be emitted by an observer retry, including ambiguous SQL commit outcomes.
func (s *Store) RecordCreationRetry(ctx context.Context, work *creationobserver.WorkSnapshot, outcome string) error {
	if work == nil || outcome != "not-included" && outcome != "unsupported" && outcome != "uncovered" {
		return a.ErrInvalid
	}
	return s.observerWrite(ctx, work.Before().Lease.Network, false, func(ctx context.Context, tx pgx.Tx) error {
		current, err := observationLock(ctx, tx, work)
		if err != nil {
			return err
		}
		latest, err := readCreationWork(ctx, tx, work.Network(), work.Before(), work.Hash())
		if err != nil {
			return err
		}
		if err := work.RequireCurrent(latest); err != nil {
			return err
		}
		var processed int64
		if tx.QueryRow(ctx, `SELECT processed_generation FROM ops_admission_v2.creation_work WHERE network_key=$1 AND tx_hash=$2`, current.Network[:], work.Hash().Bytes()).Scan(&processed) != nil {
			return a.ErrCoverage
		}
		if processed > work.Generation() {
			return nil
		}
		retry := outcome == "not-included"
		tag, err := tx.Exec(ctx, `UPDATE ops_admission_v2.creation_work SET processed_generation=$3,outcome=$4,retry_count=LEAST(retry_count,2147483646)+1,next_attempt_at=CASE WHEN $5 THEN clock_timestamp()+LEAST(60,1<<LEAST(retry_count,6))*interval'1 second' ELSE NULL END,last_reorg_epoch=$6 WHERE network_key=$1 AND tx_hash=$2 AND generation>=$3`, current.Network[:], work.Hash().Bytes(), work.Generation(), outcome, retry, current.ReorgEpoch)
		if err != nil || tag.RowsAffected() != 1 {
			return a.ErrUnavailable
		}
		_, err = observerLeaseState(ctx, tx, work.Before().Lease, false)
		return err
	})
}

// A reorg outside a job's unchanged inclusion cannot alter that block's
// execution. Acknowledge only its epoch, without re-tracing or rewriting any
// immutable facts. A new generation always takes the normal proof path.
func (s *Store) AcknowledgeUnchangedInclusion(ctx context.Context, work *creationobserver.WorkSnapshot) (bool, error) {
	if work == nil {
		return false, a.ErrInvalid
	}
	ack := false
	err := s.observerWrite(ctx, work.Before().Lease.Network, false, func(ctx context.Context, tx pgx.Tx) error {
		current, err := observationLock(ctx, tx, work)
		if err != nil {
			return err
		}
		var eligible bool
		if tx.QueryRow(ctx, `SELECT generation=$3 AND processed_generation=generation AND last_reorg_epoch<$4 AND EXISTS(SELECT 1 FROM ops_admission_v2.creation_headers h WHERE h.network_key=w.network_key AND h.number=w.inclusion_number AND h.hash=w.inclusion_hash)FROM ops_admission_v2.creation_work w WHERE network_key=$1 AND tx_hash=$2`, current.Network[:], work.Hash().Bytes(), work.Generation(), current.ReorgEpoch).Scan(&eligible) != nil {
			return a.ErrCoverage
		}
		if !eligible {
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE ops_admission_v2.creation_work SET last_reorg_epoch=$3 WHERE network_key=$1 AND tx_hash=$2`, current.Network[:], work.Hash().Bytes(), current.ReorgEpoch); err != nil {
			return a.ErrUnavailable
		}
		_, err = observerLeaseState(ctx, tx, work.Before().Lease, false)
		ack = err == nil
		return err
	})
	return ack, err
}
