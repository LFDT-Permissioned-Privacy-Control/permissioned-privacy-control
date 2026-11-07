package admissionsql

import (
	"context"
	"math"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	a "privacy-proxy/internal/admission"
	f "privacy-proxy/internal/creationfacts"
)

const observerStateColumns = `o.observer_epoch::text,o.capture_epoch::text,o.ready,o.capture_ready,o.quarantine,
 f.number,f.hash,f.parent_hash,f.timestamp::text,h.number,h.hash,h.parent_hash,h.timestamp::text,
 o.header_version,o.reorg_epoch,coalesce(o.lease_owner::text,''),o.lease_fence,o.lease_expires,
 o.source_set_digest,o.reference_binding_digest,coalesce(o.lease_expires>clock_timestamp(),false),o.known_tip_number,o.known_tip_hash,CASE WHEN o.lease_expires IS NULL THEN NULL ELSE trunc(extract(epoch FROM(o.lease_expires-clock_timestamp()))*1000000000)::text END`
const observerStateJoin = `FROM ops_admission_v2.creation_observer_state o
 JOIN ops_admission_v2.creation_headers f ON f.network_key=o.network_key AND f.number=o.floor_number AND f.hash=o.floor_hash
 JOIN ops_admission_v2.creation_headers h ON h.network_key=o.network_key AND h.number=o.head_number AND h.hash=o.head_hash WHERE o.network_key=$1`

func scanObserver(row pgx.Row, network f.Digest) (f.ObserverState, bool, error) {
	s := f.ObserverState{Network: network}
	var fh, fp, hh, hp, source, reference []byte
	var ft, ht string
	var expiry *time.Time
	var live bool
	var knownNumber *int64
	var knownHash []byte
	var ttl *string
	if err := row.Scan(&s.ObserverEpoch, &s.CaptureEpoch, &s.Ready, &s.CaptureReady, &s.Quarantine, &s.Floor.Number, &fh, &fp, &ft, &s.Head.Number, &hh, &hp, &ht, &s.HeaderVersion, &s.ReorgEpoch, &s.LeaseOwner, &s.LeaseFence, &expiry, &source, &reference, &live, &knownNumber, &knownHash, &ttl); err != nil {
		return s, false, a.ErrUnavailable
	}
	if len(fh) != 32 || len(fp) != 32 || len(hh) != 32 || len(hp) != 32 || len(source) != 32 || len(reference) != 32 || len(ft) > 20 || len(ht) > 20 {
		return s, false, a.ErrCoverage
	}
	var err error
	s.Floor.Timestamp, err = strconv.ParseUint(ft, 10, 64)
	if err != nil {
		return s, false, a.ErrCoverage
	}
	s.Head.Timestamp, err = strconv.ParseUint(ht, 10, 64)
	if err != nil {
		return s, false, a.ErrCoverage
	}
	copy(s.Floor.Hash[:], fh)
	copy(s.Floor.Parent[:], fp)
	copy(s.Head.Hash[:], hh)
	copy(s.Head.Parent[:], hp)
	copy(s.SourceSet[:], source)
	copy(s.Reference[:], reference)
	if expiry != nil {
		s.LeaseExpires = expiry.UTC()
	}
	if (knownNumber == nil) != (len(knownHash) == 0) || knownNumber != nil && (*knownNumber < 0 || len(knownHash) != 32) {
		return s, false, a.ErrCoverage
	}
	if knownNumber != nil {
		s.KnownTipSet = true
		s.KnownTip.Number = uint64(*knownNumber)
		copy(s.KnownTip.Hash[:], knownHash)
		if !s.KnownTip.Valid() {
			return s, false, a.ErrCoverage
		}
	}
	if live {
		if ttl == nil || len(*ttl) > 11 {
			return s, false, a.ErrCoverage
		}
		nanos, err := strconv.ParseInt(*ttl, 10, 64)
		if err != nil || nanos <= 0 || nanos > int64(30*time.Second) {
			return s, false, a.ErrCoverage
		}
		s.LeaseRemainingTTL = time.Duration(nanos)
	}
	if !f.UUID(s.ObserverEpoch) || !f.UUID(s.CaptureEpoch) || !s.Floor.Valid() || !s.Head.Valid() || s.Head.Number < s.Floor.Number || s.HeaderVersion < 1 || s.ReorgEpoch < 0 || s.LeaseFence < 0 || (s.LeaseOwner != "" && !f.UUID(s.LeaseOwner)) || s.SourceSet == (f.Digest{}) || s.Reference == (f.Digest{}) {
		return s, false, a.ErrCoverage
	}
	return s, live, nil
}
func observerLeaseState(ctx context.Context, q querier, l f.Lease, locked bool) (f.ObserverState, error) {
	if !l.Valid() {
		return f.ObserverState{}, a.ErrInvalid
	}
	if err := state(ctx, q, a.Digest(l.Network), a.ExpectedState{Generation: l.State.Generation, Coverage: a.Digest(l.State.Coverage)}); err != nil {
		return f.ObserverState{}, err
	}
	sql := `SELECT ` + observerStateColumns + ` ` + observerStateJoin
	if locked {
		sql += ` FOR UPDATE OF o`
	}
	s, live, err := scanObserver(q.QueryRow(ctx, sql, l.Network[:]), l.Network)
	if err != nil {
		return s, err
	}
	if !live || s.LeaseOwner != l.Owner || s.LeaseFence != l.Fence || s.ObserverEpoch != l.ObserverEpoch || s.CaptureEpoch != l.CaptureEpoch || s.SourceSet != l.SourceSet || s.Reference != l.Reference || (s.Quarantine != "none" && s.Quarantine != "awaiting-canonical") {
		return s, a.ErrUnavailable
	}
	return s, nil
}
func (s *Store) observerWrite(ctx context.Context, network f.Digest, exclusive bool, callback func(context.Context, pgx.Tx) error) error {
	if s == nil || s.mode != "observer" || s.schemaVersion != 3 || network == (f.Digest{}) {
		return a.ErrInvalid
	}
	ctx, cancel := bounded(ctx)
	defer cancel()
	tx, err := begin(ctx, s.pool, false)
	if err != nil {
		return err
	}
	defer rollback(tx)
	if err := captureLock(ctx, tx, a.Digest(network), !exclusive); err != nil {
		return err
	}
	if err := callback(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return a.ErrUnavailable
	}
	return nil
}

// AcquireObserverLease serializes takeover and source changes EXCLUSIVELY with
// covered admission. A live different owner cannot be displaced. A takeover
// rotates the capture epoch; heartbeats and normal prefix movement do not.
func (s *Store) AcquireObserverLease(ctx context.Context, network f.Digest, expected f.State, owner string, sourceSet, reference f.Digest) (f.ObserverSnapshot, error) {
	var out f.ObserverSnapshot
	if !expected.Valid() || !f.UUID(owner) || sourceSet == (f.Digest{}) || reference == (f.Digest{}) {
		return out, a.ErrInvalid
	}
	err := s.observerWrite(ctx, network, true, func(ctx context.Context, tx pgx.Tx) error {
		if err := state(ctx, tx, a.Digest(network), a.ExpectedState{Generation: expected.Generation, Coverage: a.Digest(expected.Coverage)}); err != nil {
			return err
		}
		current, live, err := scanObserver(tx.QueryRow(ctx, `SELECT `+observerStateColumns+` `+observerStateJoin+` FOR UPDATE OF o`, network[:]), network)
		if err != nil {
			return err
		}
		if current.Quarantine != "none" && current.Quarantine != "awaiting-canonical" {
			return a.ErrUnavailable
		}
		if live && (current.LeaseOwner != owner || current.SourceSet != sourceSet || current.Reference != reference) {
			return a.ErrConflict
		}
		if !live {
			if current.LeaseFence == math.MaxInt64 {
				return a.ErrCoverage
			}
			current.CaptureEpoch = uuid.NewString()
			current.LeaseFence++
			current.LeaseOwner = owner
			current.SourceSet = sourceSet
			current.Reference = reference
			current.CaptureReady = false
		}
		if _, err := tx.Exec(ctx, `UPDATE ops_admission_v2.creation_observer_state SET lease_owner=$2::uuid,lease_fence=$3,lease_expires=clock_timestamp()+interval'30 seconds',capture_epoch=$4::uuid,source_set_digest=$5,reference_binding_digest=$6,capture_ready=false,capture_heartbeat_until=NULL WHERE network_key=$1`, network[:], owner, current.LeaseFence, current.CaptureEpoch, sourceSet[:], reference[:]); err != nil {
			return a.ErrUnavailable
		}
		lease := f.Lease{Network: network, State: expected, Owner: owner, ObserverEpoch: current.ObserverEpoch, CaptureEpoch: current.CaptureEpoch, Fence: current.LeaseFence, SourceSet: sourceSet, Reference: reference}
		current, err = observerLeaseState(ctx, tx, lease, false)
		if err != nil {
			return err
		}
		out = f.ObserverSnapshot{Lease: lease, State: current}
		return nil
	})
	return out, err
}
func (s *Store) ReadObserver(ctx context.Context, lease f.Lease) (f.ObserverSnapshot, error) {
	if s == nil || s.mode != "observer" || s.schemaVersion != 3 {
		return f.ObserverSnapshot{}, a.ErrInvalid
	}
	ctx, cancel := bounded(ctx)
	defer cancel()
	current, err := observerLeaseState(ctx, s.pool, lease, false)
	return f.ObserverSnapshot{Lease: lease, State: current}, err
}
func (s *Store) RenewObserverLease(ctx context.Context, lease f.Lease) (f.ObserverSnapshot, error) {
	var out f.ObserverSnapshot
	err := s.observerWrite(ctx, lease.Network, false, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := observerLeaseState(ctx, tx, lease, true); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE ops_admission_v2.creation_observer_state SET lease_expires=clock_timestamp()+interval'30 seconds' WHERE network_key=$1`, lease.Network[:]); err != nil {
			return a.ErrUnavailable
		}
		current, err := observerLeaseState(ctx, tx, lease, false)
		out = f.ObserverSnapshot{Lease: lease, State: current}
		return err
	})
	return out, err
}
func sameObserverVersion(a, b f.ObserverState) bool {
	return a.Network == b.Network && a.ObserverEpoch == b.ObserverEpoch && a.CaptureEpoch == b.CaptureEpoch && a.Ready == b.Ready && a.Quarantine == b.Quarantine && a.Head == b.Head && a.Floor == b.Floor && a.HeaderVersion == b.HeaderVersion && a.ReorgEpoch == b.ReorgEpoch && a.SourceSet == b.SourceSet && a.Reference == b.Reference
}
func (s *Store) ReadObserverHeaders(ctx context.Context, lease f.Lease, numbers []uint64) ([]f.Header, error) {
	if s == nil || s.mode != "observer" || s.schemaVersion != 3 || len(numbers) > 128 {
		return nil, a.ErrInvalid
	}
	ctx, cancel := bounded(ctx)
	defer cancel()
	tx, err := begin(ctx, s.pool, true)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	if _, err := observerLeaseState(ctx, tx, lease, false); err != nil {
		return nil, err
	}
	out := make([]f.Header, len(numbers))
	for i, n := range numbers {
		if n > math.MaxInt64 {
			return nil, a.ErrInvalid
		}
		var hash, parent []byte
		var timestamp string
		h := f.Header{Number: n}
		if tx.QueryRow(ctx, `SELECT hash,parent_hash,timestamp::text FROM ops_admission_v2.creation_headers WHERE network_key=$1 AND number=$2`, lease.Network[:], n).Scan(&hash, &parent, &timestamp) != nil || len(hash) != 32 || len(parent) != 32 || len(timestamp) > 20 {
			return nil, a.ErrCoverage
		}
		h.Timestamp, err = strconv.ParseUint(timestamp, 10, 64)
		if err != nil {
			return nil, a.ErrCoverage
		}
		copy(h.Hash[:], hash)
		copy(h.Parent[:], parent)
		out[i] = h
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, a.ErrUnavailable
	}
	return out, nil
}

// MarkObserverTip disables only transient capture liveness. Previously valid
// capture tickets remain committable while durable trust/epochs stay unchanged.
func (s *Store) MarkObserverTip(ctx context.Context, before f.ObserverSnapshot, tip f.Header) error {
	if !tip.Valid() {
		return a.ErrInvalid
	}
	return s.observerWrite(ctx, before.Lease.Network, false, func(ctx context.Context, tx pgx.Tx) error {
		current, err := observerLeaseState(ctx, tx, before.Lease, true)
		if err != nil {
			return err
		}
		if !sameObserverVersion(current, before.State) {
			return a.ErrConflict
		}
		_, err = tx.Exec(ctx, `UPDATE ops_admission_v2.creation_observer_state SET capture_ready=false,capture_heartbeat_until=NULL,known_tip_number=CASE WHEN known_tip_number IS NULL OR $2::bigint>=known_tip_number THEN $2::bigint ELSE known_tip_number END,known_tip_hash=CASE WHEN known_tip_number IS NULL OR $2::bigint>=known_tip_number THEN $3 ELSE known_tip_hash END WHERE network_key=$1`, before.Lease.Network[:], tip.Number, tip.Hash[:])
		return dbError(err)
	})
}

// ClearObserverCapture preserves the remembered high water when a node cannot
// supply a coherent exact-false-sync observation. It changes no durable trust.
func (s *Store) ClearObserverCapture(ctx context.Context, before f.ObserverSnapshot) error {
	return s.observerWrite(ctx, before.Lease.Network, false, func(ctx context.Context, tx pgx.Tx) error {
		current, err := observerLeaseState(ctx, tx, before.Lease, true)
		if err != nil {
			return err
		}
		if !sameObserverVersion(current, before.State) {
			return a.ErrConflict
		}
		_, err = tx.Exec(ctx, `UPDATE ops_admission_v2.creation_observer_state SET capture_ready=false,capture_heartbeat_until=NULL WHERE network_key=$1 AND(capture_ready OR capture_heartbeat_until IS NOT NULL)`, before.Lease.Network[:])
		return dbError(err)
	})
}
func (s *Store) PublishObserverHeaders(ctx context.Context, update f.HeaderUpdate) (f.ObserverSnapshot, error) {
	var out f.ObserverSnapshot
	b := update.Before
	common := update.Common
	headers := append([]f.Header(nil), update.Headers...)
	tip := update.Tip
	if !b.Lease.Valid() || !common.Valid() || !tip.Valid() || len(headers) > 128 || common.Number < b.State.Floor.Number || common.Number > b.State.Head.Number {
		return out, a.ErrInvalid
	}
	head := common
	for _, h := range headers {
		if !h.Valid() || h.Number != head.Number+1 || h.Parent != head.Hash || h.Timestamp <= head.Timestamp {
			return out, a.ErrInvalid
		}
		head = h
	}
	if head.Number > tip.Number || (head.Number == tip.Number && head != tip) {
		return out, a.ErrInvalid
	}
	reorg := common != b.State.Head
	activate := !b.State.Ready && b.State.Quarantine == "awaiting-canonical" && head == tip
	prefixChanged := reorg || len(headers) > 0
	advanceVersion := prefixChanged || activate
	err := s.observerWrite(ctx, b.Lease.Network, reorg || activate, func(ctx context.Context, tx pgx.Tx) error {
		current, err := observerLeaseState(ctx, tx, b.Lease, true)
		if err != nil {
			return err
		}
		if !sameObserverVersion(current, b.State) || advanceVersion && current.HeaderVersion == math.MaxInt64 || reorg && current.ReorgEpoch == math.MaxInt64 {
			return a.ErrConflict
		}
		if !reorg && current.KnownTipSet && (tip.Number < current.KnownTip.Number || tip.Number == current.KnownTip.Number && tip.Hash != current.KnownTip.Hash) {
			return a.ErrUnavailable
		}
		var canonical bool
		if tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ops_admission_v2.creation_headers WHERE network_key=$1 AND number=$2 AND hash=$3 AND parent_hash=$4 AND timestamp=$5::numeric)`, b.Lease.Network[:], common.Number, common.Hash[:], common.Parent[:], strconv.FormatUint(common.Timestamp, 10)).Scan(&canonical) != nil || !canonical {
			return a.ErrCoverage
		}
		var next int64
		if prefixChanged {
			var count int64
			if tx.QueryRow(ctx, `SELECT header_count FROM ops_admission_v2.creation_capacity WHERE network_key=$1 FOR UPDATE`, b.Lease.Network[:]).Scan(&count) != nil {
				return a.ErrCoverage
			}
			removed := int64(current.Head.Number - common.Number)
			next = count - removed + int64(len(headers))
			if next < 1 || next > s.observerLimits.Headers {
				return a.ErrCoverage
			}
		}
		if reorg {
			if _, err := tx.Exec(ctx, `DELETE FROM ops_admission_v2.creation_headers WHERE network_key=$1 AND number>$2`, b.Lease.Network[:], common.Number); err != nil {
				return a.ErrUnavailable
			}
		}
		for _, h := range headers {
			if _, err := tx.Exec(ctx, `INSERT INTO ops_admission_v2.creation_headers(network_key,number,hash,parent_hash,timestamp)VALUES($1,$2,$3,$4,$5::numeric)`, b.Lease.Network[:], h.Number, h.Hash[:], h.Parent[:], strconv.FormatUint(h.Timestamp, 10)); err != nil {
				return dbError(err)
			}
		}
		lease := b.Lease
		if reorg || activate {
			lease.CaptureEpoch = uuid.NewString()
		}
		if reorg {
			current.ReorgEpoch++
		}
		caughtUp := head == tip
		ready := current.Ready || caughtUp
		quarantine := current.Quarantine
		if caughtUp {
			quarantine = "none"
		}
		if _, err := tx.Exec(ctx, `UPDATE ops_admission_v2.creation_observer_state SET ready=$2,quarantine=$3,head_number=$4,head_hash=$5,header_version=header_version+CASE WHEN $11 THEN 1 ELSE 0 END,reorg_epoch=$6,capture_epoch=$7::uuid,capture_ready=$8,known_tip_number=$9,known_tip_hash=$10,capture_heartbeat_until=CASE WHEN $8 THEN clock_timestamp()+interval'5 seconds' ELSE NULL END,last_confirmed=clock_timestamp() WHERE network_key=$1`, lease.Network[:], ready, quarantine, head.Number, head.Hash[:], current.ReorgEpoch, lease.CaptureEpoch, caughtUp, tip.Number, tip.Hash[:], advanceVersion); err != nil {
			return a.ErrUnavailable
		}
		if prefixChanged {
			if _, err := tx.Exec(ctx, `UPDATE ops_admission_v2.creation_capacity SET header_count=$2 WHERE network_key=$1`, lease.Network[:], next); err != nil {
				return a.ErrUnavailable
			}
		}
		current, err = observerLeaseState(ctx, tx, lease, false)
		if err != nil {
			return err
		}
		out = f.ObserverSnapshot{Lease: lease, State: current}
		return nil
	})
	return out, err
}

// QuarantineObserver is a closed, deny-only transition. There is deliberately
// no online clear-quarantine operation or permanent revocation INSERT here.
func (s *Store) QuarantineObserver(ctx context.Context, before f.ObserverSnapshot, reason string) error {
	if reason != "uncertain-capture-trust" && reason != "deep-reorg" && reason != "below-floor" && reason != "coverage-gap" && reason != "node-mismatch" {
		return a.ErrInvalid
	}
	return s.observerWrite(ctx, before.Lease.Network, true, func(ctx context.Context, tx pgx.Tx) error {
		current, err := observerLeaseState(ctx, tx, before.Lease, true)
		if err != nil {
			return err
		}
		if !sameObserverVersion(current, before.State) || current.HeaderVersion == math.MaxInt64 || current.LeaseFence == math.MaxInt64 {
			return a.ErrConflict
		}
		_, err = tx.Exec(ctx, `UPDATE ops_admission_v2.creation_observer_state SET ready=false,quarantine=$2,capture_ready=false,capture_heartbeat_until=NULL,capture_epoch=$3::uuid,header_version=header_version+1,lease_fence=lease_fence+1,lease_owner=NULL,lease_expires=NULL WHERE network_key=$1`, before.Lease.Network[:], reason, uuid.NewString())
		return dbError(err)
	})
}
