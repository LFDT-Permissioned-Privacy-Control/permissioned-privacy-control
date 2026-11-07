package admissionsql

import (
	"context"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	a "privacy-proxy/internal/admission"
	"privacy-proxy/internal/creationfacts"
)

const coverageColumns = `version,policy,network_key,admission_generation::text,state_coverage,observer_epoch::text,capture_epoch::text,source_set_digest,reference_binding_digest,ingress_binding_digest,h_number,h_hash,h_parent,h_timestamp::text,latest_number,latest_hash,latest_parent,latest_timestamp::text,header_version,lease_fence,probe_started_at,probe_finished_at,valid_until,record_digest,logical_bytes,plan_version`

type coverageScan struct {
	r                                                                                  creationfacts.CoverageRecord
	network, state, source, reference, ingress, hHash, hParent, lHash, lParent, digest []byte
	hTime, lTime                                                                       string
	logical, planVersion                                                               int
}

func (s *coverageScan) destinations() []any {
	return []any{&s.r.Version, &s.r.Policy, &s.network, &s.r.State.Generation, &s.state, &s.r.ObserverEpoch, &s.r.CaptureEpoch, &s.source, &s.reference, &s.ingress, &s.r.HighWater.Number, &s.hHash, &s.hParent, &s.hTime, &s.r.Latest.Number, &s.lHash, &s.lParent, &s.lTime, &s.r.HeaderVersion, &s.r.LeaseFence, &s.r.ProbeStarted, &s.r.ProbeFinished, &s.r.ValidUntil, &s.digest, &s.logical, &s.planVersion}
}
func (s *coverageScan) finish() (creationfacts.CoverageRecord, error) {
	for _, b := range [][]byte{s.network, s.state, s.source, s.reference, s.ingress, s.hHash, s.hParent, s.lHash, s.lParent, s.digest} {
		if len(b) != 32 {
			return creationfacts.CoverageRecord{}, a.ErrCoverage
		}
	}
	if s.planVersion != 2 || len(s.hTime) > 20 || len(s.lTime) > 20 {
		return creationfacts.CoverageRecord{}, a.ErrCoverage
	}
	copy(s.r.Network[:], s.network)
	copy(s.r.State.Coverage[:], s.state)
	copy(s.r.SourceSet[:], s.source)
	copy(s.r.Reference[:], s.reference)
	copy(s.r.Ingress[:], s.ingress)
	copy(s.r.HighWater.Hash[:], s.hHash)
	copy(s.r.HighWater.Parent[:], s.hParent)
	copy(s.r.Latest.Hash[:], s.lHash)
	copy(s.r.Latest.Parent[:], s.lParent)
	var err error
	s.r.HighWater.Timestamp, err = strconv.ParseUint(s.hTime, 10, 64)
	if err != nil {
		return creationfacts.CoverageRecord{}, a.ErrCoverage
	}
	s.r.Latest.Timestamp, err = strconv.ParseUint(s.lTime, 10, 64)
	if err != nil {
		return creationfacts.CoverageRecord{}, a.ErrCoverage
	}
	s.r.ProbeStarted = s.r.ProbeStarted.UTC()
	s.r.ProbeFinished = s.r.ProbeFinished.UTC()
	s.r.ValidUntil = s.r.ValidUntil.UTC()
	raw, err := s.r.Canonical()
	d := s.r.Digest()
	if err != nil || len(raw) != s.logical || string(d[:]) != string(s.digest) {
		return creationfacts.CoverageRecord{}, a.ErrCoverage
	}
	return s.r, nil
}

func (t *rawTx) originalCoverage(seed a.Digest, anchor common.Hash, number uint64) error {
	var scan coverageScan
	if err := t.tx.QueryRow(t.ctx, `SELECT `+coverageColumns+` FROM ops_admission_v2.creation_capture_coverage WHERE network_key=$1 AND tx_hash=$2 AND seed_digest=$3`, t.scope.Network[:], t.scope.Hash[:], seed[:]).Scan(scan.destinations()...); err != nil {
		return a.ErrCoverage
	}
	r, err := scan.finish()
	if err != nil || r.Network != creationfacts.Digest(t.scope.Network) || r.Latest.Number < number || r.HighWater.Number > number || (r.HighWater.Number == number && r.HighWater.Hash != anchor) {
		return a.ErrCoverage
	}
	var revoked bool
	if err := t.tx.QueryRow(t.ctx, `SELECT EXISTS(SELECT 1 FROM ops_admission_v2.revoked_creation_capture_epochs WHERE network_key=$1 AND capture_epoch=$2::uuid)`, t.scope.Network[:], r.CaptureEpoch).Scan(&revoked); err != nil || revoked {
		return a.ErrCoverage
	}
	return nil
}

func (t *rawTx) insertCoverage(seed a.Digest, r creationfacts.CoverageRecord) error {
	raw, err := r.Canonical()
	if err != nil {
		return a.ErrInvalid
	}
	d := r.Digest()
	_, err = t.tx.Exec(t.ctx, `INSERT INTO ops_admission_v2.creation_capture_coverage(network_key,tx_hash,seed_digest,version,policy,plan_version,admission_generation,state_coverage,observer_epoch,capture_epoch,source_set_digest,reference_binding_digest,ingress_binding_digest,h_number,h_hash,h_parent,h_timestamp,latest_number,latest_hash,latest_parent,latest_timestamp,header_version,lease_fence,probe_started_at,probe_finished_at,valid_until,record_digest,logical_bytes)VALUES($1,$2,$3,1,$4,2,$5::uuid,$6,$7::uuid,$8::uuid,$9,$10,$11,$12,$13,$14,$15::numeric,$16,$17,$18,$19::numeric,$20,$21,$22,$23,$24,$25,$26)`, t.scope.Network[:], t.scope.Hash[:], seed[:], r.Policy, r.State.Generation, r.State.Coverage[:], r.ObserverEpoch, r.CaptureEpoch, r.SourceSet[:], r.Reference[:], r.Ingress[:], r.HighWater.Number, r.HighWater.Hash[:], r.HighWater.Parent[:], strconv.FormatUint(r.HighWater.Timestamp, 10), r.Latest.Number, r.Latest.Hash[:], r.Latest.Parent[:], strconv.FormatUint(r.Latest.Timestamp, 10), r.HeaderVersion, r.LeaseFence, r.ProbeStarted, r.ProbeFinished, r.ValidUntil, d[:], len(raw))
	if err != nil {
		return dbError(err)
	}
	return nil
}

func (t *rawTx) coverageUsage(ctx context.Context) (int64, int64, error) {
	var rows, bytes int64
	if err := t.tx.QueryRow(ctx, `SELECT capture_coverage_count,capture_coverage_bytes FROM ops_admission_v2.creation_capacity WHERE network_key=$1`, t.scope.Network[:]).Scan(&rows, &bytes); err != nil {
		return 0, 0, a.ErrUnavailable
	}
	return rows, bytes, nil
}

func (t *rawTx) PutCoveredCreationIntent(i a.CreationIntent, r creationfacts.CoverageRecord) (a.CreationIntentReceipt, error) {
	if t.capture == nil || !t.capture.Valid() || r.Network != creationfacts.Digest(t.scope.Network) || r.State.Generation != t.scope.State.Generation || r.State.Coverage != creationfacts.Digest(t.scope.State.Coverage) || r.ObserverEpoch != t.capture.ObserverEpoch || r.CaptureEpoch != t.capture.CaptureEpoch || r.SourceSet != t.capture.SourceSet || r.HighWater.Number > i.Anchor.Number || (r.HighWater.Number == i.Anchor.Number && r.HighWater.Hash != i.Anchor.Hash) || r.Latest.Number < i.Anchor.Number || i.Anchor.Number > uint64(1<<63-1) {
		return a.CreationIntentReceipt{}, a.ErrInvalid
	}
	if _, err := r.Canonical(); err != nil {
		return a.CreationIntentReceipt{}, a.ErrInvalid
	}
	return t.putCreationIntent(i, &r)
}

var _ a.CoveredCreationRawTx = (*rawTx)(nil)
var _ a.CreationCoveredStore = (*Store)(nil)
