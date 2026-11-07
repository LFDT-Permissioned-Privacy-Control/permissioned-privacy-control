package activitysql

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	a "privacy-proxy/internal/activitylog"
	"privacy-proxy/internal/identity"
)

type Cut struct {
	Metadata                   a.StoreMetadata
	Reference, Epoch, Coverage string
	HeadID                     int64
	HeadHash                   string
	RetainedFromMicros         int64
	AsOf                       time.Time
}
type ReadQuery struct {
	Organization              string
	Actors                    []string
	FromMicros, ThroughMicros int64
	Limit                     int
}
type PageKey struct {
	ObservedMicros    int64
	ProducerID, RunID string
	Ordinal           int64
	RecordID          string
}
type ActivityRow struct{ Envelope a.Envelope }
type MethodCount struct {
	Method                    string
	Total, Successful, Failed uint64
}
type ReadSnapshot struct {
	reader *Reader
	tx     pgx.Tx
	ctx    context.Context
	cancel context.CancelFunc
	cut    Cut
	from   int64
	mu     sync.Mutex
	closed bool
}

func framedHash(domain string, parts ...[]byte) string {
	h := sha256.New()
	for _, p := range append([][]byte{[]byte(domain)}, parts...) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(p)))
		h.Write(n[:])
		h.Write(p)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
func makeCut(s sourceState, id int64, hash string, asOf time.Time) Cut {
	m := s.metadata
	ref := "sha256:" + hash
	if id == 0 {
		ref = framedHash("ops-activity-empty-head/v1", m.NetworkKey[:], []byte(m.SourceID), []byte(m.Generation))
	}
	h, _ := hex.DecodeString(hash)
	return Cut{Metadata: m, Reference: ref, Epoch: framedHash("ops-activity-epoch/v1", m.NetworkKey[:], []byte(m.SourceID), []byte(m.Generation)), Coverage: framedHash("ops-activity-chain-cut/v1", m.NetworkKey[:], []byte(m.SourceID), []byte(m.Generation), m.Configuration[:], []byte(strconv.FormatInt(id, 10)), h), HeadID: id, HeadHash: hash, RetainedFromMicros: s.floor, AsOf: asOf.UTC().Truncate(time.Microsecond)}
}
func (r *Reader) readState(ctx context.Context, tx pgx.Tx) (sourceState, error) {
	s, err := selected(ctx, tx, r.scope, false, true)
	if err != nil {
		return s, err
	}
	if s.metadata != r.state.metadata || s.roles != r.state.roles {
		return s, a.ErrUnavailable
	}
	if err := checkSchema(ctx, tx); err != nil {
		return s, err
	}
	if err := checkRole(ctx, tx, s.roles, "reader"); err != nil {
		return s, err
	}
	if err := checkHead(ctx, tx, s, "reader"); err != nil {
		return s, err
	}
	return s, nil
}
func resolveCut(ctx context.Context, tx pgx.Tx, s sourceState, reference string) (int64, string, error) {
	if reference == "" {
		return s.headID, s.headHash, nil
	}
	empty := makeCut(s, 0, "", time.Time{}).Reference
	if reference == empty {
		return 0, "", nil
	}
	if len(reference) != 71 || reference[:7] != "sha256:" {
		return 0, "", a.ErrInvalid
	}
	hash := reference[7:]
	if _, err := a.ParseDigestHex(hash); err != nil {
		return 0, "", a.ErrInvalid
	}
	l, err := scanLog(tx.QueryRow(ctx, `SELECT `+logColumns+` FROM ops_activity_v1.qualified_logs WHERE chain_name=$1 AND entry_hash=$2 AND activity_kind=1 LIMIT 1`, s.chain, hash))
	if err == nil {
		runs, err := loadRuns(ctx, tx, []string{l.run})
		if err != nil || !registered(runs[l.run], l.envelope, uint64(l.seq), s) || l.id > s.headID {
			return 0, "", a.ErrUnavailable
		}
		return l.id, l.hash, nil
	}
	id, h, err := anchor(ctx, tx, s.chain)
	if err != nil || id < 1 || h != hash {
		return 0, "", a.ErrUnavailable
	}
	return id, h, nil
}

// Open pins one committed SQL prefix. It never waits for local producers or
// claims that the prefix contains unlogged or still buffered RPC requests.
func (r *Reader) Open(ctx context.Context, reference string, fromMicros int64) (*ReadSnapshot, error) {
	if r == nil || r.store == nil || fromMicros < 0 || fromMicros > a.MaxObservedMicros {
		return nil, a.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	tx, err := begin(ctx, r.pool, true)
	if err != nil {
		cancel()
		return nil, err
	}
	s, err := r.readState(ctx, tx)
	if err != nil {
		rollback(tx)
		cancel()
		return nil, err
	}
	if fromMicros < s.floor {
		rollback(tx)
		cancel()
		return nil, a.ErrUnavailable
	}
	id, hash, err := resolveCut(ctx, tx, s, reference)
	if err != nil {
		rollback(tx)
		cancel()
		return nil, err
	}
	return &ReadSnapshot{reader: r, tx: tx, ctx: ctx, cancel: cancel, cut: makeCut(s, id, hash, time.Now()), from: fromMicros}, nil
}
func (s *ReadSnapshot) Cut() Cut { return s.cut }
func (s *ReadSnapshot) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		rollback(s.tx)
		s.cancel()
	}
}
func validRead(q ReadQuery) bool {
	if !a.CanonicalUUID(q.Organization) || len(q.Actors) < 1 || len(q.Actors) > 256 || q.FromMicros < 0 || q.ThroughMicros < q.FromMicros || q.ThroughMicros > a.MaxObservedMicros {
		return false
	}
	for i, actor := range q.Actors {
		if !identity.ValidActorID(actor) || i > 0 && q.Actors[i-1] >= actor {
			return false
		}
	}
	return true
}
func validKey(k *PageKey) bool {
	return k == nil || k.ObservedMicros >= 0 && k.ObservedMicros <= a.MaxObservedMicros && a.CanonicalUUID(k.ProducerID) && a.CanonicalUUID(k.RunID) && a.CanonicalUUID(k.RecordID) && k.Ordinal > 0
}
func (s *ReadSnapshot) ReadPage(ctx context.Context, q ReadQuery, after *PageKey) ([]ActivityRow, bool, error) {
	if s == nil || !validRead(q) || q.Limit < 1 || q.Limit > 100 || !validKey(after) || q.FromMicros != s.from || after != nil && (after.ObservedMicros < q.FromMicros || after.ObservedMicros > q.ThroughMicros) {
		return nil, false, a.ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ctx.Err() != nil || ctx.Err() != nil {
		return nil, false, a.ErrUnavailable
	}
	k := PageKey{ProducerID: "00000000-0000-0000-0000-000000000000", RunID: "00000000-0000-0000-0000-000000000000", RecordID: "00000000-0000-0000-0000-000000000000"}
	if after != nil {
		k = *after
	}
	rows, err := s.tx.Query(s.ctx, `SELECT `+logColumns+` FROM ops_activity_v1.qualified_logs WHERE chain_name=$1 AND id<=$2 AND activity_kind=1 AND org_id=$3 AND external_id=ANY($4::text[]) AND activity_observed_us>=$5 AND activity_observed_us<=$6 AND ($7::boolean OR(activity_observed_us,activity_producer_id,activity_run_id,activity_ordinal,activity_record_id)>($8,$9::uuid,$10::uuid,$11,$12::uuid)) ORDER BY activity_observed_us,activity_producer_id,activity_run_id,activity_ordinal,activity_record_id LIMIT $13`, s.reader.state.chain, s.cut.HeadID, q.Organization, q.Actors, q.FromMicros, q.ThroughMicros, after == nil, k.ObservedMicros, k.ProducerID, k.RunID, k.Ordinal, k.RecordID, q.Limit+1)
	if err != nil {
		return nil, false, a.ErrUnavailable
	}
	page := make([]logRow, 0, q.Limit+1)
	ids := []string{}
	for rows.Next() {
		l, err := scanLog(rows)
		if err != nil {
			rows.Close()
			return nil, false, err
		}
		page = append(page, l)
		ids = append(ids, l.run)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, false, a.ErrUnavailable
	}
	out := make([]ActivityRow, 0, min(q.Limit, len(page)))
	if len(page) > 0 {
		runs, err := loadRuns(s.ctx, s.tx, ids)
		if err != nil {
			return nil, false, err
		}
		for _, l := range page {
			if !registered(runs[l.run], l.envelope, uint64(l.seq), s.reader.state) {
				return nil, false, a.ErrUnavailable
			}
		}
	}
	end := len(page) <= q.Limit
	for _, l := range page[:min(len(page), q.Limit)] {
		out = append(out, ActivityRow{Envelope: l.envelope})
	}
	return out, end, nil
}
func (s *ReadSnapshot) Summary(ctx context.Context, q ReadQuery) ([]MethodCount, error) {
	if s == nil || !validRead(q) || q.Limit != 0 || q.FromMicros != s.from {
		return nil, a.ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ctx.Err() != nil || ctx.Err() != nil {
		return nil, a.ErrUnavailable
	}
	rows, err := s.tx.Query(s.ctx, `SELECT method,count(*),count(*)FILTER(WHERE activity_outcome='success'),count(*)FILTER(WHERE activity_outcome<>'success') FROM ops_activity_v1.qualified_logs WHERE chain_name=$1 AND id<=$2 AND activity_kind=1 AND org_id=$3 AND external_id=ANY($4::text[]) AND activity_observed_us>=$5 AND activity_observed_us<=$6 GROUP BY method ORDER BY method COLLATE "C" LIMIT 513`, s.reader.state.chain, s.cut.HeadID, q.Organization, q.Actors, q.FromMicros, q.ThroughMicros)
	if err != nil {
		return nil, a.ErrUnavailable
	}
	defer rows.Close()
	out := []MethodCount{}
	for rows.Next() {
		var method string
		var total, success, failed int64
		if rows.Scan(&method, &total, &success, &failed) != nil || !a.ValidMethod(method) || total < 0 || success < 0 || failed < 0 || success > total || failed != total-success {
			return nil, a.ErrUnavailable
		}
		if len(out) >= 512 {
			return nil, a.ErrTooBroad
		}
		out = append(out, MethodCount{method, uint64(total), uint64(success), uint64(failed)})
	}
	if rows.Err() != nil {
		return nil, a.ErrUnavailable
	}
	return out, nil
}

// CheckCurrent is a fresh sampled gate, independent of the closed read TX. It
// does not hold a fleet-wide fence through case-audit commit or HTTP delivery.
func (s *ReadSnapshot) CheckCurrent(ctx context.Context) error {
	if s == nil {
		return a.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := begin(ctx, s.reader.pool, true)
	if err != nil {
		return err
	}
	defer rollback(tx)
	state, err := s.reader.readState(ctx, tx)
	if err != nil {
		return err
	}
	if s.from < state.floor {
		return a.ErrUnavailable
	}
	id, hash, err := resolveCut(ctx, tx, state, s.cut.Reference)
	if err != nil || id != s.cut.HeadID || hash != s.cut.HeadHash {
		return a.ErrUnavailable
	}
	if tx.Commit(ctx) != nil {
		return a.ErrUnavailable
	}
	return nil
}
