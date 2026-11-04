package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/audit/buffer"
	"privacy-proxy/internal/audit/sealer"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/metrics"
	"privacy-proxy/internal/rbac"

	"github.com/prometheus/client_golang/prometheus"
)

// accessLogStore is what the sealing needs from the audit database
// (*db.AuditDB).
type accessLogStore interface {
	ReserveAccessLogBufferRange(ctx context.Context) (uint64, error)
	MaxAccessLogBufferSeqBetween(ctx context.Context, lo, hi uint64) (uint64, error)
	MaxChainAccessLogBufferSeqBelow(ctx context.Context, chainName string, limit uint64) (uint64, error)
	SealBufferedAccessLog(ctx context.Context, chain db.AccessLogChain, rec db.AccessLogRecord, bufferSeq uint64, chainName string) (string, error)
	SealBufferedAccessLogs(ctx context.Context, chain db.AccessLogChain, records []db.BufferedAccessLog, chainName string) ([]db.SealedAccessLog, error)
	SealedAccessLogsBySeq(ctx context.Context, chainName string, seqs []uint64) ([]db.SealedAccessLogRow, error)
}

// siemSender hands an event to the SIEM forwarder (*audit.SIEMForwarder).
type siemSender interface {
	Send(audit.SIEMEvent)
}

// accessLogSealing is this instance's writer of its access-log chain when
// the async audit buffer is enabled (RD-1112): the per-record and batch seal
// functions the sealer calls, and SIEM forwarding after each commit.
//
// Several instances may share an audit database and even a chain name
// (RD-1410): each numbers its entries in an allocation range of its own
// (audit/004), so its resume point is its range's sealed high-water, and each
// write links to the chain head it reads under the chain's transaction lock,
// so writers of one chain never fork it.
//
// Every sealed row is handed to the SIEM forwarder at least once while the
// sealer runs (RD-1410), including rows sealed before a restart whose buffer
// entries were still there. A write whose outcome was unknown (an error after
// the statement may have committed) leaves its records unsettled; settle
// later forwards the rows it finds in the chain for them, and a later
// successful seal of the same sequence forwards it as usual. A duplicate
// event is possible and acceptable; the forwarder's own overload and shutdown
// bounds still apply after hand-over.
type accessLogSealing struct {
	auditDB accessLogStore
	chain   *audit.HashChain
	name    string
	siem    siemSender
	// base and top bound this run's allocation range (base+1 .. top).
	base, top uint64
	// unsettled holds the (clamped) records of seal writes whose outcome was
	// unknown, by buffer sequence. Only the sealer's goroutine uses it.
	unsettled map[uint64]db.AccessLogRecord
	// settleFailedAt is when the last settle read failed (zero after success).
	settleFailedAt time.Time
}

// settleTimeout bounds one settle read; a failed read is retried next tick
// and never holds up sealing.
const settleTimeout = 5 * time.Second

// sealCommitTimeout bounds one seal write. The write runs detached from the
// sealer's context, so a shutdown does not cancel it mid-commit.
const sealCommitTimeout = 30 * time.Second

// rangeSize is the number of sequences in one allocation range.
const rangeSize = uint64(1) << buffer.RangeShift

// maxRangeDraws bounds how often a starting instance draws again when the
// audit database hands out a range that is already in use (a database
// restored from a backup older than its last starts).
const maxRangeDraws = 64

// ReasonAuditSealingStopped is the /ready reason while the async audit
// buffer's sealing has stopped (chain refused, or stalled).
const ReasonAuditSealingStopped = "audit_sealing_stopped"

// auditSealingStopped reports whether the async audit buffer's sealing has
// stopped: records are still buffered durably, but none reaches the audit
// database, so the instance reports not ready (fail closed).
func (s *Server) auditSealingStopped() bool {
	return s.auditSealer != nil && s.auditSealer.State().Stopped
}

// registerAuditSealingMetrics exposes the sealer's state as gauges.
func registerAuditSealingMetrics(reg prometheus.Registerer, s *sealer.Sealer) {
	metrics.RegisterAuditSealing(reg, func() metrics.AuditSealingState {
		st := s.State()
		return metrics.AuditSealingState{Stopped: st.Stopped, Reason: st.Reason, Backlog: st.Backlog, LastProgress: st.LastProgress}
	})
}

// openAccessLogSealing opens the async audit buffer at dir and the sealer of
// chain, as a starting server does (RD-1410): it draws this run's allocation
// range from the audit database, seeds the buffer with it before any append,
// and wires the sealer to resume every earlier range from its own sealed
// high-water. tune adjusts the sealer configuration (tests).
func openAccessLogSealing(ctx context.Context, store accessLogStore, dir, chain string, siem siemSender, tune func(*sealer.Config)) (*buffer.Buffer, *sealer.Sealer, *accessLogSealing, error) {
	buf, err := buffer.Open(dir, buffer.RequireSeed())
	if err != nil {
		return nil, nil, nil, fmt.Errorf("async audit buffer init (AUDIT_BUFFER_DIR=%q): %w", dir, err)
	}
	base, top, err := reserveBufferRange(ctx, store, buf.AllocatedThrough())
	if err == nil {
		err = buf.SeedRange(base, top)
	}
	if err != nil {
		_ = buf.Close()
		return nil, nil, nil, fmt.Errorf("async audit buffer: %w", err)
	}
	sealing := &accessLogSealing{auditDB: store, chain: audit.NewHashChain(""), name: chain, siem: siem, base: base, top: top}
	// A tick works through earlier runs' entries first, then drains this
	// run's backlog in multi-row batch writes; a failed batch is sealed
	// record by record, stopping at the failing one. Settle forwards rows
	// whose seal outcome the sealer could not observe.
	cfg := sealer.Config{SealBatch: sealing.sealBatch, Settle: sealing.settle, RangeBase: base, RangeHighWater: sealing.rangeHighWater, Verify: sealing.verify, OnMove: sealing.moved}
	if tune != nil {
		tune(&cfg)
	}
	return buf, sealer.New(buf, sealing.seal, sealing.highWater, cfg), sealing, nil
}

// reserveBufferRange draws this run's allocation range. A range is drawn
// again when it does not start above the buffer's own entries or already
// holds rows, which only a restored audit database (its sequence moved back)
// produces; after maxRangeDraws it refuses with the remedy.
func reserveBufferRange(ctx context.Context, store accessLogStore, allocated uint64) (uint64, uint64, error) {
	for draw := 0; draw < maxRangeDraws; draw++ {
		n, err := store.ReserveAccessLogBufferRange(ctx)
		if err != nil {
			return 0, 0, err
		}
		base := n << buffer.RangeShift
		top := base + rangeSize - 1
		if base < allocated {
			// Drawing again cannot catch up: the buffer was numbered in a
			// range the database has not handed out yet (it was restored).
			return 0, 0, fmt.Errorf("the audit database handed out allocation range %d, below this buffer's own entries (range %d): it was restored from a backup; advance access_logs_buffer_range_seq to at least %d before starting (see the audit-integrity documentation)", n, allocated>>buffer.RangeShift, allocated>>buffer.RangeShift+1)
		}
		used, err := store.MaxAccessLogBufferSeqBetween(ctx, base, top)
		if err != nil {
			return 0, 0, err
		}
		if used == 0 {
			return base, top, nil
		}
	}
	return 0, 0, fmt.Errorf("the audit database keeps handing out allocation ranges that are already in use (was it restored from a backup?): advance access_logs_buffer_range_seq past every range in use before starting (see the audit-integrity documentation)")
}

// highWater is this run's sealed high-water: within its own range only this
// buffer writes, so the range's highest stored sequence is exact.
func (a *accessLogSealing) highWater(ctx context.Context) (uint64, error) {
	return a.auditDB.MaxAccessLogBufferSeqBetween(ctx, a.base+1, a.top)
}

// rangeHighWater is the sealed high-water of an earlier run's range; range 0
// holds the entries numbered per chain before ranges existed.
func (a *accessLogSealing) rangeHighWater(ctx context.Context, index uint64) (uint64, error) {
	if index == 0 {
		return a.auditDB.MaxChainAccessLogBufferSeqBelow(ctx, a.name, rangeSize)
	}
	lo := index << buffer.RangeShift
	return a.auditDB.MaxAccessLogBufferSeqBetween(ctx, lo, lo+rangeSize-1)
}

// moved forgets what was tracked under an entry's old sequence: the record
// under it is not this entry's, so settling it would compare a foreign row.
func (a *accessLogSealing) moved(from, _ uint64) {
	delete(a.unsettled, from)
}

// verify compares earlier entries with the rows stored under their
// sequences in any chain (sealer.Config.Verify). A corrupt entry, which is
// never sealed, counts as sealed.
func (a *accessLogSealing) verify(ctx context.Context, entries []buffer.Entry) ([]sealer.Verdict, error) {
	seqs := make([]uint64, len(entries))
	for i, e := range entries {
		seqs[i] = e.Seq
	}
	read, cancel := context.WithTimeout(context.WithoutCancel(ctx), settleTimeout)
	defer cancel()
	rows, err := a.auditDB.SealedAccessLogsBySeq(read, "", seqs)
	if err != nil {
		return nil, err
	}
	stored := make(map[uint64]db.SealedAccessLogRow, len(rows))
	for _, r := range rows {
		stored[r.Seq] = r
	}
	out := make([]sealer.Verdict, len(entries))
	for i, e := range entries {
		rec, ok := decodeBuffered(e.Seq, e.Data)
		row, found := stored[e.Seq]
		switch {
		case !ok:
			out[i] = sealer.Sealed
		case !found:
			out[i] = sealer.Missing
		case sameSealedRecord(row, db.ClampAccessLogRecord(rec)):
			out[i] = sealer.Sealed
		default:
			out[i] = sealer.Foreign
		}
	}
	return out, nil
}

func decodeBuffered(seq uint64, data []byte) (db.AccessLogRecord, bool) {
	var rec db.AccessLogRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		// A corrupt buffered record must not wedge the sealer. Log loudly and
		// skip it; the high-water advances past it on the next drain.
		slog.Error("audit sealer: corrupt buffered record skipped", "seq", seq, "error", err)
		return rec, false
	}
	return rec, true
}

func (a *accessLogSealing) seal(ctx context.Context, seq uint64, data []byte) error {
	rec, ok := decodeBuffered(seq, data)
	if !ok {
		return nil
	}
	write, cancel := context.WithTimeout(context.WithoutCancel(ctx), sealCommitTimeout)
	defer cancel()
	hash, err := a.auditDB.SealBufferedAccessLog(write, a.chain, rec, seq, a.name)
	if err != nil {
		a.unsettle(seq, rec)
		return err
	}
	a.settled(seq)
	a.forward(db.ClampAccessLogRecord(rec), hash, time.Now().UTC())
	return nil
}

func (a *accessLogSealing) sealBatch(ctx context.Context, entries []buffer.Entry) error {
	records := make([]db.BufferedAccessLog, 0, len(entries))
	for _, e := range entries {
		if rec, ok := decodeBuffered(e.Seq, e.Data); ok {
			records = append(records, db.BufferedAccessLog{Seq: e.Seq, Record: rec})
		}
	}
	if len(records) == 0 {
		return nil
	}
	write, cancel := context.WithTimeout(context.WithoutCancel(ctx), sealCommitTimeout)
	defer cancel()
	sealed, err := a.auditDB.SealBufferedAccessLogs(write, a.chain, records, a.name)
	if err != nil {
		// The batch may have committed. The sealer re-seals it record by
		// record; if it had, those retries fail on the unique buffer
		// sequence, and settle forwards the rows the chain holds.
		for _, rec := range records {
			a.unsettle(rec.Seq, rec.Record)
		}
		return err
	}
	for i, rec := range records {
		a.settled(rec.Seq)
		a.forward(db.ClampAccessLogRecord(rec.Record), sealed[i].Hash, sealed[i].CreatedAt)
	}
	return nil
}

func (a *accessLogSealing) unsettle(seq uint64, rec db.AccessLogRecord) {
	if a.siem == nil {
		return
	}
	if a.unsettled == nil {
		a.unsettled = map[uint64]db.AccessLogRecord{}
	}
	a.unsettled[seq] = db.ClampAccessLogRecord(rec)
}

func (a *accessLogSealing) settled(seq uint64) {
	delete(a.unsettled, seq)
}

// settle is the sealer's Settle hook. It adds the recovered entries (sealed
// before a restart, possibly never forwarded) to the unsettled records, reads
// the chain rows sealed under the unsettled sequences and forwards each one
// that is this instance's record. A row under the same sequence with other
// content is another writer's: the sealer stops (ErrChainAhead) and keeps its
// own entries. A sequence at or below highWater (read before this query)
// without a row can no longer appear: the single writer seals in order, so
// its fate was decided (or its row was pruned); it is dropped with an error.
// It returns the lowest sequence still unsettled, which the sealer keeps in
// the buffer so a crash cannot lose it.
func (a *accessLogSealing) settle(ctx context.Context, highWater uint64, recovered []buffer.Entry) (uint64, error) {
	if a.siem == nil {
		return 0, nil
	}
	for _, e := range recovered {
		if rec, ok := decodeBuffered(e.Seq, e.Data); ok {
			a.unsettle(e.Seq, rec)
		}
	}
	if len(a.unsettled) == 0 {
		return 0, nil
	}
	// Against a degraded database, one bounded read per second, not two per tick.
	if !a.settleFailedAt.IsZero() && time.Since(a.settleFailedAt) < time.Second {
		return a.lowestUnsettled(), nil
	}
	seqs := make([]uint64, 0, len(a.unsettled))
	for seq := range a.unsettled {
		seqs = append(seqs, seq)
	}
	slices.Sort(seqs)
	found := make(map[uint64]bool, len(seqs))
	for chunk := range slices.Chunk(seqs, settleChunk) {
		read, cancel := context.WithTimeout(context.WithoutCancel(ctx), settleTimeout)
		// Any chain: an earlier run may have sealed under another chain
		// name, and the content comparison below tells records apart.
		rows, err := a.auditDB.SealedAccessLogsBySeq(read, "", chunk)
		cancel()
		if err != nil {
			a.settleFailedAt = time.Now()
			slog.Warn("audit sealer: could not read back sealed records for SIEM forwarding (retried; their buffer entries are kept)", "pending", len(a.unsettled), "error", err)
			return a.lowestUnsettled(), nil
		}
		for _, row := range rows {
			want, ok := a.unsettled[row.Seq]
			if !ok {
				continue
			}
			if !sameSealedRecord(row, want) {
				return a.lowestUnsettled(), fmt.Errorf("%w: the chain row under buffer sequence %d holds another writer's record", sealer.ErrChainAhead, row.Seq)
			}
			found[row.Seq] = true
			delete(a.unsettled, row.Seq)
			a.forward(db.AccessLogRecord{ExternalID: row.ExternalID, Method: row.Method, StatusCode: row.StatusCode, ResponseStatus: row.ResponseStatus, IPAddress: row.IPAddress, CorrelationID: row.CorrelationID}, row.EntryHash, row.CreatedAt)
		}
	}
	a.settleFailedAt = time.Time{}
	for _, seq := range seqs {
		if !found[seq] && seq <= highWater {
			delete(a.unsettled, seq)
			slog.Error("audit sealer: a record whose seal outcome was unknown is not in the chain at or below its high-water; nothing to forward", "seq", seq, "chain", a.name)
		}
	}
	return a.lowestUnsettled(), nil
}

// settleChunk bounds the sequences of one settle read.
const settleChunk = 2000

func (a *accessLogSealing) lowestUnsettled() uint64 {
	var low uint64
	for seq := range a.unsettled {
		if low == 0 || seq < low {
			low = seq
		}
	}
	return low
}

// sameSealedRecord compares a stored row with the (clamped) record this
// instance wrote under its sequence.
func sameSealedRecord(row db.SealedAccessLogRow, want db.AccessLogRecord) bool {
	response := want.StatusCode
	if want.ResponseStatus != nil {
		response = *want.ResponseStatus
	}
	stored := row.StatusCode
	if row.ResponseStatus != nil {
		stored = *row.ResponseStatus
	}
	return row.ExternalID == want.ExternalID && row.Method == want.Method && row.StatusCode == want.StatusCode &&
		row.CorrelationID == want.CorrelationID && row.IPAddress == want.IPAddress && stored == response &&
		row.Params == string(want.Params) && row.OrgID == want.OrgID && row.DenialReason == want.DenialReason
}

// forward sends the sealed record to the SIEM (off the request path).
func (a *accessLogSealing) forward(rec db.AccessLogRecord, hash string, sealedAt time.Time) {
	if a.siem == nil {
		return
	}
	outcome := "success"
	if rec.StatusCode >= 400 {
		outcome = "denied"
	}
	if rec.StatusCode >= 500 {
		outcome = "error"
	}
	respStatus := rec.StatusCode
	if rec.ResponseStatus != nil {
		respStatus = *rec.ResponseStatus
	}
	ev := audit.SIEMEvent{
		Timestamp:     sealedAt,
		EventType:     "access",
		CorrelationID: rec.CorrelationID,
		ActorID:       rec.ExternalID,
		Action:        rec.Method,
		Outcome:       outcome,
		Details:       fmt.Sprintf("decision=%d response=%d", rec.StatusCode, respStatus),
		SourceIP:      rec.IPAddress,
		EntryHash:     hash,
	}
	if rbac.IsPassthroughMethod(rec.Method) {
		ev.MatchedVia = "passthrough"
	}
	a.siem.Send(ev)
}
