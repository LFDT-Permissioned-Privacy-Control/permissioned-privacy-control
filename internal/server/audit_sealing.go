package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"sync/atomic"
	"time"

	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/audit/buffer"
	"privacy-proxy/internal/audit/sealer"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"
)

// accessLogStore is what the sealing needs from the audit database
// (*db.AuditDB).
type accessLogStore interface {
	GetMaxAccessLogBufferSeq(ctx context.Context, chainName string) (uint64, error)
	GetLatestAccessLogHashForChain(ctx context.Context, chainName string) (string, error)
	SealBufferedAccessLog(ctx context.Context, chain db.RBACAuditChain, rec db.AccessLogRecord, bufferSeq uint64, chainName string) (string, error)
	SealBufferedAccessLogs(ctx context.Context, chain db.BatchAuditChain, records []db.BufferedAccessLog, chainName string) ([]db.SealedAccessLog, error)
	SealedAccessLogsBySeq(ctx context.Context, chainName string, seqs []uint64) ([]db.SealedAccessLogRow, error)
}

// siemSender hands an event to the SIEM forwarder (*audit.SIEMForwarder).
type siemSender interface {
	Send(audit.SIEMEvent)
}

// accessLogSealing is the single writer of this instance's access-log chain
// when the async audit buffer is enabled (RD-1112): the per-record and batch
// seal functions the sealer calls, and SIEM forwarding after each commit.
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
	// stale is set after a write whose outcome is unknown (an error after the
	// statement may have committed). The chain head is then re-read from the
	// database before the next seal, so the next entry never links to a head
	// that is not the stored one.
	stale atomic.Bool
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

func (a *accessLogSealing) highWater(ctx context.Context) (uint64, error) {
	return a.auditDB.GetMaxAccessLogBufferSeq(ctx, a.name)
}

// ready re-reads the chain head after an ambiguous write.
func (a *accessLogSealing) ready(ctx context.Context) error {
	if !a.stale.Load() {
		return nil
	}
	head, err := a.auditDB.GetLatestAccessLogHashForChain(ctx, a.name)
	if err != nil {
		return fmt.Errorf("reload access-log chain head: %w", err)
	}
	a.chain.Reset(head)
	a.stale.Store(false)
	return nil
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
	if err := a.ready(ctx); err != nil {
		return err
	}
	write, cancel := context.WithTimeout(context.WithoutCancel(ctx), sealCommitTimeout)
	defer cancel()
	hash, err := a.auditDB.SealBufferedAccessLog(write, a.chain, rec, seq, a.name)
	if err != nil {
		a.stale.Store(true)
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
	if err := a.ready(ctx); err != nil {
		return err
	}
	write, cancel := context.WithTimeout(context.WithoutCancel(ctx), sealCommitTimeout)
	defer cancel()
	sealed, err := a.auditDB.SealBufferedAccessLogs(write, a.chain, records, a.name)
	if err != nil {
		// The batch may have committed. The sealer re-seals it record by
		// record; if it had, those retries fail on the unique buffer
		// sequence, and settle forwards the rows the chain holds.
		a.stale.Store(true)
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
		rows, err := a.auditDB.SealedAccessLogsBySeq(read, a.name, chunk)
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
		row.CorrelationID == want.CorrelationID && row.IPAddress == want.IPAddress && stored == response
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
