package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/audit/buffer"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"
)

// accessLogSealing is the single writer of this instance's access-log chain
// when the async audit buffer is enabled (RD-1112): the per-record and batch
// seal functions the sealer calls, and SIEM forwarding after each commit.
type accessLogSealing struct {
	auditDB *db.AuditDB
	chain   *audit.HashChain
	name    string
	siem    *audit.SIEMForwarder
	// stale is set after a write whose outcome is unknown (an error after the
	// statement may have committed). The chain head is then re-read from the
	// database before the next seal, so the next entry never links to a head
	// that is not the stored one.
	stale atomic.Bool
}

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
		return err
	}
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
		a.stale.Store(true)
		return err
	}
	// A batch whose commit outcome was unknown is re-sealed record by record;
	// if it had in fact committed, that retry fails on the unique buffer
	// sequence and those rows are not forwarded to the SIEM (the chain holds
	// them).
	for i, rec := range records {
		a.forward(db.ClampAccessLogRecord(rec.Record), sealed[i].Hash, sealed[i].CreatedAt)
	}
	return nil
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
