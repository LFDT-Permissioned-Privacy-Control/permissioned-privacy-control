package activitysql

import (
	"context"
	"encoding/hex"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	a "privacy-proxy/internal/activitylog"
)

type logRow struct {
	id                                                                               int64
	actor, method, ip, correlation, hash, chain, org, run, producer, record, outcome string
	status, http, format, kind                                                       int
	at                                                                               time.Time
	params                                                                           string
	seq, ordinal                                                                     int64
	observed                                                                         int64
	envelope                                                                         a.Envelope
}

const logColumns = `id,external_id,method,status_code,ip_address,created_at,correlation_id,CASE WHEN octet_length(request_params)<=2048 THEN request_params ELSE NULL END,entry_hash,response_status,hash_format_version,buffer_seq,chain_name,org_id,activity_run_id::text,activity_producer_id::text,activity_kind,activity_ordinal,activity_observed_us,activity_record_id::text,activity_outcome`

func scanLog(row pgx.Row) (logRow, error) {
	var l logRow
	if row.Scan(&l.id, &l.actor, &l.method, &l.status, &l.ip, &l.at, &l.correlation, &l.params, &l.hash, &l.http, &l.format, &l.seq, &l.chain, &l.org, &l.run, &l.producer, &l.kind, &l.ordinal, &l.observed, &l.record, &l.outcome) != nil {
		return l, a.ErrUnavailable
	}
	e, err := a.DecodeEnvelope([]byte(l.params))
	if err != nil {
		return l, a.ErrUnavailable
	}
	l.envelope = e
	l.at = l.at.UTC()
	if _, err := a.ParseDigestHex(l.hash); err != nil {
		return l, a.ErrUnavailable
	}
	if l.id < 1 || l.seq < 1 || l.ordinal < 1 || l.kind != 1 || l.format != 2 || l.actor != e.ActorID || l.method != e.Method || l.status != int(e.Status) || l.ip != e.IP || l.at.UnixMicro() != e.ObservedMicros || l.at.Nanosecond()%1000 != 0 || l.correlation != e.RecordID || l.http != int(e.HTTP) || l.org != e.DataOrg || l.run != e.RunID || l.producer != e.ProducerID || l.record != e.RecordID || l.outcome != e.Outcome || strconv.FormatInt(l.seq, 10) != e.BufferSeq || strconv.FormatInt(l.ordinal, 10) != e.Ordinal || l.observed != e.ObservedMicros {
		return l, a.ErrUnavailable
	}
	return l, nil
}

type registeredRun struct {
	id, producer, chain, generation string
	network, configuration          a.Digest
	index                           int64
}

func loadRuns(ctx context.Context, q queryer, ids []string) (map[string]registeredRun, error) {
	if len(ids) < 1 || len(ids) > 1024 {
		return nil, a.ErrInvalid
	}
	rows, err := q.Query(ctx, `SELECT run_id::text,producer_id::text,chain_name,generation::text,network_key,configuration,range_index FROM ops_activity_v1.runs WHERE run_id=ANY($1::uuid[])`, ids)
	if err != nil {
		return nil, a.ErrUnavailable
	}
	defer rows.Close()
	out := map[string]registeredRun{}
	for rows.Next() {
		var r registeredRun
		var n, c []byte
		if rows.Scan(&r.id, &r.producer, &r.chain, &r.generation, &n, &c, &r.index) != nil || len(n) != 32 || len(c) != 32 || !a.CanonicalUUID(r.id) || !a.CanonicalUUID(r.producer) || !a.CanonicalUUID(r.generation) || r.index < 1 || r.index > 8388607 {
			return nil, a.ErrUnavailable
		}
		copy(r.network[:], n)
		copy(r.configuration[:], c)
		if r.chain != chainName([32]byte(r.network)) {
			return nil, a.ErrUnavailable
		}
		out[r.id] = r
	}
	if rows.Err() != nil {
		return nil, a.ErrUnavailable
	}
	return out, nil
}
func registered(r registeredRun, e a.Envelope, seq uint64, state sourceState) bool {
	base := uint64(r.index) << 40
	top := base + (1 << 40) - 1
	return seq > base && seq <= top && r.network == state.metadata.NetworkKey && r.chain == state.chain && e.Network == hex.EncodeToString(r.network[:]) && e.Generation == r.generation && e.Configuration == hex.EncodeToString(r.configuration[:]) && e.ProducerID == r.producer && e.RunID == r.id
}

func checkHead(ctx context.Context, q queryer, s sourceState, mode string) error {
	if s.rows > 0 && s.bytes < s.rows || s.bytes > s.rows*2048 || s.rows > s.headID {
		return a.ErrUnavailable
	}
	if mode == "retention" {
		var id, size int64
		var h string
		err := q.QueryRow(ctx, `SELECT id,entry_hash,encoded_bytes FROM ops_activity_v1.prunable_logs WHERE chain_name=$1 ORDER BY id DESC LIMIT 1`, s.chain).Scan(&id, &h, &size)
		if s.rows > 0 {
			if err != nil || id != s.headID || h != s.headHash || size < 1 || size > s.bytes {
				return a.ErrUnavailable
			}
			return nil
		}
		if err != pgx.ErrNoRows {
			return a.ErrUnavailable
		}
	} else {
		l, err := scanLog(q.QueryRow(ctx, `SELECT `+logColumns+` FROM ops_activity_v1.qualified_logs WHERE chain_name=$1 ORDER BY id DESC LIMIT 1`, s.chain))
		if s.rows > 0 {
			if err != nil || l.id != s.headID || l.hash != s.headHash || int64(len(l.params)) > s.bytes {
				return a.ErrUnavailable
			}
			runs, err := loadRuns(ctx, q, []string{l.run})
			if err != nil || !registered(runs[l.run], l.envelope, uint64(l.seq), s) {
				return a.ErrUnavailable
			}
			return nil
		}
		// scanLog intentionally maps empty to Unavailable. A separate existence
		// check distinguishes an honestly empty retained set from malformed rows.
		var exists bool
		if q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ops_activity_v1.qualified_logs WHERE chain_name=$1)`, s.chain).Scan(&exists) != nil || exists {
			return a.ErrUnavailable
		}
	}
	if s.headID == 0 {
		// Reader/retention can check the exact absence of an anchor. Writer has
		// no anchor grant and trusts the selected atomic SourceHead continuity.
		if mode == "writer" {
			return nil
		}
		var exists bool
		if q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ops_activity_v1.anchors WHERE chain_name=$1)`, s.chain).Scan(&exists) != nil || exists {
			return a.ErrUnavailable
		}
		return nil
	}
	if mode == "writer" {
		return nil
	}
	var id int64
	var h string
	if q.QueryRow(ctx, `SELECT last_pruned_id,last_pruned_entry_hash FROM ops_activity_v1.anchors WHERE chain_name=$1`, s.chain).Scan(&id, &h) != nil || id != s.headID || h != s.headHash {
		return a.ErrUnavailable
	}
	return nil
}
