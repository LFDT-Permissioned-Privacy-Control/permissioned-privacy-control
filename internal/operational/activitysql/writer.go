package activitysql

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	a "privacy-proxy/internal/activitylog"
	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/audit/buffer"
	"privacy-proxy/internal/audit/sealer"
)

const rangeWidth uint64 = 1 << buffer.RangeShift

type runStore struct {
	writer  *Writer
	binding a.RunBinding
}

var _ a.Store = (*Writer)(nil)
var _ a.RunStore = (*runStore)(nil)

func (w *Writer) StartRun(ctx context.Context, r a.RunRequest) (a.RunStore, error) {
	if w == nil || w.store == nil || !a.CanonicalUUID(r.ProducerID) || !a.CanonicalUUID(r.RunID) || r.AllocatedThrough > uint64(1<<63-1) {
		return nil, a.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := begin(ctx, w.pool, false)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	s, err := w.writeState(ctx, tx)
	if err != nil {
		return nil, err
	}
	// USAGE permits one bounded nextval probe, not a non-consuming sequence
	// read. Consume ONE startup-only ID after the lock, never a catch-up loop.
	var probe, globalHead int64
	if tx.QueryRow(ctx, `SELECT nextval('public.access_logs_id_seq'),GREATEST(COALESCE((SELECT max(id)FROM public.access_logs),0),COALESCE((SELECT max(head_id)FROM ops_activity_v1.sources),0))`).Scan(&probe, &globalHead) != nil {
		return nil, a.ErrUnavailable
	}
	if probe <= max(globalHead, s.headID) {
		return nil, fmt.Errorf("%w: ID allocator behind committed head; drained owner repair required", a.ErrQuarantined)
	}
	var count int64
	if tx.QueryRow(ctx, `SELECT count(*) FROM ops_activity_v1.runs WHERE network_key=$1`, w.scope.NetworkKey[:]).Scan(&count) != nil {
		return nil, a.ErrUnavailable
	}
	if count >= s.limits.Runs {
		return nil, a.ErrTooBroad
	}
	if r.AllocatedThrough > 0 {
		index := r.AllocatedThrough >> buffer.RangeShift
		if index < 1 || index > 8388607 {
			return nil, sealer.ErrChainAhead
		}
		var exists bool
		if tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ops_activity_v1.runs WHERE range_index=$1 AND network_key=$2 AND producer_id=$3::uuid)`, int64(index), w.scope.NetworkKey[:], r.ProducerID).Scan(&exists) != nil {
			return nil, a.ErrUnavailable
		}
		if !exists {
			return nil, sealer.ErrChainAhead
		}
	}
	var index int64
	found := false
	for draw := 0; draw < 64; draw++ {
		if tx.QueryRow(ctx, `SELECT nextval('public.access_logs_buffer_range_seq')`).Scan(&index) != nil || index < 1 || index > 8388607 {
			return nil, a.ErrUnavailable
		}
		var exists bool
		if tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ops_activity_v1.runs WHERE range_index=$1)`, index).Scan(&exists) != nil {
			return nil, a.ErrUnavailable
		}
		if exists {
			continue
		}
		if uint64(index)*rangeWidth <= r.AllocatedThrough {
			return nil, sealer.ErrChainAhead
		}
		found = true
		break
	}
	if !found {
		return nil, a.ErrUnavailable
	}
	tag, err := tx.Exec(ctx, `INSERT INTO ops_activity_v1.runs(run_id,network_key,producer_id,chain_name,generation,configuration,range_index,registered_at)VALUES($1::uuid,$2,$3::uuid,$4,$5::uuid,$6,$7,clock_timestamp())`, r.RunID, w.scope.NetworkKey[:], r.ProducerID, s.chain, s.metadata.Generation, s.metadata.Configuration[:], index)
	if err != nil || tag.RowsAffected() != 1 {
		return nil, a.ErrConflict
	}
	if tx.Commit(ctx) != nil {
		return nil, a.ErrUnavailable
	}
	b := a.RunBinding{Metadata: s.metadata, ProducerID: r.ProducerID, RunID: r.RunID, RangeIndex: uint64(index), Base: uint64(index) * rangeWidth, Top: uint64(index)*rangeWidth + rangeWidth - 1}
	return &runStore{w, b}, nil
}
func (w *Writer) writeState(ctx context.Context, tx pgx.Tx) (sourceState, error) {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1::bigint)`, w.state.lock); err != nil {
		return sourceState{}, a.ErrUnavailable
	}
	s, err := selected(ctx, tx, w.scope, true, true)
	if err != nil {
		return s, err
	}
	if s.metadata != w.state.metadata || s.roles != w.state.roles {
		return s, a.ErrUnavailable
	}
	if err := checkSchema(ctx, tx); err != nil {
		return s, err
	}
	if err := checkRole(ctx, tx, s.roles, "writer"); err != nil {
		return s, err
	}
	if err := checkHead(ctx, tx, s, "writer"); err != nil {
		return s, err
	}
	return s, nil
}
func (r *runStore) Binding() a.RunBinding { return r.binding }
func (r *runStore) HighWater(ctx context.Context) (uint64, error) {
	return r.RangeHighWater(ctx, r.binding.RangeIndex)
}
func (r *runStore) RangeHighWater(ctx context.Context, index uint64) (uint64, error) {
	if index < 1 || index > 8388607 {
		return 0, sealer.ErrChainAhead
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := begin(ctx, r.writer.pool, true)
	if err != nil {
		return 0, err
	}
	defer rollback(tx)
	s, err := r.readState(ctx, tx)
	if err != nil {
		return 0, err
	}
	hw, err := rangeHighWater(ctx, tx, s, index, r.binding.ProducerID)
	if err != nil {
		return 0, err
	}
	if tx.Commit(ctx) != nil {
		return 0, a.ErrUnavailable
	}
	return hw, nil
}
func rangeHighWater(ctx context.Context, q queryer, s sourceState, index uint64, producer string) (uint64, error) {
	var registered bool
	if q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ops_activity_v1.runs WHERE range_index=$1 AND network_key=$2 AND producer_id=$3::uuid)`, int64(index), s.metadata.NetworkKey[:], producer).Scan(&registered) != nil {
		return 0, a.ErrUnavailable
	}
	if !registered {
		return 0, sealer.ErrChainAhead
	}
	var hw int64
	if q.QueryRow(ctx, `SELECT COALESCE(max(buffer_seq),0) FROM ops_activity_v1.qualified_logs WHERE chain_name=$1 AND buffer_seq>$2 AND buffer_seq<=$3`, s.chain, int64(index*rangeWidth), int64(index*rangeWidth+rangeWidth-1)).Scan(&hw) != nil {
		return 0, a.ErrUnavailable
	}
	return uint64(hw), nil
}
func (r *runStore) readState(ctx context.Context, tx pgx.Tx) (sourceState, error) {
	s, err := selected(ctx, tx, r.writer.scope, false, true)
	if err != nil {
		return s, err
	}
	if s.metadata != r.writer.state.metadata || s.roles != r.writer.state.roles {
		return s, a.ErrUnavailable
	}
	if err := checkSchema(ctx, tx); err != nil {
		return s, err
	}
	if err := checkRole(ctx, tx, s.roles, "writer"); err != nil {
		return s, err
	}
	return s, nil
}

type prepared struct {
	entry    buffer.Entry
	envelope a.Envelope
	body     string
}

func prepare(entries []buffer.Entry) ([]prepared, error) {
	if len(entries) < 1 || len(entries) > 512 {
		return nil, a.ErrInvalid
	}
	total := 0
	out := make([]prepared, 0, len(entries))
	var previous uint64
	for _, entry := range entries {
		if entry.Seq < 1 || entry.Seq > uint64(1<<63-1) || entry.Seq <= previous || len(entry.Data) > a.MaxEncodedBytes || len(entry.Data) > a.MaxBatchBytes-total {
			return nil, a.ErrInvalid
		}
		record, err := a.DecodeSpool(entry.Data)
		if err != nil {
			return nil, err
		}
		body, err := a.SealEnvelope(record, entry.Seq)
		if err != nil || len(body) > a.MaxBatchBytes-total {
			return nil, a.ErrInvalid
		}
		total += len(body)
		e := record.Fields()
		e.BufferSeq = strconv.FormatUint(entry.Seq, 10)
		out = append(out, prepared{entry: entry, envelope: e, body: string(body)})
		previous = entry.Seq
	}
	return out, nil
}
func verifyPrepared(ctx context.Context, q queryer, s sourceState, producer string, p []prepared) ([]sealer.Verdict, error) {
	ids := make([]string, 0, len(p))
	seqs := make([]int64, 0, len(p))
	for _, v := range p {
		ids = append(ids, v.envelope.RunID)
		seqs = append(seqs, int64(v.entry.Seq))
	}
	runs, err := loadRuns(ctx, q, ids)
	if err != nil {
		return nil, err
	}
	for _, v := range p {
		reg, ok := runs[v.envelope.RunID]
		if !ok || reg.producer != producer || !registered(reg, v.envelope, v.entry.Seq, s) {
			return nil, sealer.ErrChainAhead
		}
	}
	rows, err := q.Query(ctx, `SELECT `+logColumns+` FROM ops_activity_v1.qualified_logs WHERE buffer_seq=ANY($1::bigint[])`, seqs)
	if err != nil {
		return nil, a.ErrUnavailable
	}
	stored := map[uint64]logRow{}
	for rows.Next() {
		l, err := scanLog(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		if _, duplicate := stored[uint64(l.seq)]; duplicate {
			rows.Close()
			return nil, sealer.ErrChainAhead
		}
		stored[uint64(l.seq)] = l
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, a.ErrUnavailable
	}
	out := make([]sealer.Verdict, len(p))
	high := map[uint64]uint64{}
	for i, v := range p {
		if l, ok := stored[v.entry.Seq]; ok {
			if l.chain == s.chain && l.params == v.body {
				out[i] = sealer.Sealed
			} else {
				out[i] = sealer.Foreign
			}
			continue
		}
		if v.envelope.ObservedMicros < s.floor {
			return nil, fmt.Errorf("%w: preserved spool precedes retained SQL floor; offline recovery required", a.ErrQuarantined)
		}
		index := v.entry.Seq >> buffer.RangeShift
		hw, ok := high[index]
		if !ok {
			hw, err = rangeHighWater(ctx, q, s, index, producer)
			if err != nil {
				return nil, err
			}
			high[index] = hw
		}
		if v.entry.Seq <= hw {
			return nil, sealer.ErrChainAhead
		}
		out[i] = sealer.Missing
	}
	return out, nil
}
func (r *runStore) Verify(ctx context.Context, entries []buffer.Entry) ([]sealer.Verdict, error) {
	if len(entries) == 0 {
		return []sealer.Verdict{}, nil
	}
	p, err := prepare(entries)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := begin(ctx, r.writer.pool, true)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	s, err := r.readState(ctx, tx)
	if err != nil {
		return nil, err
	}
	v, err := verifyPrepared(ctx, tx, s, r.binding.ProducerID, p)
	if err != nil {
		return nil, err
	}
	if tx.Commit(ctx) != nil {
		return nil, a.ErrUnavailable
	}
	return v, nil
}
func (r *runStore) Settle(ctx context.Context, highWater uint64, entries []buffer.Entry) (uint64, error) {
	if len(entries) == 0 {
		return 0, nil
	}
	v, err := r.Verify(ctx, entries)
	if err != nil {
		return entries[0].Seq, err
	}
	for i, verdict := range v {
		if verdict == sealer.Foreign {
			return entries[i].Seq, sealer.ErrChainAhead
		}
		if verdict != sealer.Sealed {
			return entries[i].Seq, nil
		}
	}
	return 0, nil
}
func (r *runStore) SealOne(ctx context.Context, seq uint64, data []byte) error {
	return r.SealBatch(ctx, []buffer.Entry{{Seq: seq, Data: data}})
}
func (r *runStore) SealBatch(ctx context.Context, entries []buffer.Entry) error {
	p, err := prepare(entries)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := begin(ctx, r.writer.pool, false)
	if err != nil {
		return err
	}
	defer rollback(tx)
	s, err := r.writer.writeState(ctx, tx)
	if err != nil {
		return err
	}
	v, err := verifyPrepared(ctx, tx, s, r.binding.ProducerID, p)
	if err != nil {
		return err
	}
	first := len(p)
	for i, verdict := range v {
		if verdict == sealer.Foreign {
			return sealer.ErrChainAhead
		}
		if verdict == sealer.Missing {
			first = min(first, i)
		} else if first < len(p) {
			return sealer.ErrChainAhead
		}
	}
	if first == len(p) {
		if tx.Commit(ctx) != nil {
			return a.ErrUnavailable
		}
		return nil
	}
	p = p[first:]
	var bytes int64
	for _, v := range p {
		bytes += int64(len(v.body))
	}
	if int64(len(p)) > s.limits.Rows-s.rows || bytes > s.limits.Bytes-s.bytes {
		return a.ErrTooBroad
	}
	// IDs are allocated only after the shared chain lock and source selection.
	rows, err := tx.Query(ctx, `SELECT nextval('public.access_logs_id_seq') FROM generate_series(1,$1::integer)`, len(p))
	if err != nil {
		return a.ErrUnavailable
	}
	ids := make([]int64, 0, len(p))
	for rows.Next() {
		var id int64
		if rows.Scan(&id) != nil {
			rows.Close()
			return a.ErrUnavailable
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(ids) != len(p) {
		return a.ErrUnavailable
	}
	actors, methods, ips, correlations, bodies, hashes, orgs, runs, producers, records, outcomes := []string{}, []string{}, []string{}, []string{}, []string{}, []string{}, []string{}, []string{}, []string{}, []string{}, []string{}
	statuses, https := []int32{}, []int32{}
	times := []time.Time{}
	seqs, ordinals, observed := []int64{}, []int64{}, []int64{}
	prev := s.headHash
	for i, v := range p {
		e := v.envelope
		if ids[i] <= s.headID || i > 0 && ids[i] <= ids[i-1] {
			return a.ErrUnavailable
		}
		at := time.UnixMicro(e.ObservedMicros).UTC()
		content := audit.AccessLogChainContentV2(ids[i], e.ActorID, e.Method, e.IP, int(e.Status), int(e.HTTP), at, e.RecordID, v.body)
		h := sha256.Sum256([]byte(prev + content))
		prev = hex.EncodeToString(h[:])
		ordinal, _ := strconv.ParseInt(e.Ordinal, 10, 64)
		actors = append(actors, e.ActorID)
		methods = append(methods, e.Method)
		ips = append(ips, e.IP)
		correlations = append(correlations, e.RecordID)
		bodies = append(bodies, v.body)
		hashes = append(hashes, prev)
		orgs = append(orgs, e.DataOrg)
		runs = append(runs, e.RunID)
		producers = append(producers, e.ProducerID)
		records = append(records, e.RecordID)
		outcomes = append(outcomes, e.Outcome)
		statuses = append(statuses, int32(e.Status))
		https = append(https, int32(e.HTTP))
		times = append(times, at)
		seqs = append(seqs, int64(v.entry.Seq))
		ordinals = append(ordinals, ordinal)
		observed = append(observed, e.ObservedMicros)
	}
	inserted, err := tx.Exec(ctx, `INSERT INTO public.access_logs(id,external_id,method,status_code,ip_address,created_at,correlation_id,request_params,entry_hash,response_status,hash_format_version,buffer_seq,chain_name,org_id,activity_run_id,activity_producer_id,activity_kind,activity_ordinal,activity_observed_us,activity_record_id,activity_outcome)
SELECT id,actor,method,status,ip,at,correlation,body,hash,http,2,seq,$19,org,run::uuid,producer::uuid,1,ordinal,observed,record::uuid,outcome FROM unnest($1::bigint[],$2::text[],$3::text[],$4::integer[],$5::text[],$6::timestamptz[],$7::text[],$8::text[],$9::text[],$10::integer[],$11::bigint[],$12::text[],$13::text[],$14::text[],$15::bigint[],$16::bigint[],$17::text[],$18::text[])AS t(id,actor,method,status,ip,at,correlation,body,hash,http,seq,org,run,producer,ordinal,observed,record,outcome)`, ids, actors, methods, statuses, ips, times, correlations, bodies, hashes, https, seqs, orgs, runs, producers, ordinals, observed, records, outcomes, s.chain)
	if err != nil || inserted.RowsAffected() != int64(len(p)) {
		return fmt.Errorf("%w: seal insert", a.ErrUnavailable)
	}
	tag, err := tx.Exec(ctx, `UPDATE ops_activity_v1.sources SET head_id=$2,head_hash=$3,row_count=row_count+$4,byte_count=byte_count+$5 WHERE network_key=$1 AND generation=$6::uuid AND ready`, r.writer.scope.NetworkKey[:], ids[len(ids)-1], prev, len(p), bytes, r.writer.scope.ExpectedGeneration)
	if err != nil || tag.RowsAffected() != 1 {
		return a.ErrUnavailable
	}
	if tx.Commit(ctx) != nil {
		return a.ErrUnavailable
	}
	return nil
}
