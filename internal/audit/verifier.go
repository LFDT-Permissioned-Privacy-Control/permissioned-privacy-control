package audit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"
)

// ChainName identifies which audit chain the verifier walks. Constants
// match db.ChainNameAccessLogs / db.ChainNameRBACAuditLog. We redeclare
// them as audit-package constants to avoid the verifier importing the
// db package — the verifier reads via sql.DB directly so the same code
// can serve both the in-process scheduled worker and the
// privacy-cli subcommand.
type ChainName string

const (
	ChainAccessLogs   ChainName = "access_logs"
	ChainRBACAuditLog ChainName = "rbac_audit_log"
)

// Result captures one chain walk's outcome.
//
// OK true iff every row in scan order chained correctly back to the
// seed. False on the first mismatch; the remaining FirstMismatch*
// fields locate the offending row.
//
// ScannedRows counts the rows the verifier read regardless of outcome
// (rows-checked, not rows-passing). NullHashRows counts rows whose
// entry_hash is NULL — surfaced separately because they typically mean
// "writer crashed before storing the hash" (legacy / pre-RD-858) and
// not "tampering" but the verifier still flags them so the operator
// can decide.
type Result struct {
	Chain               ChainName
	OK                  bool
	ScannedRows         int64
	NullHashRows        int64
	Seed                string
	TailHash            string
	FirstMismatchID     int64
	FirstMismatchHash   string // stored hash on the offending row
	FirstMismatchExpect string // hash the verifier recomputed
	FirstMismatchTime   time.Time
	FirstMismatchReason string
	StartedAt           time.Time
	FinishedAt          time.Time
}

// Reason strings for FirstMismatchReason. Kept as exported constants
// so callers (notifier, CLI, tests) can switch on them without string-
// matching error prose.
const (
	ReasonHashMismatch    = "hash_mismatch"
	ReasonNullEntryHash   = "null_entry_hash"
	ReasonRowReadFailed   = "row_read_failed"
	ReasonSeedReadFailed  = "seed_read_failed"
	ReasonAnchorMismatch  = "anchor_mismatch"
	ReasonUnknownFormat   = "unknown_hash_format_version"
	ReasonContextCanceled = "context_canceled"
	// RD-1112 #8 signed-checkpoint truncation guard:
	ReasonCheckpointReadFailed = "checkpoint_read_failed"
	ReasonCheckpointForged     = "checkpoint_signature_invalid"
	ReasonChainTruncated       = "chain_truncated"
)

// SeedReader retrieves the chain seed for a given chain name. The
// production implementation is db.GetLatestAccessLogHash /
// GetLatestRBACAuditLogHash; tests can stub it.
type SeedReader interface {
	GetLatestAccessLogHash(ctx context.Context) (string, error)
	GetLatestRBACAuditLogHash(ctx context.Context) (string, error)
}

// Verifier walks an audit hash chain row-by-row, recomputing each
// row's hash and comparing it to the stored entry_hash. The first
// mismatch is reported in Result; the walk stops there.
//
// The verifier is intentionally **read-only** and DB-driver-agnostic:
// it accepts *sql.DB so the same code runs both inside the proxy
// (scheduled worker, admin API) and inside privacy-cli (auditor's
// command-line tool against a separate audit-role connection).
type Verifier struct {
	conn   *sql.DB
	seedFn SeedReader
	// RD-1112 #8: optional signed-checkpoint truncation guard. When both are
	// set, Verify additionally checks the access_logs chain hasn't been
	// tail-truncated below the latest signed checkpoint.
	ckptReader CheckpointReader
	ckptSigner Signer
}

// SetCheckpointVerification enables the signed-checkpoint truncation guard
// (RD-1112 #8). reader supplies the latest checkpoint; signer verifies its
// signature. Leaving both unset (the default) disables the guard.
func (v *Verifier) SetCheckpointVerification(reader CheckpointReader, signer Signer) {
	v.ckptReader = reader
	v.ckptSigner = signer
}

// checkTruncation applies the signed-checkpoint truncation guard to res (a
// no-op when the guard is not configured). It runs after the hash walk: the
// walk catches insert / modify / middle-delete; this catches TAIL truncation,
// which the walk cannot see (deleting the most recent rows breaks no
// downstream hash). Only valid for the access_logs chain (the chain_name
// column lives there).
func (v *Verifier) checkTruncation(ctx context.Context, chain ChainName, res *Result) {
	if v.ckptReader == nil || v.ckptSigner == nil {
		return
	}
	c, err := v.ckptReader.LatestCheckpoint(ctx, string(chain))
	if err != nil {
		res.OK = false
		res.FirstMismatchReason = ReasonCheckpointReadFailed
		return
	}
	if c == nil {
		return // no checkpoint yet — nothing to enforce
	}
	if err := VerifyCheckpoint(v.ckptSigner, *c); err != nil {
		// A checkpoint the verifier cannot trust is itself a tamper signal.
		res.OK = false
		res.FirstMismatchReason = ReasonCheckpointForged
		return
	}
	var curHead sql.NullInt64
	if err := v.conn.QueryRowContext(ctx,
		`SELECT max(id) FROM access_logs WHERE chain_name = $1`, string(chain),
	).Scan(&curHead); err != nil {
		res.OK = false
		res.FirstMismatchReason = ReasonCheckpointReadFailed
		return
	}
	if checkpointTruncated(c, curHead.Valid, curHead.Int64) {
		res.OK = false
		res.FirstMismatchReason = ReasonChainTruncated
		res.FirstMismatchID = c.HeadID
		res.FirstMismatchExpect = c.HeadHash
	}
}

// NewVerifier constructs a Verifier. conn must point at a database
// where the audit schema has been migrated to at least migration 057
// (rbac_audit_log entry_hash column). seedFn supplies the chain seed
// — in production this is the *db.DB itself.
func NewVerifier(conn *sql.DB, seedFn SeedReader) *Verifier {
	return &Verifier{conn: conn, seedFn: seedFn}
}

// Verify walks the named chain and returns a Result. ctx cancels the
// walk between rows; long chains can take seconds.
func (v *Verifier) Verify(ctx context.Context, chain ChainName) (*Result, error) {
	switch chain {
	case ChainAccessLogs:
		return v.verifyAccessLogs(ctx)
	case ChainRBACAuditLog:
		return v.verifyRBACAuditLog(ctx)
	default:
		return nil, fmt.Errorf("unknown chain: %q", chain)
	}
}

// verifyOneAccessLogChain walks a single chain_name and returns its Result.
// Each chain_name is an independent single-writer chain (RD-1112 #8), so it is
// verified in isolation; verifyAccessLogs aggregates across chains.
func (v *Verifier) verifyOneAccessLogChain(ctx context.Context, chainName string) (*Result, error) {
	res := &Result{Chain: ChainAccessLogs, StartedAt: time.Now().UTC(), OK: true}
	defer func() { res.FinishedAt = time.Now().UTC() }()

	startPrev, anchorID, err := v.startingPrev(ctx, ChainName(chainName))
	if err != nil {
		res.OK = false
		res.FirstMismatchReason = ReasonSeedReadFailed
		return res, err
	}
	res.Seed = startPrev

	rows, err := v.conn.QueryContext(ctx,
		`SELECT id, external_id, method, status_code, COALESCE(response_status, status_code), ip_address, COALESCE(correlation_id, ''),
			COALESCE(request_params::text, ''), created_at, entry_hash, hash_format_version
		 FROM access_logs
		 WHERE chain_name = $1 AND id > $2
		 ORDER BY id ASC`,
		chainName, anchorID,
	)
	if err != nil {
		return nil, fmt.Errorf("query access_logs: %w", err)
	}
	defer rows.Close()

	prev := startPrev
	for rows.Next() {
		if ctx.Err() != nil {
			res.OK = false
			res.FirstMismatchReason = ReasonContextCanceled
			return res, ctx.Err()
		}
		var (
			id, statusCode, responseStatus int64
			externalID, method, ipAddress  string
			correlationID, paramsDigest    string
			createdAt                      time.Time
			entryHash                      sql.NullString
			hashFormatVersion              int
		)
		if err := rows.Scan(&id, &externalID, &method, &statusCode, &responseStatus, &ipAddress,
			&correlationID, &paramsDigest, &createdAt, &entryHash, &hashFormatVersion); err != nil {
			res.OK = false
			res.FirstMismatchReason = ReasonRowReadFailed
			res.FirstMismatchID = id
			return res, fmt.Errorf("scan access_logs row: %w", err)
		}
		res.ScannedRows++

		if !entryHash.Valid || entryHash.String == "" {
			res.NullHashRows++
			if res.OK {
				res.OK = false
				res.FirstMismatchReason = ReasonNullEntryHash
				res.FirstMismatchID = id
				res.FirstMismatchTime = createdAt
			}
			// Cannot advance the chain past a NULL-hash row — its
			// content can't be verified, and the next row's prev hash
			// would be unknown. Stop the walk; the caller decides
			// whether to continue from a manually-supplied anchor.
			break
		}

		if hashFormatVersion != 2 {
			res.OK = false
			res.FirstMismatchReason = ReasonUnknownFormat
			res.FirstMismatchID = id
			res.FirstMismatchTime = createdAt
			res.FirstMismatchHash = entryHash.String
			return res, nil
		}

		content := AccessLogChainContentV2(id, externalID, method, ipAddress, int(statusCode), int(responseStatus), createdAt, correlationID, paramsDigest)
		expect := computeChainHash(prev, content)
		if expect != entryHash.String {
			res.OK = false
			res.FirstMismatchReason = ReasonHashMismatch
			res.FirstMismatchID = id
			res.FirstMismatchHash = entryHash.String
			res.FirstMismatchExpect = expect
			res.FirstMismatchTime = createdAt
			return res, nil
		}
		prev = entryHash.String
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate access_logs: %w", err)
	}
	res.TailHash = prev
	return res, nil
}

// verifyAccessLogs verifies every access_logs chain. Each chain_name is an
// independent single-writer chain (RD-1112 #8); a global id-ordered walk would
// mis-chain interleaved per-instance chains, so we verify each separately and
// apply the signed-checkpoint truncation guard per chain. Chains that have a
// signed checkpoint but no rows are included so a fully-truncated chain is
// flagged (presence), not silently skipped. The first failing chain wins.
func (v *Verifier) verifyAccessLogs(ctx context.Context) (*Result, error) {
	agg := &Result{Chain: ChainAccessLogs, StartedAt: time.Now().UTC(), OK: true}
	defer func() { agg.FinishedAt = time.Now().UTC() }()

	chains, err := v.accessLogChainNames(ctx)
	if err != nil {
		agg.OK = false
		agg.FirstMismatchReason = ReasonRowReadFailed
		return agg, fmt.Errorf("enumerate access_log chains: %w", err)
	}
	for _, cn := range chains {
		r, err := v.verifyOneAccessLogChain(ctx, cn)
		if r != nil {
			agg.ScannedRows += r.ScannedRows
			agg.NullHashRows += r.NullHashRows
			agg.TailHash = r.TailHash
		}
		if err != nil {
			if r != nil {
				agg.OK = false
				agg.FirstMismatchReason = r.FirstMismatchReason
				agg.FirstMismatchID = r.FirstMismatchID
			}
			return agg, err
		}
		if !r.OK {
			agg.OK = false
			agg.FirstMismatchReason = r.FirstMismatchReason
			agg.FirstMismatchID = r.FirstMismatchID
			agg.FirstMismatchHash = r.FirstMismatchHash
			agg.FirstMismatchExpect = r.FirstMismatchExpect
			agg.FirstMismatchTime = r.FirstMismatchTime
			return agg, nil
		}
		// Per-chain signed-checkpoint truncation guard (no-op unless configured).
		v.checkTruncation(ctx, ChainName(cn), agg)
		if !agg.OK {
			return agg, nil
		}
	}
	return agg, nil
}

// accessLogChainNames returns the union of chain_names in access_logs and in
// audit_chain_checkpoint (the latter so a fully-truncated chain — rows gone but
// a signed checkpoint exists — is still checked and flagged as truncated).
func (v *Verifier) accessLogChainNames(ctx context.Context) ([]string, error) {
	set := make(map[string]struct{})
	collect := func(q string) error {
		rows, err := v.conn.QueryContext(ctx, q)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var n sql.NullString
			if err := rows.Scan(&n); err != nil {
				return err
			}
			if n.Valid && n.String != "" {
				set[n.String] = struct{}{}
			}
		}
		return rows.Err()
	}
	if err := collect(`SELECT DISTINCT chain_name FROM access_logs`); err != nil {
		return nil, err
	}
	if err := collect(`SELECT DISTINCT chain_name FROM audit_chain_checkpoint`); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

func (v *Verifier) verifyRBACAuditLog(ctx context.Context) (*Result, error) {
	res := &Result{Chain: ChainRBACAuditLog, StartedAt: time.Now().UTC(), OK: true}
	defer func() { res.FinishedAt = time.Now().UTC() }()

	seed, err := v.seedFn.GetLatestRBACAuditLogHash(ctx)
	if err != nil {
		res.OK = false
		res.FirstMismatchReason = ReasonSeedReadFailed
		return res, fmt.Errorf("seed: %w", err)
	}
	startPrev, anchorID, err := v.startingPrev(ctx, ChainRBACAuditLog)
	if err != nil {
		res.OK = false
		res.FirstMismatchReason = ReasonSeedReadFailed
		return res, err
	}
	res.Seed = startPrev

	rows, err := v.conn.QueryContext(ctx,
		`SELECT id, COALESCE(actor_external_id, ''), action, resource_type, COALESCE(resource_id::text, ''),
			COALESCE(resource_name, ''), COALESCE(org_id::text, ''), COALESCE(ip_address, ''),
			created_at, COALESCE(old_value::text, ''), COALESCE(new_value::text, ''),
			entry_hash, hash_format_version
		 FROM rbac_audit_log
		 WHERE id > $1
		 ORDER BY id ASC`,
		anchorID,
	)
	if err != nil {
		return nil, fmt.Errorf("query rbac_audit_log: %w", err)
	}
	defer rows.Close()

	prev := startPrev
	for rows.Next() {
		if ctx.Err() != nil {
			res.OK = false
			res.FirstMismatchReason = ReasonContextCanceled
			return res, ctx.Err()
		}
		var (
			id                                                                                int64
			actorExternalID, action, resourceType, resourceID, resourceName, orgID, ipAddress string
			createdAt                                                                         time.Time
			oldValue, newValue                                                                string
			entryHash                                                                         sql.NullString
			hashFormatVersion                                                                 int
		)
		if err := rows.Scan(&id, &actorExternalID, &action, &resourceType, &resourceID,
			&resourceName, &orgID, &ipAddress, &createdAt, &oldValue, &newValue,
			&entryHash, &hashFormatVersion); err != nil {
			res.OK = false
			res.FirstMismatchReason = ReasonRowReadFailed
			res.FirstMismatchID = id
			return res, fmt.Errorf("scan rbac_audit_log row: %w", err)
		}
		res.ScannedRows++

		if !entryHash.Valid || entryHash.String == "" {
			res.NullHashRows++
			if res.OK {
				res.OK = false
				res.FirstMismatchReason = ReasonNullEntryHash
				res.FirstMismatchID = id
				res.FirstMismatchTime = createdAt
			}
			break
		}

		if hashFormatVersion != 1 {
			res.OK = false
			res.FirstMismatchReason = ReasonUnknownFormat
			res.FirstMismatchID = id
			res.FirstMismatchTime = createdAt
			res.FirstMismatchHash = entryHash.String
			return res, nil
		}

		content := RBACAuditChainContentV1(id, actorExternalID, action, resourceType, resourceID, resourceName, orgID, ipAddress, createdAt, oldValue, newValue)
		expect := computeChainHash(prev, content)
		if expect != entryHash.String {
			res.OK = false
			res.FirstMismatchReason = ReasonHashMismatch
			res.FirstMismatchID = id
			res.FirstMismatchHash = entryHash.String
			res.FirstMismatchExpect = expect
			res.FirstMismatchTime = createdAt
			return res, nil
		}
		prev = entryHash.String
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rbac_audit_log: %w", err)
	}
	res.TailHash = prev
	if res.OK && seed != "" && seed != prev {
		// RD-1164 #13: an anchor mismatch means the chain head does not match
		// the external anchor (seed) — a tail truncation/replacement signal.
		// This MUST fail verification: the integrity worker alerts on !res.OK,
		// so leaving OK=true here made anchor mismatches silent.
		res.OK = false
		res.FirstMismatchReason = ReasonAnchorMismatch
		res.FirstMismatchHash = prev
	}
	return res, nil
}

// startingPrev returns the (prev_hash, anchor_id) the walk should
// begin from. If audit_chain_anchor has a row for the chain (rows have
// been pruned), prev is the anchor hash and anchor_id is the last
// pruned id — we start from id > anchor_id. Otherwise prev = "" and
// anchor_id = 0 (walk from the very first row).
func (v *Verifier) startingPrev(ctx context.Context, chain ChainName) (string, int64, error) {
	var prev sql.NullString
	var anchorID sql.NullInt64
	err := v.conn.QueryRowContext(ctx,
		`SELECT last_pruned_entry_hash, last_pruned_id FROM audit_chain_anchor WHERE chain_name = $1`,
		string(chain),
	).Scan(&prev, &anchorID)
	if err == nil {
		return prev.String, anchorID.Int64, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, nil
	}
	return "", 0, fmt.Errorf("read audit_chain_anchor for %s: %w", chain, err)
}

// AccessLogChainContentV2 mirrors db.AccessLogChainContent but lives
// in the audit package so the verifier doesn't import db (which would
// create a cycle: db already imports audit via RBACAuditChain). Format
// MUST match db.AccessLogChainContent byte-for-byte.
func AccessLogChainContentV2(id int64, externalID, method, ipAddress string, statusCode, responseStatus int, createdAt time.Time, correlationID, paramsDigest string) string {
	return fmt.Sprintf("v2|%d|%s|%s|%s|%d|%d|%s|%s|%s",
		id, externalID, method, ipAddress, statusCode, responseStatus,
		createdAt.UTC().Format(time.RFC3339Nano),
		correlationID,
		paramsDigest,
	)
}

// RBACAuditChainContentV1 mirrors db.buildRBACAuditContent for v1 rows.
// The format MUST match byte-for-byte.
func RBACAuditChainContentV1(id int64, actorExternalID, action, resourceType, resourceID, resourceName, orgID, ipAddress string, createdAt time.Time, oldValue, newValue string) string {
	return fmt.Sprintf("v1|%d|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s",
		id,
		actorExternalID,
		action,
		resourceType,
		resourceID,
		resourceName,
		orgID,
		ipAddress,
		createdAt.UTC().Format(time.RFC3339Nano),
		oldValue,
		newValue,
	)
}

func computeChainHash(prev, content string) string {
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write([]byte(content))
	return hex.EncodeToString(h.Sum(nil))
}
