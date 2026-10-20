package audit

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ReAnchor is a signed, authorized break in an audit chain (RD-1112 #8,
// security review #3). It documents a deliberate discontinuity — recovery
// after data loss, a migration, a chain reset — so the integrity verifier
// treats the gap as authorized rather than as tamper. It is signed by the
// checkpoint key, which lives outside the DB credential's blast radius;
// writing one therefore requires that key and is gated to the break-glass
// runbook (PR-approved, dual-control — the key holder is not the routine
// DB-writing identity).
//
// Visibility, not suppression: the ReAnchor row is a permanent, signed,
// attributable record of the break. It does not erase the discontinuity; it
// classifies it. After it is written, the chain anchor + a fresh signed
// checkpoint move the verifier's baseline to the recovery point, so the
// verifier stops re-alarming on the (now-authorized) gap while the ReAnchor
// row preserves the audit trail of what happened, who authorized it, and why.
type ReAnchor struct {
	ChainName  string
	Reason     string
	Actor      string
	FromHeadID int64 // last checkpointed head before the break (0 if none)
	FromHash   string
	ToHeadID   int64 // recovery point (current head) the chain resumes from
	ToHash     string
	CreatedAt  time.Time
	KeyID      string
	Signature  string
}

func (r ReAnchor) signedContent() []byte {
	return []byte(strings.Join([]string{
		"reanchor-v2",
		r.ChainName,
		r.Reason,
		r.Actor,
		strconv.FormatInt(r.FromHeadID, 10),
		r.FromHash,
		strconv.FormatInt(r.ToHeadID, 10),
		r.ToHash,
		// MICROSECOND precision — see Checkpoint.signedContent: created_at is a
		// Postgres TIMESTAMP (microsecond), so signing nanos breaks verification
		// after the DB round-trip on sub-µs-resolution hosts (Linux). (v1 signed
		// nanos; tag bumped to v2.)
		strconv.FormatInt(r.CreatedAt.UTC().UnixMicro(), 10),
	}, "|"))
}

// SignReAnchor signs r in place.
func SignReAnchor(s Signer, r *ReAnchor) error {
	sig, keyID, err := s.Sign(r.signedContent())
	if err != nil {
		return fmt.Errorf("sign re-anchor: %w", err)
	}
	r.Signature = sig
	r.KeyID = keyID
	return nil
}

// VerifyReAnchor verifies r's signature.
func VerifyReAnchor(s Signer, r ReAnchor) error {
	return s.Verify(r.signedContent(), r.Signature, r.KeyID)
}

// ReAnchorStore is the persistence the break-glass operation needs.
type ReAnchorStore interface {
	ChainStats(ctx context.Context, chainName string) (rowCount, headID int64, headHash string, err error)
	LatestCheckpoint(ctx context.Context, chainName string) (*Checkpoint, error)
	SetAnchor(ctx context.Context, chainName string, lastID int64, lastHash string) error
	WriteCheckpoint(ctx context.Context, c Checkpoint) error
	WriteReAnchor(ctx context.Context, r ReAnchor) error
}

// BreakGlassReAnchor records an authorized discontinuity for chainName and
// moves the verifier's baseline to the current head so it resumes cleanly.
// Steps (all signed/persisted): capture the prior checkpoint as the "from"
// point; sign + persist a ReAnchor row (the permanent audit trail); set the
// chain anchor to the current head; write a fresh signed checkpoint there.
// Requires a non-empty actor and reason — an unattributed break is rejected.
func BreakGlassReAnchor(ctx context.Context, store ReAnchorStore, signer Signer, chainName, actor, reason string) (*ReAnchor, error) {
	if actor == "" || reason == "" {
		return nil, fmt.Errorf("break-glass re-anchor requires a non-empty actor and reason")
	}

	rowCount, headID, headHash, err := store.ChainStats(ctx, chainName)
	if err != nil {
		return nil, fmt.Errorf("re-anchor: read chain stats: %w", err)
	}

	r := &ReAnchor{
		ChainName: chainName,
		Reason:    reason,
		Actor:     actor,
		ToHeadID:  headID,
		ToHash:    headHash,
		CreatedAt: time.Now().UTC(),
	}
	// Best-effort capture of the point we're breaking from (the prior checkpoint).
	if prev, perr := store.LatestCheckpoint(ctx, chainName); perr == nil && prev != nil {
		r.FromHeadID = prev.HeadID
		r.FromHash = prev.HeadHash
	}

	if err := SignReAnchor(signer, r); err != nil {
		return nil, err
	}
	if err := store.WriteReAnchor(ctx, *r); err != nil {
		return nil, fmt.Errorf("re-anchor: persist record: %w", err)
	}
	// Move the verifier's start to the recovery point.
	if err := store.SetAnchor(ctx, chainName, headID, headHash); err != nil {
		return nil, fmt.Errorf("re-anchor: set chain anchor: %w", err)
	}
	// Fresh signed checkpoint so the truncation guard's baseline matches the
	// recovery point (otherwise the stale checkpoint would keep alarming).
	cp := Checkpoint{ChainName: chainName, HeadID: headID, HeadHash: headHash, RowCount: rowCount, CreatedAt: time.Now().UTC()}
	if err := SignCheckpoint(signer, &cp); err != nil {
		return nil, err
	}
	if err := store.WriteCheckpoint(ctx, cp); err != nil {
		return nil, fmt.Errorf("re-anchor: write checkpoint: %w", err)
	}
	return r, nil
}
