// Package walletsql is the named operational PostgreSQL adapter for wallet
// proofs, permanent revocations and shared one-use challenges. Its database,
// writer and restore process are trusted inputs to privacy decisions.
package walletsql

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"privacy-proxy/internal/identity"
	w "privacy-proxy/internal/walletops"
)

type Store struct {
	pool *pgxpool.Pool
	mode string
}

var _ w.Store = (*Store)(nil)

func Open(ctx context.Context, dsn string) (*Store, error)       { return open(ctx, dsn, "app") }
func OpenReader(ctx context.Context, dsn string) (*Store, error) { return open(ctx, dsn, "reader") }
func OpenRetention(ctx context.Context, dsn string) (*Store, error) {
	return open(ctx, dsn, "retention")
}
func open(ctx context.Context, dsn, mode string) (*Store, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, w.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, w.ErrUnavailable
	}
	config.MaxConns = 8
	config.ConnConfig.ConnectTimeout = 3 * time.Second
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, w.ErrUnavailable
	}
	s := &Store{pool, mode}
	if s.CheckSchema(ctx) != nil || s.checkPrivileges(ctx) != nil {
		pool.Close()
		return nil, w.ErrUnavailable
	}
	return s, nil
}
func (s *Store) Close() { s.pool.Close() }
func bounded(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 5*time.Second)
}
func rollback(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}
func closeConnection(conn *pgx.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = conn.Close(ctx)
}
func begin(ctx context.Context, pool *pgxpool.Pool) (pgx.Tx, error) {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, w.ErrUnavailable
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout','1s',true),set_config('statement_timeout','3s',true)`); err != nil {
		rollback(tx)
		return nil, w.ErrUnavailable
	}
	return tx, nil
}
func checkState(ctx context.Context, q querier, ns w.Namespace, state w.ExpectedState) error {
	var ready bool
	err := q.QueryRow(ctx, `SELECT ready AND generation=$2::uuid AND revocation_coverage_digest=$3 FROM ops_wallet_v2.store_state WHERE namespace=$1`, ns[:], state.Generation, state.Coverage[:]).Scan(&ready)
	if err != nil || !ready {
		return w.ErrUnavailable
	}
	return nil
}
func (s *Store) WithActorTransaction(ctx context.Context, ns w.Namespace, state w.ExpectedState, actor string, callback func(w.ActorTx) error) error {
	if s.mode != "app" || !state.Valid() || !identity.ValidActorID(actor) || callback == nil {
		return w.ErrInvalid
	}
	ctx, cancel := bounded(ctx)
	defer cancel()
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return err
	}
	defer rollback(tx)
	a, b := w.ActorLock(ns, actor)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1::integer,$2::integer)`, a, b); err != nil {
		return w.ErrUnavailable
	}
	if err := checkState(ctx, tx, ns, state); err != nil {
		return err
	}
	if err := callback(&actorTx{ctx, tx, ns, state, actor}); err != nil {
		return err
	}
	if err := checkState(ctx, tx, ns, state); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return w.ErrUnavailable
	}
	return nil
}

type actorTx struct {
	ctx   context.Context
	tx    pgx.Tx
	ns    w.Namespace
	state w.ExpectedState
	actor string
}

func (t *actorTx) DeleteExpiredChallenges(at time.Time, limit int) error {
	if limit < 1 || limit > w.MaxChallenges {
		return w.ErrInvalid
	}
	_, err := t.tx.Exec(t.ctx, `DELETE FROM ops_wallet_v2.wallet_challenges WHERE(namespace,generation,nonce) IN(SELECT namespace,generation,nonce FROM ops_wallet_v2.wallet_challenges WHERE namespace=$1 AND actor_id=$2 AND expires_at<=$3 ORDER BY expires_at LIMIT $4)`, t.ns[:], t.actor, at, limit)
	if err != nil {
		return w.ErrUnavailable
	}
	return nil
}
func (t *actorTx) CountChallenges() (int, error) {
	return t.count(`SELECT count(*) FROM(SELECT 1 FROM ops_wallet_v2.wallet_challenges WHERE namespace=$1 AND actor_id=$2 LIMIT 9)bounded`)
}
func (t *actorTx) CountLinkRows() (int, error) {
	return t.count(`SELECT count(*) FROM(SELECT 1 FROM ops_wallet_v2.wallet_links WHERE namespace=$1 AND actor_id=$2 LIMIT 4097)bounded`)
}
func (t *actorTx) count(query string) (int, error) {
	var n int
	err := t.tx.QueryRow(t.ctx, query, t.ns[:], t.actor).Scan(&n)
	if err != nil {
		return 0, w.ErrUnavailable
	}
	return n, nil
}
func (t *actorTx) InsertChallenge(c w.Challenge) error {
	if c.Namespace != t.ns || c.Generation != t.state.Generation || c.Actor != t.actor || len(c.Message) == 0 || len(c.Message) > 4096 {
		return w.ErrInvalid
	}
	_, err := t.tx.Exec(t.ctx, `INSERT INTO ops_wallet_v2.wallet_challenges(namespace,generation,actor_id,nonce,address,message,issued_at,expires_at)VALUES($1,$2::uuid,$3,$4,$5,$6,$7,$8)`, t.ns[:], t.state.Generation, t.actor, c.Nonce[:], c.Address[:], []byte(c.Message), c.IssuedAt, c.ExpiresAt)
	if err != nil {
		return w.ErrUnavailable
	}
	return nil
}
func (t *actorTx) TakeChallenge(nonce [32]byte, address common.Address, at time.Time) (w.Challenge, bool, error) {
	c := w.Challenge{Namespace: t.ns, Generation: t.state.Generation, Actor: t.actor, Nonce: nonce, Address: address}
	var message []byte
	err := t.tx.QueryRow(t.ctx, `DELETE FROM ops_wallet_v2.wallet_challenges WHERE namespace=$1 AND generation=$2::uuid AND actor_id=$3 AND nonce=$4 AND address=$5 AND issued_at<=$6 AND expires_at>$6 RETURNING CASE WHEN octet_length(message)<=4096 THEN message ELSE NULL END,issued_at,expires_at`, t.ns[:], t.state.Generation, t.actor, nonce[:], address[:], at).Scan(&message, &c.IssuedAt, &c.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, false, nil
	}
	if err != nil || len(message) == 0 || len(message) > 4096 {
		return c, false, w.ErrUnavailable
	}
	c.Message = string(message)
	return c, true, nil
}
func scanLink(row pgx.Row, ns w.Namespace, actor string, address common.Address) (w.Link, bool, error) {
	l := w.Link{Namespace: ns, Actor: actor, Address: address}
	var message []byte
	var accepted, revoked *time.Time
	err := row.Scan(&l.ProofKind, &message, &l.Signature, &l.MessageHash, &accepted, &l.Revoked, &revoked)
	if errors.Is(err, pgx.ErrNoRows) {
		return l, false, nil
	}
	if err != nil {
		return l, false, w.ErrUnavailable
	}
	l.Message = string(message)
	if accepted != nil {
		l.AcceptedAt = *accepted
	}
	if revoked != nil {
		l.RevokedAt = *revoked
	}
	if l.Validate() != nil {
		return l, false, w.ErrUnavailable
	}
	return l, true, nil
}
func (t *actorTx) GetLink(address common.Address) (w.Link, bool, error) {
	return scanLink(t.tx.QueryRow(t.ctx, `SELECT proof_kind,CASE WHEN octet_length(message)<=4096 THEN message ELSE NULL END,CASE WHEN octet_length(signature)=65 THEN signature ELSE NULL END,CASE WHEN octet_length(message_hash)=32 THEN message_hash ELSE NULL END,accepted_at,revoked,revoked_at FROM ops_wallet_v2.wallet_links WHERE namespace=$1 AND actor_id=$2 AND address=$3`, t.ns[:], t.actor, address[:]), t.ns, t.actor, address)
}
func (t *actorTx) InsertOwnership(l w.Link) (bool, error) {
	if l.Namespace != t.ns || l.Actor != t.actor || l.ProofKind != "eip191_v2" || l.Revoked || l.Validate() != nil {
		return false, w.ErrInvalid
	}
	tag, err := t.tx.Exec(t.ctx, `INSERT INTO ops_wallet_v2.wallet_links(namespace,actor_id,address,proof_kind,message,signature,message_hash,accepted_at,revoked)VALUES($1,$2,$3,'eip191_v2',$4,$5,$6,$7,false)ON CONFLICT(namespace,actor_id,address)DO NOTHING`, t.ns[:], t.actor, l.Address[:], []byte(l.Message), l.Signature, l.MessageHash, l.AcceptedAt)
	if err != nil {
		return false, w.ErrUnavailable
	}
	return tag.RowsAffected() == 1, nil
}
func (t *actorTx) Revoke(address common.Address, at time.Time) (bool, bool, error) {
	_, found, err := t.GetLink(address)
	if err != nil || !found {
		return found, false, err
	}
	tag, err := t.tx.Exec(t.ctx, `UPDATE ops_wallet_v2.wallet_links SET revoked=true,revoked_at=$4 WHERE namespace=$1 AND actor_id=$2 AND address=$3 AND NOT revoked`, t.ns[:], t.actor, address[:], at)
	if err != nil {
		return false, false, w.ErrUnavailable
	}
	return true, tag.RowsAffected() == 1, nil
}

// A left lateral join returns the ready state even for an actor with zero links;
// missing/mismatched state can never masquerade as a successful empty snapshot.
func (s *Store) LoadActive(ctx context.Context, ns w.Namespace, state w.ExpectedState, actor string, limit int) ([]w.OwnershipFact, error) {
	if s.mode == "retention" || !state.Valid() || !identity.ValidActorID(actor) || limit < 1 || limit > w.MaxLinks+1 {
		return nil, w.ErrInvalid
	}
	ctx, cancel := bounded(ctx)
	defer cancel()
	rows, err := s.pool.Query(ctx, `SELECT s.ready AND s.generation=$2::uuid AND s.revocation_coverage_digest=$3,l.address,l.accepted_at FROM ops_wallet_v2.store_state s LEFT JOIN LATERAL(SELECT address,accepted_at FROM ops_wallet_v2.wallet_links WHERE namespace=s.namespace AND actor_id=$4 AND NOT revoked AND proof_kind='eip191_v2' ORDER BY address LIMIT $5)l ON true WHERE s.namespace=$1`, ns[:], state.Generation, state.Coverage[:], actor, limit)
	if err != nil {
		return nil, w.ErrUnavailable
	}
	defer rows.Close()
	out := []w.OwnershipFact{}
	stateSeen := false
	for rows.Next() {
		var ready bool
		var address []byte
		var at *time.Time
		if rows.Scan(&ready, &address, &at) != nil || !ready {
			return nil, w.ErrUnavailable
		}
		stateSeen = true
		if address == nil && at == nil {
			continue
		}
		if len(address) != 20 || at == nil {
			return nil, w.ErrUnavailable
		}
		f := w.OwnershipFact{Namespace: ns, Actor: actor, Address: common.BytesToAddress(address), ProofVersion: 2, VerifiedAt: *at}
		if !f.Valid(ns, actor) {
			return nil, w.ErrUnavailable
		}
		out = append(out, f)
	}
	if rows.Err() != nil || !stateSeen {
		return nil, w.ErrUnavailable
	}
	return out, nil
}
func (s *Store) ResolveActiveActors(ctx context.Context, ns w.Namespace, state w.ExpectedState, address common.Address, limit int) ([]string, error) {
	if s.mode == "retention" || !state.Valid() || limit != 2 {
		return nil, w.ErrInvalid
	}
	ctx, cancel := bounded(ctx)
	defer cancel()
	rows, err := s.pool.Query(ctx, `SELECT s.ready AND s.generation=$2::uuid AND s.revocation_coverage_digest=$3,l.actor_id FROM ops_wallet_v2.store_state s LEFT JOIN LATERAL(SELECT actor_id FROM ops_wallet_v2.wallet_links WHERE namespace=s.namespace AND address=$4 AND NOT revoked AND proof_kind='eip191_v2' ORDER BY actor_id LIMIT $5)l ON true WHERE s.namespace=$1`, ns[:], state.Generation, state.Coverage[:], address[:], limit)
	if err != nil {
		return nil, w.ErrUnavailable
	}
	defer rows.Close()
	out := []string{}
	stateSeen := false
	for rows.Next() {
		var ready bool
		var actor *string
		if rows.Scan(&ready, &actor) != nil || !ready {
			return nil, w.ErrUnavailable
		}
		stateSeen = true
		if actor == nil {
			continue
		}
		if !identity.ValidActorID(*actor) {
			return nil, w.ErrUnavailable
		}
		out = append(out, *actor)
	}
	if rows.Err() != nil || !stateSeen {
		return nil, w.ErrUnavailable
	}
	return out, nil
}
