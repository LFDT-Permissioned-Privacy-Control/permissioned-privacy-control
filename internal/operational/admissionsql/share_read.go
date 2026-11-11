package admissionsql

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5"
	a "privacy-proxy/internal/admission"
	h "privacy-proxy/internal/admissionsharedata"
)

// ShareReader borrows an existing restricted reader Store. It owns neither a
// pool nor a writer callback, and must not close the caller's Store.
type ShareReader struct {
	store *Store
	meta  h.ShareMetadata
}

func NewShareReader(store *Store, expected h.ShareBinding) (*ShareReader, error) {
	if store == nil || store.pool == nil || store.mode != "reader" || store.schemaVersion != 3 || !expected.Valid() {
		return nil, a.ErrInvalid
	}
	return &ShareReader{store: store, meta: h.ShareMetadata{Binding: expected, Mode: "reader", Identity: h.NewReaderIdentity()}}, nil
}
func (r *ShareReader) Metadata() h.ShareMetadata {
	if r == nil {
		return h.ShareMetadata{}
	}
	return r.meta
}

// Nested CASE bounds array metadata/storage BEFORE unnesting, JSON creation or
// network decoding. A present malformed row yields NULL, never "absent".
// Even an owner-inserted oversized value cannot become an oversized pgx field.
const boundedShareProjection = `CASE WHEN
 octet_length(sender_actor_id)=50 AND sender_actor_id~'^ops:p1:[A-Za-z0-9_-]{43}$'
 AND array_ndims(recipients)=1 AND array_lower(recipients,1)=1
 AND cardinality(recipients) BETWEEN 1 AND 32 AND pg_column_size(recipients)<=8192
 AND octet_length(recipient_digest)=32 AND octet_length(anchor_hash)=32
 AND octet_length(manifest_digest)=32 AND octet_length(wallet_version)=32
 AND anchor_number BETWEEN 0 AND 18446744073709551615 AND scale(anchor_number)=0
 AND anchor_timestamp BETWEEN 0 AND 18446744073709551615 AND scale(anchor_timestamp)=0
 AND isfinite(declared_at) AND isfinite(wallet_evidence_at)
 THEN CASE WHEN NOT EXISTS(SELECT 1 FROM unnest(recipients) actor WHERE actor IS NULL OR octet_length(actor)<>50 OR actor!~'^ops:p1:[A-Za-z0-9_-]{43}$')
 THEN jsonb_build_object('actor',sender_actor_id,'organization',sender_org_id::text,
 'recipients',recipients,'recipientDigest',encode(recipient_digest,'hex'),'declaredAt',declared_at,
 'anchor',encode(anchor_hash,'hex'),'number',anchor_number::text,'timestamp',anchor_timestamp::text,
 'manifest',encode(manifest_digest,'hex'),'wallet',encode(wallet_version,'hex'),'walletEvidenceAt',wallet_evidence_at)::text
 ELSE NULL END ELSE NULL END`

type shareWire struct {
	Actor            string    `json:"actor"`
	Organization     string    `json:"organization"`
	Recipients       []string  `json:"recipients"`
	RecipientDigest  string    `json:"recipientDigest"`
	DeclaredAt       time.Time `json:"declaredAt"`
	Anchor           string    `json:"anchor"`
	Number           string    `json:"number"`
	Timestamp        string    `json:"timestamp"`
	Manifest         string    `json:"manifest"`
	Wallet           string    `json:"wallet"`
	WalletEvidenceAt time.Time `json:"walletEvidenceAt"`
}

func decodeShare(raw string, network a.Digest, hash common.Hash) (a.Share, error) {
	if len(raw) == 0 || len(raw) > 8192 {
		return a.Share{}, a.ErrUnavailable
	}
	var w shareWire
	if json.Unmarshal([]byte(raw), &w) != nil {
		return a.Share{}, a.ErrUnavailable
	}
	s := a.Share{Network: network, Hash: hash, Actor: w.Actor, Organization: w.Organization, Recipients: w.Recipients, DeclaredAt: w.DeclaredAt}
	for _, field := range []struct {
		raw string
		out []byte
	}{{w.RecipientDigest, s.RecipientDigest[:]}, {w.Anchor, s.Witness.AnchorHash[:]}, {w.Manifest, s.Witness.ManifestDigest[:]}, {w.Wallet, s.Witness.WalletVersion[:]}} {
		if len(field.raw) != 64 {
			return a.Share{}, a.ErrUnavailable
		}
		if _, err := hex.Decode(field.out, []byte(field.raw)); err != nil {
			return a.Share{}, a.ErrUnavailable
		}
	}
	var err error
	s.Witness.AnchorNumber, err = strconv.ParseUint(w.Number, 10, 64)
	if err != nil {
		return a.Share{}, a.ErrUnavailable
	}
	s.Witness.AnchorTimestamp, err = strconv.ParseUint(w.Timestamp, 10, 64)
	if err != nil {
		return a.Share{}, a.ErrUnavailable
	}
	s.Witness.WalletEvidenceAt = w.WalletEvidenceAt
	if !s.Valid() {
		return a.Share{}, a.ErrUnavailable
	}
	return s, nil
}

func (r *ShareReader) Read(ctx context.Context, q h.ShareQuery) (*h.SharePass, error) {
	if r == nil || r.store == nil || r.store.mode != "reader" || r.store.schemaVersion != 3 || ctx == nil {
		return nil, a.ErrInvalid
	}
	q, err := h.NormalizeShareQuery(q)
	if err != nil {
		return nil, err
	}
	fence, err := q.OperationFence(ctx)
	if err != nil {
		return nil, err
	}
	bound, cancel, err := fence.Bind(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	b := r.meta.Binding
	n := a.NetworkBinding{Environment: b.Network.Environment, ChainID: b.Network.ChainID, GenesisHash: b.Network.GenesisHash, DeploymentID: b.Network.DeploymentID}
	key, genesis, err := bindingValues(n)
	if err != nil {
		return nil, a.ErrInvalid
	}
	charged := 256 + 64*len(q.Hashes)
	if charged > q.ByteLimit() {
		return nil, h.ErrTooBroad
	}
	keys := make([][]byte, len(q.Hashes))
	for i := range q.Hashes {
		keys[i] = q.Hashes[i][:]
	}
	shares := make([]a.Share, 0, len(keys))
	err = r.store.readReady(bound, key, b.State, func(ctx context.Context, tx pgx.Tx) error {
		if verifyBinding(ctx, tx, key, n, genesis) != nil {
			return a.ErrUnavailable
		}
		rows, err := tx.Query(ctx, `SELECT tx_hash,`+boundedShareProjection+` FROM ops_admission_v2.tx_shares WHERE network_key=$1 AND tx_hash=ANY($2::bytea[]) ORDER BY tx_hash LIMIT 1025`, key[:], keys)
		if err != nil {
			return a.ErrUnavailable
		}
		defer rows.Close()
		for rows.Next() {
			var hash []byte
			var raw *string
			if rows.Scan(&hash, &raw) != nil || len(hash) != 32 || raw == nil || len(*raw) > 8192 || len(shares) >= len(keys) {
				return a.ErrUnavailable
			}
			// All SQL text is bounded before transport; charge retained/temporary
			// decoding conservatively before allocating its recipients.
			charged += 512 + 4*len(*raw)
			if charged > q.ByteLimit() {
				return h.ErrTooBroad
			}
			s, err := decodeShare(*raw, key, common.BytesToHash(hash))
			if err != nil {
				return err
			}
			shares = append(shares, s)
		}
		if rows.Err() != nil || ctx.Err() != nil {
			return a.ErrUnavailable
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if bound.Err() != nil || fence.Check() != nil {
		return nil, a.ErrUnavailable
	}
	return h.NewSharePass(r.meta.Identity, b, q, shares, fence)
}
func (r *ShareReader) Recheck(ctx context.Context, original *h.SharePass) error {
	if r == nil || original.ValidateFor(r.meta.Identity, r.meta.Binding) != nil {
		return a.ErrUnavailable
	}
	bound, cancel, err := original.Bind(ctx)
	if err != nil {
		return a.ErrUnavailable
	}
	defer cancel()
	current, err := r.Read(bound, original.Query())
	if err != nil || !original.SamePositives(current) || bound.Err() != nil || original.ValidateFor(r.meta.Identity, r.meta.Binding) != nil {
		return a.ErrUnavailable
	}
	return nil
}
