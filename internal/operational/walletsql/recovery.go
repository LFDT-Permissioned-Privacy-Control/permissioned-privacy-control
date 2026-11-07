package walletsql

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/strictjson"
	w "privacy-proxy/internal/walletops"
)

const MaxImportBytes = 16 << 20
const MaxImportRows = 100000

func EmptyCoverage() [32]byte { return sha256.Sum256([]byte("ops.wallet.empty-source/v1")) }
func Digest(raw string) ([32]byte, error) {
	var out [32]byte
	if len(raw) != 71 || !strings.HasPrefix(raw, "sha256:") {
		return out, w.ErrInvalid
	}
	decoded, err := hex.DecodeString(raw[7:])
	if err != nil || hex.EncodeToString(decoded) != raw[7:] {
		return out, w.ErrInvalid
	}
	copy(out[:], decoded)
	return out, nil
}
func DigestString(d [32]byte) string { return "sha256:" + hex.EncodeToString(d[:]) }

// offline serializes administrative changes only. Recovery requires draining
// every application replica; it does not implement distributed activation.
func offline(ctx context.Context, dsn string, callback func(context.Context, pgx.Tx) error) error {
	if strings.TrimSpace(dsn) == "" {
		return w.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		return w.ErrUnavailable
	}
	config.ConnectTimeout = 3 * time.Second
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return w.ErrUnavailable
	}
	defer closeConnection(conn)
	tx, err := conn.Begin(ctx)
	if err != nil {
		return w.ErrUnavailable
	}
	defer rollback(tx)
	if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout','1s',true),set_config('statement_timeout','55s',true),pg_advisory_xact_lock(49222381407002)`); err != nil {
		return w.ErrUnavailable
	}
	if err := checkSchema(ctx, tx); err != nil {
		return err
	}
	if err := callback(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return w.ErrUnavailable
	}
	return nil
}

// BootstrapEmpty only creates a previously absent namespace. It cannot reset
// revocations in an existing installation or bless an incomplete restore.
func BootstrapEmpty(ctx context.Context, dsn string, binding w.ServiceBinding, generation string) error {
	ns, err := binding.Namespace()
	if err != nil || !(w.ExpectedState{Generation: generation}).Valid() {
		return w.ErrInvalid
	}
	coverage := EmptyCoverage()
	return offline(ctx, dsn, func(ctx context.Context, tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ops_wallet_v2.wallet_links WHERE namespace=$1)OR EXISTS(SELECT 1 FROM ops_wallet_v2.wallet_challenges WHERE namespace=$1)OR EXISTS(SELECT 1 FROM ops_wallet_v2.store_state WHERE namespace=$1)`, ns[:]).Scan(&exists); err != nil {
			return w.ErrUnavailable
		}
		if exists {
			return w.ErrConflict
		}
		_, err := tx.Exec(ctx, `INSERT INTO ops_wallet_v2.store_state(namespace,generation,ready,revocation_coverage_digest)VALUES($1,$2::uuid,true,$3)`, ns[:], generation, coverage[:])
		if err != nil {
			return w.ErrUnavailable
		}
		return nil
	})
}
func BeginRecovery(ctx context.Context, dsn string, binding w.ServiceBinding, generation string) error {
	ns, err := binding.Namespace()
	if err != nil || !(w.ExpectedState{Generation: generation}).Valid() {
		return w.ErrInvalid
	}
	return offline(ctx, dsn, func(ctx context.Context, tx pgx.Tx) error {
		var zero [32]byte
		tag, err := tx.Exec(ctx, `INSERT INTO ops_wallet_v2.store_state(namespace,generation,ready,revocation_coverage_digest)VALUES($1,$2::uuid,false,$3) ON CONFLICT(namespace)DO UPDATE SET ready=false,generation=EXCLUDED.generation,revocation_coverage_digest=EXCLUDED.revocation_coverage_digest WHERE ops_wallet_v2.store_state.generation<>EXCLUDED.generation OR NOT ops_wallet_v2.store_state.ready`, ns[:], generation, zero[:])
		if err != nil {
			return w.ErrUnavailable
		}
		if tag.RowsAffected() != 1 {
			return w.ErrConflict
		}
		return nil
	})
}

type RevocationBatch struct {
	APIVersion         string       `json:"apiVersion"`
	Kind               string       `json:"kind"`
	Namespace          string       `json:"namespace"`
	SourceExportDigest string       `json:"sourceExportDigest"`
	Aliases            []Alias      `json:"aliases"`
	Revocations        []Revocation `json:"revocations"`
}
type Alias struct {
	LegacySubject     string `json:"legacySubject"`
	ActorID           string `json:"actorId"`
	EvidenceDigest    string `json:"evidenceDigest"`
	IdentityAuthority string `json:"identityAuthority"`
	SourceTenant      string `json:"sourceTenant"`
	SourceKind        string `json:"sourceKind"`
}
type Revocation struct {
	LegacySubject string `json:"legacySubject"`
	Address       string `json:"address"`
	RevokedAt     string `json:"revokedAt"`
}
type ImportSummary struct {
	Aliases   int `json:"aliases"`
	Rows      int `json:"rows"`
	Inserted  int `json:"inserted"`
	Revoked   int `json:"revoked"`
	Unchanged int `json:"unchanged"`
}
type resolvedRevocation struct {
	actor   string
	address common.Address
	at      time.Time
}

func validText(s string, max int, empty bool) bool {
	if (!empty && s == "") || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func validAliasAuthority(a Alias) bool {
	if a.IdentityAuthority == "privado" {
		return a.SourceTenant == "" && a.SourceKind == "human"
	}
	tenant, err := uuid.Parse(a.SourceTenant)
	return err == nil && tenant != uuid.Nil && tenant.String() == a.SourceTenant && a.IdentityAuthority == "https://login.microsoftonline.com/"+a.SourceTenant+"/v2.0" && (a.SourceKind == "human" || a.SourceKind == "service")
}
func decodeBatch(raw []byte, ns w.Namespace) (RevocationBatch, []resolvedRevocation, error) {
	var batch RevocationBatch
	if len(raw) == 0 || len(raw) > MaxImportBytes || !utf8.Valid(raw) {
		return batch, nil, w.ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	value, err := strictjson.ReadValue(d, 0, 16)
	if err != nil {
		return batch, nil, w.ErrInvalid
	}
	if _, err := d.Token(); err != io.EOF {
		return batch, nil, w.ErrInvalid
	}
	object, ok := value.(map[string]any)
	if !ok {
		return batch, nil, w.ErrInvalid
	}
	for _, key := range []string{"aliases", "revocations"} {
		array, ok := object[key].([]any)
		if !ok || len(array) > MaxImportRows {
			return batch, nil, w.ErrInvalid
		}
	}
	if strictjson.ExactDecode(value, &batch) != nil || batch.APIVersion != "ops.wallet-revocations/v1" || batch.Kind != "WalletRevocationBatch" || batch.Namespace != ns.String() || batch.Aliases == nil || batch.Revocations == nil || len(batch.Aliases) > MaxImportRows || len(batch.Revocations) > MaxImportRows {
		return batch, nil, w.ErrInvalid
	}
	if _, err := Digest(batch.SourceExportDigest); err != nil {
		return batch, nil, err
	}
	aliases := map[string]string{}
	for _, a := range batch.Aliases {
		if !validText(a.LegacySubject, 255, false) || !identity.ValidActorID(a.ActorID) || !validText(a.IdentityAuthority, 2048, false) || !validText(a.SourceTenant, 128, true) || !validAliasAuthority(a) {
			return batch, nil, w.ErrInvalid
		}
		if _, err := Digest(a.EvidenceDigest); err != nil {
			return batch, nil, err
		}
		if _, exists := aliases[a.LegacySubject]; exists {
			return batch, nil, w.ErrInvalid
		}
		aliases[a.LegacySubject] = a.ActorID
	}
	seen := map[string]bool{}
	resolved := map[string]resolvedRevocation{}
	for _, r := range batch.Revocations {
		actor, known := aliases[r.LegacySubject]
		address, err := w.ParseAddress(r.Address)
		if !known || err != nil || w.AddressString(address) != r.Address || len(r.RevokedAt) != 20 {
			return batch, nil, w.ErrInvalid
		}
		at, err := time.Parse(time.RFC3339, r.RevokedAt)
		if err != nil || at.Unix() < 0 || at.UTC().Format(time.RFC3339) != r.RevokedAt {
			return batch, nil, w.ErrInvalid
		}
		original := r.LegacySubject + "\x00" + r.Address
		if seen[original] {
			return batch, nil, w.ErrInvalid
		}
		seen[original] = true
		key := actor + "\x00" + r.Address
		previous, exists := resolved[key]
		if !exists || at.Before(previous.at) {
			resolved[key] = resolvedRevocation{actor, address, at}
		}
	}
	keys := make([]string, 0, len(resolved))
	for k := range resolved {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]resolvedRevocation, 0, len(keys))
	for _, k := range keys {
		out = append(out, resolved[k])
	}
	return batch, out, nil
}
func ImportRevocations(ctx context.Context, dsn string, binding w.ServiceBinding, generation string, raw []byte, expectedDigest [32]byte) (ImportSummary, error) {
	var summary ImportSummary
	ns, err := binding.Namespace()
	if err != nil || !(w.ExpectedState{Generation: generation}).Valid() || len(raw) == 0 || len(raw) > MaxImportBytes || sha256.Sum256(raw) != expectedDigest {
		return summary, w.ErrInvalid
	}
	batch, rows, err := decodeBatch(raw, ns)
	if err != nil {
		return summary, err
	}
	summary.Aliases = len(batch.Aliases)
	summary.Rows = len(batch.Revocations)
	err = offline(ctx, dsn, func(ctx context.Context, tx pgx.Tx) error {
		var unready bool
		if err := tx.QueryRow(ctx, `SELECT NOT ready AND generation=$2::uuid FROM ops_wallet_v2.store_state WHERE namespace=$1`, ns[:], generation).Scan(&unready); err != nil || !unready {
			return w.ErrConflict
		}
		counts := map[string]int{}
		for _, row := range rows {
			if _, known := counts[row.actor]; !known {
				var count int
				if err := tx.QueryRow(ctx, `SELECT count(*)FROM(SELECT 1 FROM ops_wallet_v2.wallet_links WHERE namespace=$1 AND actor_id=$2 LIMIT 4097)bounded`, ns[:], row.actor).Scan(&count); err != nil {
					return w.ErrUnavailable
				}
				counts[row.actor] = count
			}
			tag, err := tx.Exec(ctx, `INSERT INTO ops_wallet_v2.wallet_links(namespace,actor_id,address,proof_kind,revoked,revoked_at)VALUES($1,$2,$3,'legacy_revoked',true,$4)ON CONFLICT(namespace,actor_id,address)DO NOTHING`, ns[:], row.actor, row.address[:], row.at)
			if err != nil {
				return w.ErrUnavailable
			}
			if tag.RowsAffected() == 1 {
				if counts[row.actor] >= w.MaxLinks {
					return w.ErrConflict
				}
				counts[row.actor]++
				summary.Inserted++
				continue
			}
			tag, err = tx.Exec(ctx, `UPDATE ops_wallet_v2.wallet_links SET revoked=true,revoked_at=LEAST(COALESCE(revoked_at,$4),$4) WHERE namespace=$1 AND actor_id=$2 AND address=$3 AND(NOT revoked OR revoked_at>$4)`, ns[:], row.actor, row.address[:], row.at)
			if err != nil {
				return w.ErrUnavailable
			}
			if tag.RowsAffected() == 1 {
				summary.Revoked++
			} else {
				summary.Unchanged++
			}
		}
		return nil
	})
	if err != nil {
		return ImportSummary{}, err
	}
	return summary, nil
}

// FinalizeRecovery publishes an operator's explicit completeness attestation.
// It cannot prove an export included absent revocations; the operator is trusted.
func FinalizeRecovery(ctx context.Context, dsn string, binding w.ServiceBinding, state w.ExpectedState, acknowledgeComplete bool) error {
	ns, err := binding.Namespace()
	if err != nil || !state.Valid() || !acknowledgeComplete {
		return w.ErrInvalid
	}
	return offline(ctx, dsn, func(ctx context.Context, tx pgx.Tx) error {
		var unready bool
		if err := tx.QueryRow(ctx, `SELECT NOT ready AND generation=$2::uuid FROM ops_wallet_v2.store_state WHERE namespace=$1`, ns[:], state.Generation).Scan(&unready); err != nil || !unready {
			return w.ErrConflict
		}
		if err := validateStoredLinks(ctx, tx, ns); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE ops_wallet_v2.store_state SET ready=true,revocation_coverage_digest=$3 WHERE namespace=$1 AND generation=$2::uuid AND NOT ready`, ns[:], state.Generation, state.Coverage[:])
		if err != nil {
			return w.ErrUnavailable
		}
		if tag.RowsAffected() != 1 {
			return w.ErrConflict
		}
		return nil
	})
}
func validateStoredLinks(ctx context.Context, tx pgx.Tx, ns w.Namespace) error {
	lastActor := ""
	lastAddress := []byte{}
	for {
		rows, err := tx.Query(ctx, `SELECT actor_id,address,proof_kind,CASE WHEN octet_length(message)<=4096 THEN message ELSE NULL END,CASE WHEN octet_length(signature)=65 THEN signature ELSE NULL END,CASE WHEN octet_length(message_hash)=32 THEN message_hash ELSE NULL END,accepted_at,revoked,revoked_at FROM ops_wallet_v2.wallet_links WHERE namespace=$1 AND(actor_id,address)>($2,$3::bytea)ORDER BY actor_id,address LIMIT 1000`, ns[:], lastActor, lastAddress)
		if err != nil {
			return w.ErrUnavailable
		}
		count := 0
		for rows.Next() {
			var l w.Link
			var address, message []byte
			var accepted, revoked *time.Time
			if rows.Scan(&l.Actor, &address, &l.ProofKind, &message, &l.Signature, &l.MessageHash, &accepted, &l.Revoked, &revoked) != nil || len(address) != 20 {
				rows.Close()
				return w.ErrUnavailable
			}
			l.Namespace = ns
			l.Address = common.BytesToAddress(address)
			l.Message = string(message)
			if accepted != nil {
				l.AcceptedAt = *accepted
			}
			if revoked != nil {
				l.RevokedAt = *revoked
			}
			if l.Validate() != nil {
				rows.Close()
				return w.ErrUnavailable
			}
			lastActor = l.Actor
			lastAddress = bytes.Clone(address)
			count++
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return w.ErrUnavailable
		}
		if count < 1000 {
			return nil
		}
	}
}
