package v2demo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"

	"github.com/jackc/pgx/v5"
)

// ExplorerState compares only the actual existing store metadata. It never
// initializes, recovers, resets or deletes a confidential app context.
func ExplorerState(ctx context.Context, root string) error {
	root, e := canonicalRoot(root)
	if e != nil {
		return e
	}
	s, e := readState(root)
	if e != nil {
		return e
	}
	raw, e := os.ReadFile(s.file("explorer/source.json"))
	if e != nil {
		return e
	}
	pinned, e := os.ReadFile(s.file("explorer/source.sha256"))
	if e != nil {
		return e
	}
	hash := sha256.Sum256(raw)
	if strings.TrimSpace(string(pinned)) != hex.EncodeToString(hash[:]) {
		return ErrInvalid
	}
	var source struct {
		RecoveryEpoch string `json:"recoveryEpoch"`
		Limits        struct {
			MaxContexts      int   `json:"maxContexts"`
			MaxCipherBytes   int64 `json:"maxCipherBytes"`
			MaxMetadataBytes int64 `json:"maxMetadataBytes"`
		} `json:"limits"`
	}
	if json.Unmarshal(raw, &source) != nil || source.RecoveryEpoch != s.Epochs["sso"] || source.Limits.MaxContexts < 1 || source.Limits.MaxContexts > 200000 || source.Limits.MaxCipherBytes < 1 || source.Limits.MaxCipherBytes > 1<<30 || source.Limits.MaxMetadataBytes < 2048 || source.Limits.MaxMetadataBytes > 512<<20 {
		return ErrInvalid
	}
	c, e := pgx.Connect(ctx, s.dsn("explorer", "postgres"))
	if e != nil {
		return e
	}
	defer c.Close(ctx)
	tx, e := c.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	var matches bool
	e = tx.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(id=1 AND config_digest=$1 AND recovery_epoch=$2::uuid AND ready AND max_contexts=$3 AND max_cipher_bytes=$4 AND max_metadata_bytes=$5 AND context_count>=0 AND context_count<=max_contexts AND cipher_bytes>=0 AND cipher_bytes<=max_cipher_bytes AND context_count::bigint*2048<=max_metadata_bytes) FROM explorer_sso_v2.store_state`, hash[:], source.RecoveryEpoch, source.Limits.MaxContexts, source.Limits.MaxCipherBytes, source.Limits.MaxMetadataBytes).Scan(&matches)
	if e != nil {
		return e
	}
	if !matches {
		return ErrInvalid
	}
	return nil
}
