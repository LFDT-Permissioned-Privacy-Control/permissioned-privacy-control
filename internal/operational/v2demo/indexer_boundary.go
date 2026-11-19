package v2demo

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// CheckIndexerBoundary verifies the credentials actually exported to OPS,
// rather than assuming that absence of a particular environment key suffices.
// Owner and indexer credentials remain confined to offline provisioning.
func CheckIndexerBoundary(ctx context.Context, root string) error {
	root, err := canonicalRoot(root)
	if err != nil {
		return err
	}
	s, err := readState(root)
	if err != nil || !s.Configured {
		return ErrInvalid
	}
	raw, err := os.ReadFile(s.file("ops/env"))
	if err != nil {
		return err
	}
	checked := 0
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || !strings.HasSuffix(key, "_DSN") {
			continue
		}
		selected, err := url.Parse(value)
		if err != nil || selected.Scheme != "postgres" || selected.User == nil || selected.User.Username() == "postgres" || strings.Contains(selected.Path, "index") {
			return fmt.Errorf("OPS environment contains an invalid/private database binding")
		}
		own, err := pgx.Connect(ctx, value)
		if err != nil {
			return fmt.Errorf("OPS operational credential cannot open its own store")
		}
		_ = own.Close(ctx)
		selected.Path = "/ops_v2_demo_index"
		if s.PrivateNetwork {
			// This offline administrator can reach both clusters. The serving
			// OPS namespace cannot reach this cluster at all; its separate
			// network test proves that stronger boundary.
			index, _ := url.Parse(s.dsn("index", "postgres"))
			selected.Host = index.Host
		}
		forbidden, err := pgx.Connect(ctx, selected.String())
		if err == nil {
			_ = forbidden.Close(ctx)
			return fmt.Errorf("OPS operational credential can open the private indexer database")
		}
		var denied *pgconn.PgError
		if !errors.As(err, &denied) || (denied.Code != "42501" && !(s.PrivateNetwork && denied.Code == "28P01")) {
			return fmt.Errorf("private indexer access did not fail with database authorization denial")
		}
		checked++
	}
	if checked == 0 {
		return fmt.Errorf("no exported OPS operational credentials were checked")
	}
	return nil
}
