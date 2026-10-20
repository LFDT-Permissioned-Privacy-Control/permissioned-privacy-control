// Package indexerclient provides an ExplorerBackend backed by the chain-indexer
// gRPC service. It embeds *explorer.Store for fallback, so methods that are
// not yet ported to gRPC keep hitting the SQL path unchanged.
//
// Cutover strategy: RD-855 Phase 3 migrates callers one method at a time.
// Each ported method:
//  1. Calls the indexer over gRPC
//  2. Maps the proto response to the corresponding explorer.* struct
//  3. Returns; the embedded *Store method is shadowed
//
// The SQL-visibility-filter variants (GetXxxFiltered) intentionally stay on
// *Store for now: the chain-indexer has no concept of visibility, so those
// require post-fetch filtering in the Open Privacy Suite which is a separate
// follow-up (RD-855 Phase 3 stage 2 — not in this commit).
package indexerclient

import (
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	indexerv1 "privacy-proxy/gen/go/chain_indexer/v1"
	"privacy-proxy/internal/explorer"
)

// Backend wraps a gRPC chain-indexer client. It embeds *explorer.Store so
// unmigrated methods keep hitting SQL until they are ported.
type Backend struct {
	*explorer.Store // fallback for methods not yet ported to gRPC

	client indexerv1.IndexerServiceClient
	conn   *grpc.ClientConn
}

// Config controls the gRPC client.
type Config struct {
	// IndexerURL is the dial target for the chain-indexer, e.g.
	// "chain-indexer:50051" or "dns:///chain-indexer.trust-zone.svc:50051".
	IndexerURL string

	// DialTimeout bounds how long New() will wait for the initial connection.
	// Default 5s if zero.
	DialTimeout time.Duration
}

// New constructs a Backend. The provided sqlStore is used for methods not
// yet ported to gRPC. It must already be connected and migrated.
func New(cfg Config, sqlStore *explorer.Store) (*Backend, error) {
	if cfg.IndexerURL == "" {
		return nil, errors.New("indexerclient: IndexerURL is required")
	}
	if sqlStore == nil {
		return nil, errors.New("indexerclient: sqlStore is required for fallback until all methods are ported")
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 5 * time.Second
	}

	conn, err := grpc.NewClient(
		cfg.IndexerURL,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		// The indexer and Open Privacy Suite share a trusted network
		// (RD-855 trust model): no auth token between them.
	)
	if err != nil {
		return nil, fmt.Errorf("indexerclient: dial %s: %w", cfg.IndexerURL, err)
	}

	return &Backend{
		Store:  sqlStore,
		client: indexerv1.NewIndexerServiceClient(conn),
		conn:   conn,
	}, nil
}

// Close releases the gRPC connection and the embedded SQL store.
func (b *Backend) Close() error {
	var firstErr error
	if b.conn != nil {
		if err := b.conn.Close(); err != nil {
			firstErr = err
		}
	}
	if b.Store != nil {
		if err := b.Store.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// isNotFound returns true if err is a gRPC NotFound status.
func isNotFound(err error) bool {
	return status.Code(err) == codes.NotFound
}

// Compile-time assertion that *Backend satisfies explorer.ExplorerBackend.
// The embedded *explorer.Store covers methods the gRPC-side handlers haven't
// overridden yet.
var _ explorer.ExplorerBackend = (*Backend)(nil)
