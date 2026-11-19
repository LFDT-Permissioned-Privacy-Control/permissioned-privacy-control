// Package indexertest connects integration tests to the real Indexer API and
// its actual migrations. Serving code never imports fixture infrastructure.
package indexertest

import (
	"context"
	"encoding/hex"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"privacy-proxy/internal/explorerquery"
	"privacy-proxy/internal/networkidentity"
	"privacy-proxy/internal/operational/explorerindex"
)

func Require(t testing.TB) {
	t.Helper()
	for _, key := range []string{"OPS_TEST_INDEXER_SOURCE", "OPS_TEST_INDEXED_READ_SERVER"} {
		value := os.Getenv(key)
		if value == "" {
			t.Skip("real indexer integration fixture requires " + key + "; see V2 test prerequisites")
		}
		if !filepath.IsAbs(value) {
			t.Fatal(key + " must be an absolute path")
		}
		if _, err := os.Stat(value); err != nil {
			t.Fatal(key + " is unavailable")
		}
	}
}
func processEnvironment(dsn string) []string {
	env := []string{}
	for _, item := range os.Environ() {
		if !strings.HasPrefix(item, "INDEXER_FIXTURE_") {
			env = append(env, item)
		}
	}
	return append(env, "INDEXER_FIXTURE_DSN="+dsn)
}

// Schema uses the producer's real migrations, never a consumer-maintained
// copy of its private SQL. Only the trusted owner seeds fixture identity.
func Schema(t testing.TB, owner *pgx.Conn, network networkidentity.Binding) {
	t.Helper()
	Require(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Getenv("OPS_TEST_INDEXED_READ_SERVER"), "--migrate")
	cmd.Env = processEnvironment(owner.Config().ConnString())
	if err := cmd.Run(); err != nil {
		t.Fatal("actual indexer migration fixture failed")
	}
	genesis, err := hex.DecodeString(strings.TrimPrefix(network.GenesisHash, "0x"))
	if err != nil || len(genesis) != 32 {
		t.Fatal("invalid fixture genesis")
	}
	if _, err := owner.Exec(ctx, `UPDATE indexer_dataset_metadata SET chain_id=$1,genesis_hash=$2 WHERE id=1`, network.ChainID, genesis); err != nil {
		t.Fatal("cannot initialize trusted fixture identity")
	}
}
func Grant(t testing.TB, owner *pgx.Conn, role string) {
	t.Helper()
	// This credential belongs to the Indexer fixture process alone, never OPS.
	if _, err := owner.Exec(context.Background(), "REVOKE CREATE ON SCHEMA public FROM PUBLIC;GRANT USAGE ON SCHEMA public TO "+pgx.Identifier{role}.Sanitize()+";GRANT SELECT ON ALL TABLES IN SCHEMA public TO "+pgx.Identifier{role}.Sanitize()); err != nil {
		t.Fatal("cannot grant fixture producer read access")
	}
}

func Open(t testing.TB, readerDSN string, network networkidentity.Binding) (*explorerindex.Reader, explorerquery.Binding) {
	return open(t, readerDSN, network, "", nil, explorerindex.DefaultLimits())
}

// OpenWithNode enables the producer's real point fallback against the same
// signed TLS node used by the consumer. Its explicit certificate is trusted;
// verification is never bypassed. The certificate carries no private key.
func OpenWithNode(t testing.TB, readerDSN string, network networkidentity.Binding, endpoint string, certificate []byte) (*explorerindex.Reader, explorerquery.Binding) {
	t.Helper()
	if endpoint == "" || len(certificate) == 0 {
		t.Fatal("node endpoint and explicit fixture certificate required")
	}
	return open(t, readerDSN, network, endpoint, certificate, explorerindex.DefaultLimits())
}

// OpenWithLimits exercises the consumer's original cumulative budget against
// the real service, without fake paging replies or producer limit changes.
func OpenWithLimits(t testing.TB, dsn string, network networkidentity.Binding, limits explorerindex.Limits) (*explorerindex.Reader, explorerquery.Binding) {
	return open(t, dsn, network, "", nil, limits)
}

func open(t testing.TB, readerDSN string, network networkidentity.Binding, endpoint string, certificate []byte, limits explorerindex.Limits) (*explorerindex.Reader, explorerquery.Binding) {
	t.Helper()
	Require(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target := listener.Addr().String()
	_ = listener.Close()
	binding := explorerquery.Binding{Network: network, APIVersion: explorerquery.APIVersion}
	cmd := exec.Command(os.Getenv("OPS_TEST_INDEXED_READ_SERVER"))
	cmd.Env = append(processEnvironment(readerDSN), "INDEXER_FIXTURE_LISTEN_ADDR="+target)
	if endpoint != "" {
		file := filepath.Join(t.TempDir(), "node-ca.crt")
		if err := os.WriteFile(file, certificate, 0600); err != nil {
			t.Fatal(err)
		}
		clean := cmd.Env[:0]
		for _, item := range cmd.Env {
			if !strings.HasPrefix(item, "SSL_CERT_FILE=") {
				clean = append(clean, item)
			}
		}
		cmd.Env = append(clean, "SSL_CERT_FILE="+file, "INDEXER_FIXTURE_NODE_CA_FILE="+file, "INDEXER_FIXTURE_NODE_RPC_URL="+endpoint)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal("cannot start actual indexer fixture")
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	exited := false
	t.Cleanup(func() {
		if !exited {
			_ = cmd.Process.Kill()
			<-done
		}
	})
	reader, err := explorerindex.OpenReader(context.Background(), target, binding, limits)
	if err != nil {
		t.Fatal("cannot construct selected Indexer client")
	}
	t.Cleanup(reader.Close)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-done:
			exited = true
			t.Fatal("Indexer fixture exited before availability")
		default:
		}
		ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		err := reader.CheckReady(ctx)
		cancel()
		if err == nil {
			return reader, binding
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("actual Indexer V2 API did not become available")
	return nil, explorerquery.Binding{}
}
