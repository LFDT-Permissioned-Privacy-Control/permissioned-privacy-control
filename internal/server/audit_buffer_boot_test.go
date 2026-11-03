package server

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"
)

// G66 at boot (RD-1410): the server seeds the async audit buffer from the
// chain's sealed high-water before the request path exists. A recreated,
// empty AUDIT_BUFFER_DIR while the audit database already holds buffer
// sequences up to N gets its first new sequence above N, and that event is
// sealed rather than skipped and deleted as "already sealed".
func TestServerSeedsTheAuditBufferFromTheSealedChain(t *testing.T) {
	// Building a whole server arms the process-wide method registries; restore
	// them so later tests in this package can still register namespaces.
	defer rbac.SnapshotMethodRegistriesForTest()()
	dbURL := sharedTestDBURL(t)
	database, err := db.New(dbURL)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := db.ResetTestDatabase(database); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	auditDB := db.NewAuditHandle(database)
	chain := audit.NewHashChain("")
	for seq := uint64(1); seq <= 3; seq++ {
		if _, err := auditDB.SealBufferedAccessLog(ctx, chain, db.AccessLogRecord{ExternalID: "did:test:boot", Method: "eth_chainId", StatusCode: 200}, seq, "access_logs"); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &config.Config{
		ReadProfile: rbac.ReadProfileStandard, NodeURL: "http://127.0.0.1:1", DatabaseURL: dbURL, AuditDatabaseURL: dbURL, AuditAdminDatabaseURL: dbURL,
		JWTSecret: "test-secret", JWTRefreshSecret: "test-refresh-secret", VerifierID: "did:privado:verifier:test", BaseURL: "http://127.0.0.1", Environment: "development",
		AuditBufferDir: t.TempDir(), AuditChainName: "access_logs",
	}
	s, err := NewWithVerifier(cfg, &mockPrivadoVerifier{})
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	defer s.Stop()
	if got := s.auditBuffer.AllocatedThrough(); got != 3 {
		t.Fatalf("buffer seeded at %d, want the sealed high-water 3", got)
	}
	data, _ := json.Marshal(db.AccessLogRecord{ExternalID: "did:test:boot", Method: "net_version", StatusCode: 200})
	seq, err := s.auditBuffer.Append(data)
	if err != nil || seq != 4 {
		t.Fatalf("first append after boot: %d %v, want 4", seq, err)
	}
	// The server's own sealer (running since boot) seals it.
	deadline := time.Now().Add(10 * time.Second)
	for {
		hw, err := auditDB.GetMaxAccessLogBufferSeq(ctx, "access_logs")
		if err == nil && hw == 4 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the event appended after boot was not sealed: high-water %d %v", hw, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	res, err := audit.NewVerifier(database.Conn(), database).Verify(ctx, audit.ChainAccessLogs)
	if err != nil || !res.OK || res.ScannedRows != 4 {
		t.Fatalf("chain after boot: %+v %v", res, err)
	}
}
