package audit

import (
	"context"
	"os"
	"testing"

	"privacy-proxy/internal/audit/buffer"
	"privacy-proxy/internal/db"
)

// Audit-write hot-path before/after (RD-1112). NODE-FREE by construction —
// measures only the proxy's per-request audit cost (the dominant bottleneck),
// not anything the Ethereum node does. b.RunParallel simulates concurrent
// requests. Run against a real, migrated Postgres:
//
//	AUDIT_BENCH_DSN=postgres://postgres:postgres@localhost:5432/privacy_proxy?sslmode=disable \
//	  go test -run '^$' -bench BenchmarkAuditWrite -benchmem -cpu 1,8,32 ./internal/audit/
func benchDSN(b *testing.B) string {
	dsn := os.Getenv("AUDIT_BENCH_DSN")
	if dsn == "" {
		b.Skip("set AUDIT_BENCH_DSN to a real migrated Postgres to run this benchmark")
	}
	return dsn
}

var benchParams = []byte(`{"params":["0xf86c808504a817c80082520894abcabcabcabcabcabcabcabcabcabcabcabcabca880de0b6b3a764000080"]}`)

// BenchmarkAuditWriteSyncChain — the CURRENT synchronous path: LogAccessChained
// holds one process-global mutex across two Postgres round-trips (nextval +
// chained INSERT) per request. Under RunParallel the mutex serializes all
// callers, so this measures the serialized per-write cost.
func BenchmarkAuditWriteSyncChain(b *testing.B) {
	dsn := benchDSN(b)
	d, err := db.NewWithoutMigrate(dsn)
	if err != nil {
		b.Fatalf("open db: %v", err)
	}
	defer d.Close()

	ctx := context.Background()
	seed, _ := d.GetLatestAccessLogHash(ctx)
	chain := NewHashChain(seed)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, _, _, err := d.LogAccessChained(ctx, chain,
				"did:bench:user", "eth_sendRawTransaction", 200, "127.0.0.1", "", benchParams, nil, "", ""); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

// BenchmarkAuditWriteAsyncBuffer — the NEW path: append the same record to the
// durable Pebble buffer (fsync) and return. No Postgres and no chain mutex on
// the request path; the background sealer drains it off-path.
func BenchmarkAuditWriteAsyncBuffer(b *testing.B) {
	buf, err := buffer.Open(b.TempDir())
	if err != nil {
		b.Fatalf("open buffer: %v", err)
	}
	defer buf.Close()

	rec := []byte(`{"e":"did:bench:user","m":"eth_sendRawTransaction","s":200,"ip":"127.0.0.1","p":"` + string(benchParams) + `"}`)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := buf.Append(rec); err != nil {
				b.Error(err)
				return
			}
		}
	})
}
