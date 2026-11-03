package server

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"privacy-proxy/internal/compliance"
	"privacy-proxy/internal/db"
)

// statementCounter is a pgx tracer that records every statement (BEGIN and
// COMMIT included) issued under a context marked by measure. It counts
// statements, which is what each transfer costs in round trips at steady
// state; a cold per-connection prepare or an idle-connection reset ping is not
// counted. Statements from background work (the publisher, the probe) carry
// other contexts and are not counted.
type statementCounter struct {
	mu         sync.Mutex
	statements []string
}

type countedKey struct{}

var collapseSpace = regexp.MustCompile(`\s+`)

func (c *statementCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if ctx.Value(countedKey{}) == nil {
		return ctx
	}
	c.mu.Lock()
	{
		sql := strings.TrimSpace(collapseSpace.ReplaceAllString(data.SQL, " "))
		if len(sql) > 90 {
			sql = sql[:90]
		}
		c.statements = append(c.statements, sql)
	}
	c.mu.Unlock()
	return ctx
}
func (c *statementCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// measure runs fn with a marked context and returns the statements issued
// under it.
func (c *statementCounter) measure(fn func(ctx context.Context)) []string {
	c.mu.Lock()
	c.statements = nil
	c.mu.Unlock()
	fn(context.WithValue(context.Background(), countedKey{}, true))
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.statements...)
}

// configureCompliance enables enforced travel-rule compliance for the org of
// each user, as the gate-2 runner does (threshold above the transfer, a
// manual ETH price), so a transfer pays its real compliance reads and its
// compliance_logs record.
func configureCompliance(t *testing.T, database *db.DB, users []rd1112User) {
	t.Helper()
	ctx := context.Background()
	for _, user := range users {
		var org string
		if err := database.Conn().QueryRowContext(ctx, `SELECT g.org_id FROM users u JOIN user_memberships m ON m.user_id=u.id JOIN groups g ON g.id=m.group_id WHERE u.external_id=$1 LIMIT 1`, user.DID).Scan(&org); err != nil {
			t.Fatal(err)
		}
		if err := database.UpsertComplianceConfig(ctx, &compliance.ComplianceConfig{ID: uuid.NewString(), OrgID: org, Enabled: true, ThresholdFiat: 1000, Currency: "usd", UnknownPricePolicy: compliance.UnknownPriceForbidden, EnforcementMode: compliance.EnforcementEnforce}); err != nil {
			t.Fatal(err)
		}
		if err := database.UpsertTokenPrice(ctx, &compliance.TokenPrice{ID: uuid.NewString(), OrgID: org, TokenAddress: "native", Symbol: "ETH", Decimals: 18, PriceFiat: 3000, PricesByCurrency: map[string]float64{"usd": 3000}}, "usd"); err != nil {
			t.Fatal(err)
		}
	}
}

// R12.2 (RD-1410): database round trips per steady-state transfer on the
// processor path (RBAC admission, compliance, execution and the access log;
// the HTTP middleware is not part of it), counted with a pgx tracer rather
// than a load run. The budgets are the measured counts after the request-path
// DB budget change; a regression that adds a round trip fails here.
func TestTransferRoundTripsPerRequest(t *testing.T) {
	counter := &statementCounter{}
	database, err := db.New(sharedTestDBURL(t), db.WithQueryTracer(counter))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	budgets := map[rd1112Path]int{rd1112Legacy: legacyTransferRoundTrips, rd1112V2: v2TransferRoundTrips}
	for _, path := range []rd1112Path{rd1112Legacy, rd1112V2} {
		t.Run(string(path), func(t *testing.T) {
			if err := db.ResetTestDatabase(database); err != nil {
				t.Fatal(err)
			}
			h := newRD1112Harness(t, database, path, 1, true)
			defer h.Close()
			configureCompliance(t, database, h.Users)
			h.Proc.complianceChecker = compliance.NewChecker(database, 24*time.Hour, time.Hour)
			warm, measured := h.requests(t, "unique", 3)
			h.warm(t, warm)
			// Two more transfers settle every cache; the third is counted.
			for _, req := range measured[:2] {
				if res := h.Proc.Process(context.Background(), req); res.StatusCode != http.StatusOK {
					t.Fatalf("settling transfer: %+v", res.Error)
				}
			}
			var res *ProcessResult
			statements := counter.measure(func(ctx context.Context) { res = h.Proc.Process(ctx, measured[2]) })
			if res.StatusCode != http.StatusOK {
				t.Fatalf("measured transfer: %+v", res.Error)
			}
			t.Logf("%s transfer: %d round trips", path, len(statements))
			for i, sql := range statements {
				t.Logf("  %2d %s", i+1, sql)
			}
			// Exact, not a ceiling: a change that drops a read (a ban, sanctions
			// or the compliance record) must show up here as well as one that
			// adds a round trip. Update the budget when the change is intended.
			if len(statements) != budgets[path] {
				t.Errorf("%s transfer made %d round trips, budget %d:\n%s", path, len(statements), budgets[path], strings.Join(statements, "\n"))
			}
			for _, sql := range statements {
				if path == rd1112Legacy && strings.Contains(sql, "eth_address_links") {
					t.Errorf("a steady-state legacy transfer still writes the known system link: %s", sql)
				}
				if !strings.Contains(strings.Join(statements, "\n"), "INSERT INTO compliance_logs") {
					t.Fatal("the transfer wrote no compliance record")
				}
			}
		})
	}
}

// Round-trip budgets per steady-state transfer (TestTransferRoundTripsPerRequest).
// Before the request-path DB budget change: legacy 12, V2 15. Legacy no longer
// re-sends the sender's system link once it is known; V2's remaining per-request
// writes (intent INSERT, accepted UPDATE) move to the execution-tracking design.
const (
	legacyTransferRoundTrips = 11
	v2TransferRoundTrips     = 15
)

// The system link is still written for a new sender, and a link deleted by
// an administrator comes back at the latest one cache lifetime later.
func TestSystemLinkIsWrittenOnceThenRemembered(t *testing.T) {
	database, err := db.New(sharedTestDBURL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := db.ResetTestDatabase(database); err != nil {
		t.Fatal(err)
	}
	h := newRD1112Harness(t, database, rd1112Legacy, 1, true)
	defer h.Close()
	clock := time.Now()
	h.Proc.systemLinks.now = func() time.Time { return clock }
	warm, measured := h.requests(t, "unique", 2)
	links := func() int {
		var n int
		if err := database.Conn().QueryRow(`SELECT count(*) FROM eth_address_links WHERE did=$1 AND eth_address=$2`, h.Users[0].DID, h.Users[0].Address).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	h.warm(t, warm)
	if links() != 1 {
		t.Fatal("the first transfer did not system-link its sender")
	}
	if _, err := database.Conn().Exec(`DELETE FROM eth_address_links WHERE did=$1`, h.Users[0].DID); err != nil {
		t.Fatal(err)
	}
	if res := h.Proc.Process(context.Background(), measured[0]); res.StatusCode != http.StatusOK {
		t.Fatalf("%+v", res.Error)
	}
	if links() != 0 {
		t.Fatal("a remembered link was written again inside the cache lifetime")
	}
	clock = clock.Add(systemLinkCacheTTL + time.Second)
	if res := h.Proc.Process(context.Background(), measured[1]); res.StatusCode != http.StatusOK {
		t.Fatalf("%+v", res.Error)
	}
	if links() != 1 {
		t.Fatal("the link was not re-created after the cache lifetime")
	}
}
