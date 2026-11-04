package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureEnhancedLogger records the orgID argument passed to the chained
// writer so the test can assert logAccess forwards req.resolvedOrgID.
type captureEnhancedLogger struct {
	calledChained   bool
	gotOrgID        string
	gotDenialReason string
	writeErr        error
}

func (c *captureEnhancedLogger) LogAccessChained(
	_ context.Context,
	_ db.RBACAuditChain,
	_, _ string,
	_ int,
	_, _ string,
	_ []byte,
	_ *int,
	orgID string,
	denialReason string,
) (int64, time.Time, string, error) {
	c.calledChained = true
	c.gotOrgID = orgID
	c.gotDenialReason = denialReason
	return 1, time.Time{}, "hash", c.writeErr
}

func (c *captureEnhancedLogger) LogAccessEnhanced(
	_ context.Context,
	_, _ string,
	_ int,
	_, _ string,
	_ []byte,
	_ *int,
	orgID string,
	denialReason string,
) (int64, time.Time, error) {
	c.gotOrgID = orgID
	c.gotDenialReason = denialReason
	return 1, time.Time{}, nil
}

func (c *captureEnhancedLogger) UpdateAccessLogHash(_ context.Context, _ int64, _ string) error {
	return nil
}

// TestLogAccess_ForwardsResolvedOrgID locks the RD-1135 write-path wiring: the
// resolved org stamped onto the request must reach the access_logs writer so
// the row can later be org-scoped on read. A regression here would silently
// write NULL org_id and make a tenant admin unable to see their own row.
func TestLogAccess_ForwardsResolvedOrgID(t *testing.T) {
	cl := &captureEnhancedLogger{}
	// Both enhancedLogger and a non-nil hashChain are required for logAccess to
	// take the chained path (the production path).
	p := NewJSONRPCProcessor(JSONRPCProcessorConfig{
		ReadProfile:         rbac.ReadProfileStandard,
		EnhancedAuditLogger: cl,
		HashChain:           audit.NewHashChain(""),
	})

	req := &ProcessRequest{
		UserID:        "did:test:user",
		Method:        "eth_call",
		ClientIP:      "203.0.113.7",
		resolvedOrgID: "org-resolved-123",
		denialReason:  ReasonSenderNotLinked,
	}
	p.logAccess(context.Background(), req, 403)

	require.True(t, cl.calledChained, "logAccess must use the chained writer")
	assert.Equal(t, "org-resolved-123", cl.gotOrgID, "resolved org must reach the writer")
	assert.Equal(t, ReasonSenderNotLinked, cl.gotDenialReason, "denial reason (RD-1137) must reach the writer")
}

// TestLogAccess_EmptyResolvedOrgIDStaysEmpty confirms an unattributed request
// (anonymous / org-free metadata / pre-auth) forwards "" so the writer stores
// NULL — keeping such rows super-admin-only on read.
func TestLogAccess_EmptyResolvedOrgIDStaysEmpty(t *testing.T) {
	cl := &captureEnhancedLogger{}
	p := NewJSONRPCProcessor(JSONRPCProcessorConfig{
		ReadProfile:         rbac.ReadProfileStandard,
		EnhancedAuditLogger: cl,
		HashChain:           audit.NewHashChain(""),
	})

	req := &ProcessRequest{UserID: "did:test:anon", Method: "eth_blockNumber", ClientIP: "203.0.113.7"}
	p.logAccess(context.Background(), req, 200)

	require.True(t, cl.calledChained)
	assert.Equal(t, "", cl.gotOrgID)
}

type failedAccessBuffer struct{}

func (failedAccessBuffer) Append([]byte) (uint64, error) {
	return 0, errors.New("buffer write failed")
}

type countBasicAccessLogger struct{ calls int }

func (l *countBasicAccessLogger) LogAccess(context.Context, string, string, int, string) error {
	l.calls++
	return nil
}

func TestLogAccess_BufferFailureUsesChainedFallback(t *testing.T) {
	for _, failChain := range []bool{false, true} {
		t.Run(map[bool]string{false: "chain succeeds", true: "chain fails"}[failChain], func(t *testing.T) {
			chained, basic := &captureEnhancedLogger{}, &countBasicAccessLogger{}
			if failChain {
				chained.writeErr = errors.New("audit database unavailable")
			}
			p := NewJSONRPCProcessor(JSONRPCProcessorConfig{
				ReadProfile: rbac.ReadProfileStandard, AuditBuffer: failedAccessBuffer{},
				AccessLogger: basic, EnhancedAuditLogger: chained, HashChain: audit.NewHashChain(""),
			})
			p.logAccess(context.Background(), &ProcessRequest{
				UserID: "did:test:fallback", Method: "eth_call", resolvedOrgID: "org-fallback", denialReason: ReasonSenderNotLinked,
			}, 403)
			require.True(t, chained.calledChained)
			assert.Equal(t, "org-fallback", chained.gotOrgID)
			assert.Equal(t, ReasonSenderNotLinked, chained.gotDenialReason)
			assert.Zero(t, basic.calls, "a configured audit chain must never get an unchained fallback row")
		})
	}
}
