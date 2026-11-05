package server

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"
)

type startupExecutionPolicyInventory struct {
	active bool
	err    error
	calls  int
}

func (i *startupExecutionPolicyInventory) HasActiveExecutionPolicy(context.Context) (bool, error) {
	i.calls++
	return i.active, i.err
}

func startupRethPolicy() config.NodePolicyConfig {
	return config.NodePolicyConfig{
		Mode: "reth", URL: "http://127.0.0.1:1", Token: strings.Repeat("t", 16),
		PrivateKeyFile: "/not-opened-by-configuration-validation", KeyID: "test",
		ChainID: 31337, DeploymentID: "test", ConsumerID: "producer",
		FactTTL: 30 * time.Second, IdentityTTL: time.Minute, PublishInterval: time.Second,
	}
}

func TestExecutionPolicyStartupRequiresConsumerForActiveState(t *testing.T) {
	for _, mode := range []string{"", "legacy"} {
		t.Run(mode, func(t *testing.T) {
			inventory := &startupExecutionPolicyInventory{active: true}
			err := validateExecutionPolicyStartup(t.Context(), config.NodePolicyConfig{Mode: mode}, inventory)
			if err == nil || !strings.Contains(err.Error(), "requires a compatible execution-policy consumer") {
				t.Fatalf("active policy was not refused: %v", err)
			}
			if inventory.calls != 1 {
				t.Fatalf("inventory called %d times", inventory.calls)
			}
		})
	}
}

func TestExecutionPolicyStartupAllowsLegacyWithoutActivePolicy(t *testing.T) {
	// Guard v1 can be enabled on this legacy path; its signed preflight is
	// not an execution-DSL consumer and does not change the inventory rule.
	inventory := &startupExecutionPolicyInventory{}
	if err := validateExecutionPolicyStartup(t.Context(), config.NodePolicyConfig{Mode: "legacy"}, inventory); err != nil {
		t.Fatal(err)
	}
	if inventory.calls != 1 {
		t.Fatalf("inventory called %d times", inventory.calls)
	}
}

func TestExecutionPolicyStartupInventoryFailureIsFatalAndOpaque(t *testing.T) {
	inventory := &startupExecutionPolicyInventory{err: errors.New("private tenant identifier and query details")}
	err := validateExecutionPolicyStartup(t.Context(), config.NodePolicyConfig{Mode: "legacy"}, inventory)
	if err == nil || !strings.Contains(err.Error(), "cannot inspect active execution-policy state") {
		t.Fatalf("inventory failure was not refused: %v", err)
	}
	if strings.Contains(err.Error(), "private tenant") || strings.Contains(err.Error(), "query details") {
		t.Fatalf("inventory failure exposed details: %v", err)
	}
	if err := validateExecutionPolicyStartup(t.Context(), config.NodePolicyConfig{}, nil); err == nil {
		t.Fatal("missing inventory was treated as an empty store")
	}
}

func TestExecutionPolicyStartupConfiguredRethDoesNotDependOnBootstrapReadiness(t *testing.T) {
	policy := startupRethPolicy()
	if err := policy.Validate(); err != nil {
		t.Fatalf("invalid test configuration: %v", err)
	}
	// The endpoint is unavailable, no bridge has been initialized and no
	// facts have been applied. Selected capable Reth still accepts its state.
	inventory := &startupExecutionPolicyInventory{active: true, err: errors.New("must not query")}
	if err := validateExecutionPolicyStartup(t.Context(), policy, inventory); err != nil {
		t.Fatal(err)
	}
	if inventory.calls != 0 {
		t.Fatalf("capable bootstrap depended on inventory: %d calls", inventory.calls)
	}
	if err := validateExecutionPolicyStartup(t.Context(), policy, nil); err != nil {
		t.Fatalf("capable bootstrap depended on a wired inventory: %v", err)
	}
}

func TestExecutionPolicyStartupInvalidModeNeverBecomesLegacy(t *testing.T) {
	inventory := &startupExecutionPolicyInventory{}
	err := validateExecutionPolicyStartup(t.Context(), config.NodePolicyConfig{Mode: "unknown"}, inventory)
	if err == nil || !strings.Contains(err.Error(), "OPS_NODE_POLICY_MODE must be legacy or reth") {
		t.Fatalf("invalid mode was not refused: %v", err)
	}
	if inventory.calls != 0 {
		t.Fatalf("invalid mode reached inventory: %d calls", inventory.calls)
	}
}

func TestExecutionPolicyStartupConstructorRejectsInvalidModeBeforeDatabase(t *testing.T) {
	cfg := &config.Config{DatabaseURL: ":invalid database URL", NodePolicy: config.NodePolicyConfig{Mode: "unknown"}}
	server, err := NewWithVerifier(cfg, nil)
	if server != nil || err == nil || !strings.Contains(err.Error(), "OPS_NODE_POLICY_MODE must be legacy or reth") {
		t.Fatalf("constructor did not reject mode before opening the database: server=%v error=%v", server, err)
	}
	if strings.Contains(err.Error(), "database") {
		t.Fatalf("invalid mode reached database startup: %v", err)
	}
}

func TestExecutionPolicyStartupConstructorRefusesActiveSourceBeforeServices(t *testing.T) {
	databaseURL := sharedTestDBURL(t)
	database, err := db.New(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := db.ResetTestDatabase(database); err != nil {
		t.Fatal(err)
	}
	org := &rbac.Organization{ID: uuid.NewString(), Slug: "startup-" + uuid.NewString(), Name: "Startup compatibility"}
	if err := database.CreateOrganization(t.Context(), org); err != nil {
		t.Fatal(err)
	}
	id := uuid.NewString()
	// A selected source with no corresponding execution projection is still
	// active policy state. Do not repair or ignore it during legacy startup.
	_, err = database.Conn().ExecContext(t.Context(), `INSERT INTO configuration_revisions
 (id,scope_kind,org_id,kind,revision,base_revision,source,digest,dependencies,status,created_by,created_principal_kind,activated_by,activated_at)
 VALUES($1,'organization',$2,'execution-rules',1,0,'{"preserve":"exact source"}',$3,'{}','active',$4,'human',$5,now())`,
		id, org.ID, "sha256:"+strings.Repeat("b", 64), uuid.NewString(), uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := database.Conn().ExecContext(ctx, `DELETE FROM configuration_revisions WHERE id=$1`, id); err != nil {
			t.Errorf("remove owned startup fixture: %v", err)
		}
		if _, err := database.Conn().ExecContext(ctx, `DELETE FROM organizations WHERE id=$1`, org.ID); err != nil {
			t.Errorf("remove owned startup organization: %v", err)
		}
	})
	snapshot := func() string {
		t.Helper()
		var row string
		if err := database.Conn().QueryRowContext(t.Context(), `SELECT row_to_json(r)::text FROM configuration_revisions r WHERE id=$1`, id).Scan(&row); err != nil {
			t.Fatal(err)
		}
		return row
	}
	before := snapshot()
	// Audit/Redis/node settings are intentionally absent: the active-policy
	// guard must refuse before reaching any of those services or workers.
	server, err := NewWithVerifier(&config.Config{DatabaseURL: databaseURL, NodePolicy: config.NodePolicyConfig{Mode: "legacy"}}, nil)
	if server != nil || err == nil || !strings.Contains(err.Error(), "requires a compatible execution-policy consumer") {
		t.Fatalf("constructor did not stop at active-policy compatibility: server=%v error=%v", server, err)
	}
	if strings.Contains(err.Error(), org.ID) || strings.Contains(err.Error(), id) || strings.Contains(err.Error(), "exact source") {
		t.Fatalf("startup refusal exposed tenant policy details: %v", err)
	}
	if after := snapshot(); after != before {
		t.Fatalf("startup rewrote active policy state: before=%s after=%s", before, after)
	}
}
