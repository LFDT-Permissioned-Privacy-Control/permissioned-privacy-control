package server

import (
	"context"
	"errors"
	"time"

	"privacy-proxy/internal/config"
)

const executionPolicyStartupTimeout = 10 * time.Second

type activeExecutionPolicyInventory interface {
	HasActiveExecutionPolicy(context.Context) (bool, error)
}

// validateExecutionPolicyStartup runs before workers or listeners start. The
// configured implementation is the authority here: node wiring/readiness comes
// later and must not prevent a capable runtime from loading its first policy.
func validateExecutionPolicyStartup(ctx context.Context, policy config.NodePolicyConfig, inventory activeExecutionPolicyInventory) error {
	if err := policy.Validate(); err != nil {
		return err
	}
	if policy.Enabled() {
		return nil
	}
	if inventory == nil {
		return errors.New("cannot inspect active execution-policy state; check database availability and schema compatibility")
	}
	active, err := inventory.HasActiveExecutionPolicy(ctx)
	if err != nil {
		// Startup errors can reach process logs. Do not expose policy contents,
		// tenant IDs or query details from the underlying inventory failure.
		return errors.New("cannot inspect active execution-policy state; check database availability and schema compatibility")
	}
	if active {
		return errors.New("active execution policy requires a compatible execution-policy consumer; retain a capable runtime or complete a reviewed migration")
	}
	return nil
}
