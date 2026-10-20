package testutil

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// SetupAnvilContainer starts an Anvil testcontainer with debug tracing enabled.
// Returns the RPC URL (e.g., "http://localhost:PORT") and a cleanup function.
// Falls back to ANVIL_URL env var if set (for CI or pre-existing Anvil).
func SetupAnvilContainer(t *testing.T) (string, func()) {
	t.Helper()

	// Allow using external Anvil (for CI or when running alongside docker-compose)
	if url := os.Getenv("ANVIL_URL"); url != "" {
		t.Logf("Using external Anvil at %s", url)
		return url, func() {}
	}

	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        "ghcr.io/foundry-rs/foundry:latest",
		ExposedPorts: []string{"8545/tcp"},
		Entrypoint:   []string{"anvil", "--host", "0.0.0.0", "--port", "8545", "--steps-tracing"},
		WaitingFor: wait.ForListeningPort("8545/tcp").
			WithStartupTimeout(30 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("failed to start Anvil container: %v", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		container.Terminate(ctx)
		t.Fatalf("failed to get Anvil host: %v", err)
	}

	port, err := container.MappedPort(ctx, "8545/tcp")
	if err != nil {
		container.Terminate(ctx)
		t.Fatalf("failed to get Anvil port: %v", err)
	}

	rpcURL := fmt.Sprintf("http://%s:%s", host, port.Port())
	t.Logf("Anvil running at %s", rpcURL)

	cleanup := func() {
		if err := container.Terminate(ctx); err != nil {
			t.Logf("failed to terminate Anvil container: %v", err)
		}
	}

	return rpcURL, cleanup
}
