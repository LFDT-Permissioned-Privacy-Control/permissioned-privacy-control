package db

import (
	"context"
	"errors"
	"testing"

	"privacy-proxy/internal/nodepolicy"
)

// TestNetworkSingletonGuard is G40 (RD-1410): the tracking database records
// the network at its first start; another network is refused, a restart with
// the same network keeps the incarnation, and an unmigrated database reads as
// uninitialised (never as an empty, adoptable one).
func TestNetworkSingletonGuard(t *testing.T) {
	_, mainURL := setupMainAndURL(t)
	execURL := newTrackingDatabase(t, mainURL)
	ctx := context.Background()

	pool, err := NewWithoutMigrate(execURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := NewExecHandle(pool).TrackingMeta(ctx); !errors.Is(err, ErrTrackingUninitialised) {
		t.Fatalf("unmigrated tracking database: %v, want ErrTrackingUninitialised", err)
	}

	runtime, admin, first := openTracking(t, execURL, trackingTestNetwork)
	if first.Network != trackingTestNetwork || first.Incarnation.String() == "00000000-0000-0000-0000-000000000000" {
		t.Fatalf("first start recorded %+v", first)
	}
	again, err := admin.EnsureTrackingMeta(ctx, trackingTestNetwork)
	if err != nil || again != first {
		t.Fatalf("restart with the same network: %+v %v, want %+v", again, err, first)
	}
	read, err := runtime.TrackingMeta(ctx)
	if err != nil || read != first {
		t.Fatalf("runtime read %+v %v", read, err)
	}
	for _, other := range []nodepolicy.Network{
		{ChainID: trackingTestNetwork.ChainID + 1, DeploymentID: trackingTestNetwork.DeploymentID},
		{ChainID: trackingTestNetwork.ChainID, DeploymentID: "another-deployment"},
	} {
		if _, err := admin.EnsureTrackingMeta(ctx, other); !errors.Is(err, ErrTrackingNetworkMismatch) {
			t.Fatalf("network %+v: %v, want ErrTrackingNetworkMismatch", other, err)
		}
	}
	if read, _ := runtime.TrackingMeta(ctx); read != first {
		t.Fatalf("a refused network changed the singleton: %+v", read)
	}
}
