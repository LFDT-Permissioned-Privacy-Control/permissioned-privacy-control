package disclosuredata

import (
	p "privacy-proxy/internal/disclosurepolicy"
	"testing"
	"time"
)

// Independent Python protocol vector: all five kinds, retained finance semantics.
func TestFinanceRetainedFiveSourceGolden(t *testing.T) {
	descriptors := []SourceDescriptor{
		{Version: 1, Kind: "activity", Reference: "sha256:a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0", NetworkKey: "sha256:1111111111111111111111111111111111111111111111111111111111111111", Epoch: "sha256:b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0", Generation: "33333333-3333-4333-8333-333333333333", PlanDigest: "sha256:5555555555555555555555555555555555555555555555555555555555555555", FormatDigest: "sha256:c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0", CoverageDigest: "sha256:d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0", Population: "SEALED_RPC_COMPLETIONS_AS_OF_CHAIN_HEAD", AsOf: time.Unix(1900000000, 0).UTC()}, {Version: 1, Kind: "finance", Reference: "sha256:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1", NetworkKey: "sha256:1111111111111111111111111111111111111111111111111111111111111111", Epoch: "sha256:b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1", Generation: "33333333-3333-4333-8333-333333333333", PlanDigest: "sha256:5555555555555555555555555555555555555555555555555555555555555555", FormatDigest: "sha256:c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1", CoverageDigest: "sha256:d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1", Population: "RETAINED_ADMISSION_DECISIONS_AS_OF_SNAPSHOT", AsOf: time.Unix(1900000000, 0).UTC()}, {Version: 1, Kind: "history", Reference: "sha256:a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2", NetworkKey: "sha256:1111111111111111111111111111111111111111111111111111111111111111", Epoch: "sha256:b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2", Generation: "33333333-3333-4333-8333-333333333333", PlanDigest: "sha256:5555555555555555555555555555555555555555555555555555555555555555", FormatDigest: "sha256:c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2", CoverageDigest: "sha256:d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2", Population: "CURRENT_SCOPED_WALLET_HISTORY", AsOf: time.Unix(1900000000, 0).UTC()}, {Version: 1, Kind: "sanctions", Reference: "sha256:a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3", NetworkKey: "sha256:1111111111111111111111111111111111111111111111111111111111111111", Epoch: "sha256:b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3", Generation: "33333333-3333-4333-8333-333333333333", PlanDigest: "sha256:5555555555555555555555555555555555555555555555555555555555555555", FormatDigest: "sha256:c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3", CoverageDigest: "sha256:d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3", Population: "CURRENT_APPROVED_SANCTIONS", AsOf: time.Unix(1900000000, 0).UTC()}, {Version: 1, Kind: "wallet", Reference: "sha256:a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4", NetworkKey: "sha256:1111111111111111111111111111111111111111111111111111111111111111", Epoch: "sha256:b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4", Generation: "33333333-3333-4333-8333-333333333333", PlanDigest: "sha256:5555555555555555555555555555555555555555555555555555555555555555", FormatDigest: "sha256:c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4", CoverageDigest: "sha256:d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4", Population: "CURRENT_PROVED_ASSOCIATIONS", AsOf: time.Unix(1900000000, 0).UTC()},
	}
	got, err := SourceSetDigest(descriptors, p.ComplianceReport, Report)
	if err != nil || got != "sha256:69dcce2eba5da6f3c77594e949202bb2cee49a75af490e99b80392bdc0759d80" {
		t.Fatal("five-source retained vector", got, err)
	}
	descriptors[1].Population = "ADMISSION_DECISIONS_AS_OF_CUT"
	if _, err := SourceSetDigest(descriptors, p.ComplianceReport, Report); err == nil {
		t.Fatal("legacy commit-frontier population accepted")
	}
}
