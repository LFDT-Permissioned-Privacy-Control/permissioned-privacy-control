package disclosurecase_test

import (
	"testing"

	c "privacy-proxy/internal/disclosurecase"
	"privacy-proxy/internal/policybundle"
)

func TestNamespaceLengthPrefixVectorAndSelectionIsolation(t *testing.T) {
	metadata := policybundle.BundleMetadata{Environment: "test", ChainID: "1", SourceRevision: "first"}
	base, err := c.Namespace(metadata, "epoch1")
	if err != nil || base != "sha256:b5244fd96220284ee712913b686d28e66f89e8fb4647d29e028825e4974a2bf6" {
		t.Fatal("independent LP vector", base, err)
	}
	for _, field := range []string{"environment", "chain", "epoch"} {
		m := metadata
		epoch := "epoch1"
		switch field {
		case "environment":
			m.Environment = "prod"
		case "chain":
			m.ChainID = "2"
		case "epoch":
			epoch = "epoch2"
		}
		other, err := c.Namespace(m, epoch)
		if err != nil || other == base {
			t.Fatal("selection did not isolate namespace", field, err)
		}
	}
	metadata.SourceRevision = "second"
	metadata.ManifestDigest = "different"
	same, err := c.Namespace(metadata, "epoch1")
	if err != nil || same != base {
		t.Fatal("ordinary source rollout invalidated cases", err)
	}
	metadata.ChainID = "01"
	if _, err := c.Namespace(metadata, "epoch1"); err == nil {
		t.Fatal("noncanonical chain accepted")
	}
}
