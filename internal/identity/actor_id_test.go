package identity_test

import (
	"strings"
	"testing"

	"privacy-proxy/internal/identity"
)

func TestCanonicalActorSyntaxDoesNotAcceptLegacyOrAmbiguousEncoding(t *testing.T) {
	if !identity.ValidActorID(azureActor) || !identity.ValidActorID(privadoActor) {
		t.Fatal("issued canonical actor rejected")
	}
	for _, bad := range []string{"", strings.ToUpper(azureActor), azureActor + "=", azureActor[:len(azureActor)-1] + "h", "did:polygonid:polygon:amoy:abc", "11111111-1111-1111-1111-111111111111", strings.TrimPrefix(azureActor, "ops:p1:")} {
		if identity.ValidActorID(bad) {
			t.Fatalf("noncanonical actor accepted: %q", bad)
		}
	}
}
