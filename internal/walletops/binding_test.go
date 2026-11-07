package walletops

import (
	"strings"
	"testing"
)

func TestBindingAndActorLockVectors(t *testing.T) {
	b := ServiceBinding{ServiceOrigin: "https://ops.test", Environment: "test", ChainID: "1", GenesisHash: "0x" + strings.Repeat("0", 63) + "1", DeploymentID: "wallet-protocol"}
	ns, err := b.Namespace()
	if err != nil || ns.String() != "sha256:c96e36483be3c21348f49b68eaa5dedf46b59a620a5331322c5bceebdb008fb9" {
		t.Fatal("namespace vector", ns, err)
	}
	a, c := ActorLock(ns, "ops:p1:"+strings.Repeat("A", 43))
	if a != -755110369 || c != -1325864373 {
		t.Fatal("signed int32 lock vector", a, c)
	}
	b.DeploymentID = "another"
	other, err := b.Namespace()
	if err != nil || other == ns {
		t.Fatal("deployment alias", err)
	}
	for _, chain := range []string{"", "0", "01", "-1", "0x1", strings.Repeat("9", 79)} {
		b.ChainID = chain
		if _, err := b.Namespace(); err == nil {
			t.Fatal("noncanonical chain", chain)
		}
	}
	b.ChainID = "1"
	for _, origin := range []string{"http://ops.test", "https://ops.test/", "https://user@ops.test", "https://ops.test?", "https://ops.test/path", "https://ops.test/#fragment"} {
		b.ServiceOrigin = origin
		if _, err := b.Namespace(); err == nil {
			t.Fatal("non-origin URL", origin)
		}
	}
}
func TestAddressAndNonceBoundaries(t *testing.T) {
	for _, raw := range []string{"0x" + strings.Repeat("a", 40), "0x" + strings.Repeat("A", 40)} {
		a, err := ParseAddress(raw)
		if err != nil || AddressString(a) != "0x"+strings.Repeat("a", 40) {
			t.Fatal("byte address equality", err)
		}
	}
	for _, raw := range []string{strings.Repeat("a", 40), "0X" + strings.Repeat("a", 40), "0x01", "0x" + strings.Repeat("g", 40)} {
		if _, err := ParseAddress(raw); err == nil {
			t.Fatal("address coercion", raw)
		}
	}
	if _, err := ParseNonce(strings.Repeat("A", 64)); err == nil {
		t.Fatal("noncanonical nonce")
	}
}
