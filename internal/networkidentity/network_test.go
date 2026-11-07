package networkidentity_test

import (
	"errors"
	"strings"
	"testing"

	"privacy-proxy/internal/admission"
	n "privacy-proxy/internal/networkidentity"
)

func TestExistingNetworkBytesAndWrapperAcceptance(t *testing.T) {
	base := n.Binding{Environment: "test", ChainID: "1", GenesisHash: "0x" + strings.Repeat("0", 63) + "1", DeploymentID: "test-deployment"}
	key, e := base.Key()
	if e != nil || admission.Digest(key).String() != "sha256:308c17e9717958e307cf48c146ecedfe1f51e7e3e712b3cc57ab53fe8b27d44a" {
		t.Fatal("independent canonical network vector", key, e)
	}
	cases := []struct {
		name   string
		change func(*n.Binding)
		valid  bool
	}{
		{"uint64max", func(b *n.Binding) { b.ChainID = "18446744073709551615" }, true},
		{"zero chain", func(b *n.Binding) { b.ChainID = "0" }, false},
		{"overflow", func(b *n.Binding) { b.ChainID = "18446744073709551616" }, false},
		{"leadingzero", func(b *n.Binding) { b.ChainID = "01" }, false},
		{"signed", func(b *n.Binding) { b.ChainID = "+1" }, false},
		{"spaces preserved", func(b *n.Binding) { b.Environment = " test "; b.DeploymentID = " deployment " }, true},
		{"existing C1 acceptance", func(b *n.Binding) { b.Environment = "test\u0085" }, true},
		{"ASCII controls", func(b *n.Binding) { b.Environment = "test\n" }, false},
		{"zero genesis derivation", func(b *n.Binding) { b.GenesisHash = "0x" + strings.Repeat("0", 64) }, true},
		{"uppercase hex", func(b *n.Binding) { b.GenesisHash = "0x" + strings.Repeat("A", 64) }, false},
		{"invalidUTF8", func(b *n.Binding) { b.Environment = string([]byte{0xff}) }, false},
	}
	for _, row := range cases {
		t.Run(row.name, func(t *testing.T) {
			b := base
			row.change(&b)
			got, e := b.Key()
			old, oe := (admission.NetworkBinding{Environment: b.Environment, ChainID: b.ChainID, GenesisHash: b.GenesisHash, DeploymentID: b.DeploymentID}).Key()
			if (e == nil) != row.valid || (oe == nil) != row.valid || e == nil && got != [32]byte(old) {
				t.Fatal("acceptance/bytes changed", e, oe)
			}
			if !row.valid && (!errors.Is(e, n.ErrInvalid) || !errors.Is(oe, admission.ErrInvalid)) {
				t.Fatal("public error compatibility", e, oe)
			}
		})
	}
}
