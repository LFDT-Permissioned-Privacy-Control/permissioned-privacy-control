package walletadapter

import (
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/walletops"
)

func TestCapturedWalletVersionBindsCanonicalFacts(t *testing.T) {
	var namespace walletops.Namespace
	namespace[0] = 1
	state := walletops.ExpectedState{Generation: "11111111-1111-1111-1111-111111111111"}
	state.Coverage[0] = 2
	actor := "ops:p1:" + strings.Repeat("A", 43)
	a, b := common.HexToAddress("0x1000000000000000000000000000000000000001"), common.HexToAddress("0x2000000000000000000000000000000000000002")
	before := []common.Address{b, a}
	version, err := snapshotVersion(namespace, state, actor, before)
	if err != nil {
		t.Fatal(err)
	}
	if version != "sha256:66dc529524bb9dd75bad0c9f703c0b754d0fc39a7c5c114b405a1a2a3daf9f1d" {
		t.Fatal("snapshot vector", version)
	}
	reordered, err := snapshotVersion(namespace, state, actor, []common.Address{a, b})
	if err != nil || version != reordered || before[0] != b {
		t.Fatal("order dependence/mutation", err)
	}
	variants := []struct {
		namespace walletops.Namespace
		state     walletops.ExpectedState
		actor     string
		addresses []common.Address
	}{
		{namespace, state, actor, []common.Address{a}},
		{namespace, state, actor, nil},
		{namespace, state, "ops:p1:" + strings.Repeat("A", 42) + "E", []common.Address{a, b}},
	}
	changed := state
	changed.Coverage[0] = 3
	variants = append(variants, struct {
		namespace walletops.Namespace
		state     walletops.ExpectedState
		actor     string
		addresses []common.Address
	}{namespace, changed, actor, []common.Address{a, b}})
	changed = state
	changed.Generation = "22222222-2222-2222-2222-222222222222"
	variants = append(variants, struct {
		namespace walletops.Namespace
		state     walletops.ExpectedState
		actor     string
		addresses []common.Address
	}{namespace, changed, actor, []common.Address{a, b}})
	other := namespace
	other[0] = 2
	variants = append(variants, struct {
		namespace walletops.Namespace
		state     walletops.ExpectedState
		actor     string
		addresses []common.Address
	}{other, state, actor, []common.Address{a, b}})
	for _, variant := range variants {
		got, err := snapshotVersion(variant.namespace, variant.state, variant.actor, variant.addresses)
		if err != nil || got == version {
			t.Fatal("changed fact reused version", got, err)
		}
	}
	if _, err := snapshotVersion(namespace, state, actor, []common.Address{a, a}); err == nil {
		t.Fatal("duplicate addresses accepted")
	}
}
