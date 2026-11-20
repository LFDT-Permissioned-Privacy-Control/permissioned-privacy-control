package historyfacts

import (
	"slices"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestCountFullAddressSetIsCompleteOriginalPlainAuthority(t *testing.T) {
	x := newFixture(t)
	c := x.begin(t, "Auditor", "Foreign")
	set, e := c.FullAddressSet(4096)
	if e != nil || !slices.Contains(set, x.a) || !slices.Contains(set, x.own) || slices.Contains(set, x.b) || slices.Contains(set, common.Address{}) || slices.Contains(set, common.Address{19: 18}) {
		t.Fatalf("plain current set %v %v", set, e)
	}
	if len(set) != 11 {
		t.Fatalf("own + selected association +9public, got%d", len(set))
	}
	set[0] = x.b
	again, e := c.FullAddressSet(4096)
	if e != nil || slices.Contains(again, x.b) {
		t.Fatal("caller mutation entered current authority")
	}
	if partial, e := c.FullAddressSet(10); e == nil || partial != nil {
		t.Fatal("truncated Full set returned as complete", partial, e)
	}
	readonly := x.begin(t, "Readonly")
	set, e = readonly.FullAddressSet(4096)
	if e != nil || slices.Contains(set, x.a) {
		t.Fatal("readonly manufactured plain contract access")
	}
}
func TestCountMethodScopeBorrowsOriginalIdentityWalletAndDeadline(t *testing.T) {
	x := newFixture(t)
	c := x.begin(t, "Auditor")
	before := x.wallets.loads
	next, e := c.ForMethod("eth_getLogs")
	if e != nil {
		t.Fatal(e)
	}
	if next.view != c.view || next.AuthCapture() != c.AuthCapture() || next.WalletVersion() != c.WalletVersion() || next.Organization() != c.Organization() || next.Method() != "eth_getLogs" || x.wallets.loads != before {
		t.Fatal("subcount refreshed authority")
	}
	d, done := c.OriginalFence()
	nd, ndone := next.OriginalFence()
	if !d.Equal(nd) || done != ndone {
		t.Fatal("subcount renewed owning lifetime")
	}
	if _, e = c.ForMethod("unknown_method"); e == nil {
		t.Fatal("unknown method granted")
	}
	x.clock.Add(600)
	if _, e = c.ForMethod("eth_getLogs"); e == nil {
		t.Fatal("expired original identity borrowed")
	}
}
