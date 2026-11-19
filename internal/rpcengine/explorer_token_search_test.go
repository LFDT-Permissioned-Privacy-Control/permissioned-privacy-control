package rpcengine

import "testing"

func TestTokenSearchIsNativeAndCursorBound(t *testing.T) {
	a, e := parseExplorerRequest("/api/v2/explorer/tokens", "search=Bank+Token&type=ERC20&limit=2")
	if e != nil || a.query.Search != "Bank Token" || a.tokenType != "ERC20" {
		t.Fatal("token search missing", e)
	}
	b, e := parseExplorerRequest("/api/v2/explorer/tokens", "search=Other&type=ERC20&limit=2")
	if e != nil || a.digest == b.digest {
		t.Fatal("search not cursor-bound")
	}
	for _, x := range []struct{ path, query string }{
		{"/api/v2/explorer/tokens", "search=%00"},
		{"/api/v2/explorer/tokens", "search=a%0Ab"},
		{"/api/v2/explorer/tokens", "search=A&search=B"},
		{"/api/v2/explorer/tokens/0x1111111111111111111111111111111111111111", "search=A"},
		{"/api/v2/explorer/accounts", "search=A"},
	} {
		if _, e := parseExplorerRequest(x.path, x.query); e == nil {
			t.Fatal("unsupported/invalid search accepted", x)
		}
	}
}
