package rpcengine

import (
	"crypto/sha256"
	"privacy-proxy/internal/explorerquery"
	"testing"
)

func TestTransferTypeStrictQueryAndOriginalUnfilteredDigest(t *testing.T) {
	// Source-qualified pre-change JSON from d5106f57 parseExplorerRequest:
	// Query has no TokenKind member. Keeping these exact digest bytes makes
	// existing unfiltered AEAD cursor query bindings interoperable.
	const legacy = `{"Route":"/transfers","Query":{"Family":"transfers","Address":"","Hash":"","Token":"","Topic0":"","Search":"","Block":null,"From":null,"Through":null,"Upper":null,"After":null,"DatasetEpoch":"","RunFloor":null,"RawLimit":4},"Limit":1,"Category":"","TokenType":"","Interval":""}`
	original, e := parseExplorerRequest("/api/v2/explorer/transfers", "limit=1")
	if e != nil || original.digest != sha256.Sum256([]byte(legacy)) {
		t.Fatalf("old unfiltered cursor query digest changed: %x %v", original.digest, e)
	}
	for _, kind := range []string{"ERC20", "ERC721", "ERC1155"} {
		r, e := parseExplorerRequest("/api/v2/explorer/transfers", "type="+kind+"&limit=1")
		if e != nil || r.query.TokenKind != explorerquery.TokenKind(kind) || r.digest == original.digest {
			t.Fatalf("missing source/cursor filter: %+v %v", r, e)
		}
		other, _ := parseExplorerRequest("/api/v2/explorer/transfers", "type=ERC20&limit=1")
		if kind != "ERC20" && other.digest == r.digest {
			t.Fatal("different kinds share query identity")
		}
	}
	for _, raw := range []string{"type=", "type=erc20", "type=+ERC20", "type=ERC777", "type=ERC20&type=ERC20", "type=ERC20&type=ERC721", "type=%zz"} {
		if _, e := parseExplorerRequest("/api/v2/explorer/transfers", raw); e == nil {
			t.Fatal("invalid kind accepted", raw)
		}
	}
	for _, path := range []string{"/api/v2/explorer/transactions", "/api/v2/explorer/addresses/0x1111111111111111111111111111111111111111/transfers"} {
		if _, e := parseExplorerRequest(path, "type=ERC20"); e == nil {
			t.Fatal("unapproved filter route accepted", path)
		}
	}
}
