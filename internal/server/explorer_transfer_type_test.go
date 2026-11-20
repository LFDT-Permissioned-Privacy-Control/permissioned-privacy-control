package server

import (
	"context"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"net/http/httptest"
	"privacy-proxy/internal/explorer"
	"privacy-proxy/internal/rbac"
	"testing"
)

type transferTypeProbe struct {
	explorer.ExplorerBackend
	kind                 string
	offset, limit, calls int
	unsupported          bool
	err                  error
}

func (p *transferTypeProbe) GetAllTransfers(context.Context, int, int) ([]explorer.TokenTransfer, int64, error) {
	p.calls++
	return nil, 900, nil
}
func (p *transferTypeProbe) GetAllTransfersByType(_ context.Context, l, o int, k string) ([]explorer.TokenTransfer, int64, error) {
	p.calls++
	p.kind, p.limit, p.offset = k, l, o
	if p.unsupported {
		return nil, 0, explorer.ErrTransferTypeUnsupported
	}
	return nil, 900, p.err
}

type untypedTransferProbe struct{ explorer.ExplorerBackend }

func TestLegacyAllTransfersAppliesOrRejectsType(t *testing.T) {
	gin.SetMode(gin.TestMode)
	p := &transferTypeProbe{}
	srv := &Server{explorerStore: p, explorerRedactor: explorer.NewRedactionEngine(nil, nil, rbac.ReadProfileStandard)}
	router := gin.New()
	router.GET("/transfers", srv.getExplorerAllTransfers)
	get := func(raw string) int {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("GET", "/transfers?"+raw, nil))
		if w.Code == 200 && w.Body.String() != `{"data":[],"total":0}` {
			t.Fatal("raw provider total escaped", w.Body.String())
		}
		return w.Code
	}
	for _, raw := range []string{"type=erc20&limit=2&offset=4", "type=+ERC721+&limit=2&offset=4", "type=Erc1155&limit=2&offset=4"} {
		if get(raw) != 200 || p.kind == "" || p.limit != 2 || p.offset != 4 {
			t.Fatal("typed page not applied", raw, p)
		}
	}
	before := p.calls
	for _, raw := range []string{"type=garbage", "type=+", "type=ERC20&type=ERC20", "type=ERC20&type=ERC721", "type=%zz"} {
		if get(raw) != 400 || p.calls != before {
			t.Fatal("invalid type broadened/read provider", raw)
		}
	}
	if get("type=") != 200 || get("") != 200 {
		t.Fatal("legacy all feed rejected")
	}
	p.err = status.Error(codes.Unimplemented, "older producer has no typed feed")
	if get("type=ERC20") != 400 {
		t.Fatal("unsupported older RPC did not reject type")
	}
	p.err = nil
	p.unsupported = true
	if get("type=ERC20") != 400 {
		t.Fatal("unsupported provider silently fell back")
	}
	srv.explorerStore = &untypedTransferProbe{}
	if get("type=ERC20") != 400 {
		t.Fatal("provider without typed capability silently fell back")
	}
}
