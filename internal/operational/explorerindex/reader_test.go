package explorerindex

import (
	"context"
	"errors"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	pb "privacy-proxy/gen/go/chain_indexer/v2"
	q "privacy-proxy/internal/explorerquery"
	"privacy-proxy/internal/networkidentity"
	"strings"
	"testing"
	"time"
)

func testBinding() q.Binding {
	return q.Binding{Network: networkidentity.Binding{Environment: "test", ChainID: "1", GenesisHash: "0x" + strings.Repeat("1", 64), DeploymentID: "test"}, APIVersion: q.APIVersion}
}
func TestLazyReaderDoesNotRequireIndexerAtStartup(t *testing.T) {
	r, e := OpenReader(t.Context(), "127.0.0.1:1", testBinding(), DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	if !r.Metadata().Binding.Valid() {
		t.Fatal("invalidstaticbinding")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	if r.CheckReady(ctx) == nil {
		t.Fatal("offlineindexerready")
	}
}
func TestNoSQLOrResolverFallback(t *testing.T) {
	for _, target := range []string{"postgres://reader:secret@localhost/db", "dns:///indexer:50051", "indexer:0", "indexer:050051", " indexer:50051"} {
		if _, e := OpenReader(t.Context(), target, testBinding(), DefaultLimits()); !errors.Is(e, ErrInvalid) {
			t.Fatal(target, e)
		}
	}
}
func TestTypedKeyRoundTripAndWrongFamily(t *testing.T) {
	hash := "0x" + strings.Repeat("a", 64)
	address := "0x" + strings.Repeat("b", 40)
	for family, pos := range map[q.Family]q.Position{q.Blocks: {Block: 12}, q.Transactions: {Block: 12, Index: 2, Hash: hash}, q.Logs: {Block: 12, Index: 3}, q.Transfers: {Block: 12, Index: 4}, q.Internals: {Block: 12, Hash: hash, Subkey: "0,1"}, q.Contracts: {Block: 12, Hash: address}, q.Addresses: {Hash: address}, q.Balances: {Hash: address, Subkey: address}, q.Holders: {Hash: address, Amount: "9007199254740993"}, q.Search: {Block: 12, Hash: hash, Subkey: "2"}} {
		wire, e := keyWire(family, &pos)
		if e != nil {
			t.Fatal(family, e)
		}
		got, e := keyRead(family, wire)
		if e != nil || got != pos {
			t.Fatal(family, got, e)
		}
		if _, e = keyRead(q.Sync, wire); e == nil {
			t.Fatal("wrongfamilyaccepted")
		}
	}
}
func TestFixedErrorReasonsPreserved(t *testing.T) {
	for reason, want := range map[string]error{"HISTORY_PRUNED": ErrPruned, "CHAIN_REORGED": ErrConflict, "DATASET_EPOCH_CHANGED": ErrConflict, "INDEX_RUN_CHANGED": ErrConflict} {
		s, e := status.New(codes.Aborted, "opaque").WithDetails(&errdetails.ErrorInfo{Reason: reason, Domain: "indexer.ops"})
		if e != nil {
			t.Fatal(e)
		}
		if !errors.Is(rpcError(s.Err()), want) {
			t.Fatal(reason)
		}
	}
}
func TestPageRejectsEpochFloorAnchorAndUnknownFields(t *testing.T) {
	r, e := OpenReader(t.Context(), "127.0.0.1:1", testBinding(), DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	for _, change := range []func(*pb.PageInfo){func(p *pb.PageInfo) { p.DatasetEpoch = "bad" }, func(p *pb.PageInfo) { p.RunFloorBlock = 11 }, func(p *pb.PageInfo) { p.ReadAt.BlockHash = []byte{1} }, func(p *pb.PageInfo) { p.Consistency = pb.Consistency_CONSISTENCY_CURRENT }, func(p *pb.PageInfo) { p.ProtoReflect().SetUnknown([]byte{0x98, 0x06, 0x01}) }} {
		o, e := r.newOperation(t.Context())
		if e != nil {
			t.Fatal(e)
		}
		p := &pb.PageInfo{ReadAt: &pb.ReadAt{BlockNumber: 10, BlockHash: []byte(strings.Repeat("x", 32))}, DatasetEpoch: "11111111-1111-4111-8111-111111111111", EndedAt: pb.EndedAt_ENDED_AT_END_OF_RANGE, Consistency: pb.Consistency_CONSISTENCY_SNAPSHOT}
		change(p)
		if o.page(p, pb.Consistency_CONSISTENCY_SNAPSHOT) == nil {
			t.Fatal("invalidpageaccepted")
		}
		o.Close()
	}
}
func TestOriginalOperationCancellationAndBudgetDoNotRenew(t *testing.T) {
	r, e := OpenReader(t.Context(), "127.0.0.1:1", testBinding(), DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	ctx, cancel := context.WithCancel(t.Context())
	o, e := r.newOperation(ctx)
	if e != nil {
		t.Fatal(e)
	}
	cancel()
	calls := 0
	_, e = o.call(context.Background(), &pb.GetChainViewRequest{}, func(context.Context) (proto.Message, error) { calls++; return &pb.GetChainViewResponse{}, nil })
	if e == nil || calls != 0 {
		t.Fatal("canceledoperationdispatched")
	}
	if e = o.retain(r.limits.MaxChargedBytes + 1); !errors.Is(e, ErrTooBroad) {
		t.Fatal(e)
	}
}
