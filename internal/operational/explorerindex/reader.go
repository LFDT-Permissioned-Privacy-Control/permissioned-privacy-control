// Package explorerindex is a typed consumer of chain_indexer.v2. It owns no SQL,
// server read sessions or database identity. Policy remains with OPS.
package explorerindex

import (
	"bytes"
	"context"
	"encoding/hex"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	pb "privacy-proxy/gen/go/chain_indexer/v2"
	"privacy-proxy/internal/admissionsharedata"
	q "privacy-proxy/internal/explorerquery"
)

var (
	ErrInvalid     = q.ErrInvalid
	ErrUnavailable = q.ErrUnavailable
	ErrTooBroad    = q.ErrTooBroad
	ErrConflict    = q.ErrConflict
	ErrPruned      = q.ErrPruned
	ErrNotFound    = q.ErrNotFound
)

const Mode = q.Mode
const maxMessage = 16 << 20

type Limits struct {
	Timeout                                                 time.Duration
	MaxChargedBytes, MaxFieldBytes, MaxResultRows, MaxCalls int
}

func DefaultLimits() Limits { return Limits{5 * time.Second, 16 << 20, 2 << 20, 20000, 128} }
func (l Limits) Valid() bool {
	m := DefaultLimits()
	return l.Timeout > 0 && l.Timeout <= m.Timeout && l.MaxChargedBytes > 0 && l.MaxChargedBytes <= m.MaxChargedBytes && l.MaxFieldBytes > 0 && l.MaxFieldBytes <= m.MaxFieldBytes && l.MaxResultRows > 0 && l.MaxResultRows <= m.MaxResultRows && l.MaxCalls > 0 && l.MaxCalls <= m.MaxCalls
}

type Reader struct {
	conn     *grpc.ClientConn
	client   pb.IndexerServiceClient
	metadata q.Metadata
	limits   Limits
	closed   atomic.Bool
}

func OpenReader(ctx context.Context, target string, binding q.Binding, limits Limits) (*Reader, error) {
	if ctx == nil || ctx.Err() != nil || !binding.Valid() || !limits.Valid() || len(target) > 512 || strings.TrimSpace(target) != target || strings.ContainsAny(target, "/\\@?#\r\n\t") {
		return nil, ErrInvalid
	}
	host, port, err := net.SplitHostPort(target)
	n, pe := strconv.ParseUint(port, 10, 16)
	if err != nil || pe != nil || host == "" || n == 0 || strconv.FormatUint(n, 10) != port {
		return nil, ErrInvalid
	}
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithDisableRetry(), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxMessage), grpc.MaxCallSendMsgSize(4<<20)))
	if err != nil {
		return nil, ErrUnavailable
	}
	// Deliberately lazy. An indexer outage cannot prevent ordinary OPS startup.
	return &Reader{conn: conn, client: pb.NewIndexerServiceClient(conn), metadata: q.Metadata{Binding: binding, Mode: Mode, Identity: q.NewReaderIdentity()}, limits: limits}, nil
}
func (r *Reader) Metadata() q.Metadata {
	if r == nil {
		return q.Metadata{}
	}
	return r.metadata
}
func (r *Reader) Close() {
	if r != nil && r.closed.CompareAndSwap(false, true) {
		_ = r.conn.Close()
	}
}
func (r *Reader) valid() bool { return r != nil && !r.closed.Load() }
func Reason(err error) string {
	for _, d := range status.Convert(err).Details() {
		if i, ok := d.(*errdetails.ErrorInfo); ok && i.Domain == "indexer.ops" {
			return i.Reason
		}
	}
	return ""
}
func rpcError(err error) error {
	if err == nil {
		return nil
	}
	switch Reason(err) {
	case "HISTORY_PRUNED":
		return ErrPruned
	case "CHAIN_REORGED", "DATASET_EPOCH_CHANGED", "INDEX_RUN_CHANGED":
		return ErrConflict
	}
	switch status.Code(err) {
	case codes.NotFound:
		return ErrNotFound
	case codes.ResourceExhausted:
		return ErrTooBroad
	case codes.Aborted:
		return ErrConflict
	default:
		return ErrUnavailable
	}
}
func closedMessage(m proto.Message) bool {
	if m == nil || !m.ProtoReflect().IsValid() {
		return false
	}
	var visit func(protoreflect.Message) bool
	visit = func(m protoreflect.Message) bool {
		if m.Descriptor().FullName() == "google.protobuf.Timestamp" {
			fields := m.Descriptor().Fields()
			sec := m.Get(fields.ByName("seconds")).Int()
			ns := m.Get(fields.ByName("nanos")).Int()
			if sec < -62135596800 || sec > 253402300799 || ns < 0 || ns > 999999999 {
				return false
			}
		}
		if len(m.GetUnknown()) != 0 {
			return false
		}
		ok := true
		m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
			if fd.IsMap() {
				return true
			}
			if fd.Kind() == protoreflect.MessageKind {
				if fd.IsList() {
					l := v.List()
					for i := 0; i < l.Len(); i++ {
						if !visit(l.Get(i).Message()) {
							ok = false
							break
						}
					}
				} else {
					ok = visit(v.Message())
				}
			}
			return ok
		})
		return ok
	}
	return visit(m.ProtoReflect())
}
func hexBytes(v []byte) string { return "0x" + hex.EncodeToString(v) }
func unhex(s string, n int) ([]byte, error) {
	if len(s) != 2+n*2 || !strings.HasPrefix(s, "0x") {
		return nil, ErrInvalid
	}
	b, e := hex.DecodeString(s[2:])
	if e != nil || hexBytes(b) != s {
		return nil, ErrInvalid
	}
	return b, nil
}
func canonicalEpoch(s string) bool {
	id, e := uuid.Parse(s)
	return e == nil && id != uuid.Nil && id.String() == s
}

type operation struct {
	mu                   sync.Mutex
	owner                *Reader
	fence                admissionsharedata.Fence
	read                 *pb.ReadContext
	charged, calls, rows int
	closed               bool
}

func (r *Reader) newOperation(ctx context.Context) (*operation, error) {
	if !r.valid() {
		return nil, ErrUnavailable
	}
	f, e := admissionsharedata.NewFence(ctx, r.limits.Timeout)
	if e != nil {
		return nil, ErrUnavailable
	}
	return &operation{owner: r, fence: f}, nil
}
func (o *operation) call(ctx context.Context, request proto.Message, fn func(context.Context) (proto.Message, error)) (proto.Message, error) {
	if o.closed || !o.owner.valid() || o.fence.Check() != nil || o.calls >= o.owner.limits.MaxCalls {
		return nil, ErrUnavailable
	}
	o.calls++
	if err := o.retain(proto.Size(request) * 2); err != nil {
		return nil, err
	}
	bound, cancel, e := o.fence.Bind(ctx)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer cancel()
	reply, e := fn(bound)
	if e != nil {
		return nil, e
	}
	if !closedMessage(reply) || bound.Err() != nil || o.fence.Check() != nil {
		return nil, ErrUnavailable
	}
	if e = o.retain(proto.Size(reply) * 2); e != nil {
		return nil, e
	}
	return reply, nil
}

// chargeRows belongs to the original operation, including protected CURRENT
// rechecks. Exhaustion retires the purpose; no later call can renew the ledger.
func (o *operation) chargeRows(n int) error {
	if n < 0 || n > o.owner.limits.MaxResultRows-o.rows {
		o.closed = true
		return ErrTooBroad
	}
	o.rows += n
	return nil
}
func (o *operation) retain(n int) error {
	if n < 0 || n > o.owner.limits.MaxChargedBytes-o.charged {
		return ErrTooBroad
	}
	o.charged += n
	return nil
}
func (o *operation) Close() { o.mu.Lock(); defer o.mu.Unlock(); o.closed = true }
func (o *operation) page(p *pb.PageInfo, consistency pb.Consistency) error {
	if p == nil || !closedMessage(p) || p.ReadAt == nil || len(p.ReadAt.BlockHash) != 32 || bytes.Equal(p.ReadAt.BlockHash, make([]byte, 32)) || p.ReadAt.BlockNumber > 1<<63-1 || !canonicalEpoch(p.DatasetEpoch) || p.RunFloorBlock > p.ReadAt.BlockNumber || p.Consistency != consistency {
		return ErrUnavailable
	}
	if p.EndedAt < pb.EndedAt_ENDED_AT_UNSPECIFIED || p.EndedAt > pb.EndedAt_ENDED_AT_INDEX_FLOOR {
		return ErrUnavailable
	}
	if p.HistoryFromBlock > p.ReadAt.BlockNumber {
		return ErrPruned
	}
	if p.NextStartAfter == nil && p.EndedAt == pb.EndedAt_ENDED_AT_UNSPECIFIED || p.NextStartAfter != nil && p.EndedAt != pb.EndedAt_ENDED_AT_UNSPECIFIED {
		return ErrUnavailable
	}
	if o.read == nil || o.read.ExpectDatasetEpoch == "" {
		if o.read != nil && o.read.ReadAt != nil && !proto.Equal(o.read.ReadAt, p.ReadAt) {
			return ErrConflict
		}
		o.read = &pb.ReadContext{ReadAt: proto.Clone(p.ReadAt).(*pb.ReadAt), ExpectDatasetEpoch: p.DatasetEpoch, ExpectedRunFloor: proto.Uint64(p.RunFloorBlock)}
	} else if !proto.Equal(o.read.ReadAt, p.ReadAt) || o.read.ExpectDatasetEpoch != p.DatasetEpoch || o.read.ExpectedRunFloor == nil || *o.read.ExpectedRunFloor != p.RunFloorBlock {
		return ErrConflict
	}
	return nil
}
func (o *operation) chain(ctx context.Context) (*pb.GetChainViewResponse, error) {
	req := &pb.GetChainViewRequest{Read: o.read}
	v, e := o.call(ctx, req, func(c context.Context) (proto.Message, error) { return o.owner.client.GetChainView(c, req) })
	if e != nil {
		return nil, rpcError(e)
	}
	r := v.(*pb.GetChainViewResponse)
	if r.ChainId != o.owner.metadata.Binding.Network.ChainID || hexBytes(r.GenesisHash) != o.owner.metadata.Binding.Network.GenesisHash {
		return nil, ErrConflict
	}
	if e = o.page(r.Page, pb.Consistency_CONSISTENCY_SNAPSHOT); e != nil {
		return nil, e
	}
	return r, nil
}
func (r *Reader) CheckReady(ctx context.Context) error {
	o, e := r.newOperation(ctx)
	if e != nil {
		return e
	}
	defer o.Close()
	_, e = o.chain(ctx)
	return e
}
