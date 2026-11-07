package guardbridge

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/grpc"
	"privacy-proxy/internal/nodeapproval"
	"privacy-proxy/internal/nodeapproval/approvalpb"
	"privacy-proxy/internal/rpcexecution"
)

type sealedProducer struct {
	approvalpb.UnimplementedApprovalDeliveryServer
	received chan []byte
}

func (p *sealedProducer) Status(context.Context, *approvalpb.StatusRequest) (*approvalpb.StatusResponse, error) {
	return &approvalpb.StatusResponse{BootId: "pair-boot", ChainId: 1, TrustedKeyIds: []string{"pair-key"}, MaxTtlMs: uint64(time.Hour.Milliseconds()), Capacity: 10000, WaitMs: 5000}, nil
}
func (p *sealedProducer) Deliver(_ context.Context, r *approvalpb.DeliverRequest) (*approvalpb.DeliverResponse, error) {
	p.received <- bytes.Clone(r.Batch)
	return &approvalpb.DeliverResponse{BootId: "pair-boot", Stored: 1}, nil
}

func TestDeliveryPairQueuesOnlyItsOriginalSealedApproval(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	producer := &sealedProducer{received: make(chan []byte, 8)}
	grpcServer := grpc.NewServer()
	approvalpb.RegisterApprovalDeliveryServer(grpcServer, producer)
	go grpcServer.Serve(listener)
	defer grpcServer.Stop()
	tx := verified(t, []byte{1, 2})
	n := newNode(t, tx)
	server := httptest.NewServer(n)
	defer server.Close()
	b := rpcexecution.NodeBinding{OrganizationID: org, URL: server.URL, ChainID: "1", Profile: rpcexecution.GuardRetainedProfileID, PragueStartInclusive: 0, PragueEndExclusive: 20, Credentials: map[string]rpcexecution.Credential{"key": {Header: "X-Key", Value: "selected"}, "other": {Header: "X-Key", Value: "selected"}}}
	seed := bytes.Repeat([]byte{7}, 32)
	options := nodeapproval.BoundDeliveryOptions{Seed: seed, KeyID: "pair-key", MaxBatch: 32, Delivery: nodeapproval.DeliveryOptions{Targets: []string{listener.Addr().String()}, Timeout: time.Second, MaxInFlight: 1, RetainMax: 32}}
	p, err := NewDeliveryPair(b, "key", server.Client().Transport, nodeapproval.HashCalls, rpcexecution.DefaultLimits(), options)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	other, err := NewDeliveryPair(b, "other", server.Client().Transport, nodeapproval.HashCalls, rpcexecution.DefaultLimits(), options)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	deadline := time.Now().Add(3 * time.Second)
	for !p.Ready() && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if !p.Ready() {
		t.Fatal("producer not ready")
	}
	q, err := p.AcquireSigned(t.Context(), tx)
	if err != nil {
		t.Fatal(err)
	}
	if other.EnqueueQualified(q) == nil {
		t.Fatal("different Pair/service/credential accepted approval")
	}
	copyPrepared := *q.prepared
	copyQualified := *q
	copyQualified.prepared = &copyPrepared
	if p.EnqueueQualified(&copyQualified) == nil {
		t.Fatal("public copied Prepared accepted")
	}
	approval := q.prepared.Approval
	q.prepared.Approval.Fingerprint[0] ^= 0xff
	if p.EnqueueQualified(q) == nil {
		t.Fatal("substituted approval accepted")
	}
	q.prepared.Approval = approval
	if err := p.EnqueueQualified(q); err != nil {
		t.Fatal(err)
	}
	p.Close()
	if p.Ready() || p.EnqueueQualified(q) == nil {
		t.Fatal("closed pair accepted work")
	}
	select {
	case raw := <-producer.received:
		if len(raw) < 64 {
			t.Fatal("missing signature")
		}
		message, signature := raw[:len(raw)-64], raw[len(raw)-64:]
		public := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		if !ed25519.Verify(public, message, signature) {
			t.Fatal("producer received invalid original signer envelope")
		}
		prefix := []byte("OPS_APPROVAL_BATCH_V2\x00")
		if !bytes.HasPrefix(message, prefix) {
			t.Fatal("wire domain changed")
		}
		offset := len(prefix)
		keyLen := int(message[offset])
		offset += 1 + keyLen
		if len(message) < offset+20 {
			t.Fatal("short batch")
		}
		issued, expires := binary.BigEndian.Uint64(message[offset:]), binary.BigEndian.Uint64(message[offset+8:])
		count := binary.BigEndian.Uint32(message[offset+16:])
		offset += 20
		if count != 1 || expires-issued != uint64(nodeapproval.DefaultApprovalTTL.Milliseconds()) || !bytes.Equal(message[offset:], approval.Message()) {
			t.Fatal("queued approval/TTL differs from original sealed Prepared")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("original accepted approval not drained")
	}
}
