package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"io"
	"log/slog"
	"net/http"
	"os"
	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/loggate"
	"privacy-proxy/internal/nodepolicy"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
)

type nodeFactVersion interface {
	NodePolicyVersion(context.Context) (uint64, error)
}
type executionNodeClient interface {
	PolicyStatus(context.Context) (nodepolicy.NodeStatus, error)
	SubmitTransaction(context.Context, []byte, string) (nodepolicy.Submission, error)
	Simulate(context.Context, []byte, []byte) (json.RawMessage, error)
}
type nodeSubmissionStore interface {
	SaveNodeSubmission(context.Context, db.NodeSubmission) error
	MarkNodeSubmissionAccepted(context.Context, nodepolicy.Network, string) error
}
type nodeExecutionBridge struct {
	source   nodeFactVersion
	node     executionNodeClient
	signer   nodepolicy.Signer
	network  nodepolicy.Network
	lifetime time.Duration
	now      func() time.Time

	// cache holds the node's status, so preparing an identity reads only the
	// database fact version per request (RD-1410).
	cache       nodeStatusCache
	slotOnce    sync.Once
	refreshSlot chan struct{} // single flight for request-triggered refreshes
	lastRefresh atomic.Int64  // unix nanos (wall clock) when the last one started
	kick        chan struct{} // asks the probe for an immediate read
	log         loggate.Gate
}

// nodeStatusMaxAge bounds how old the last node status read may be before
// identities are refused; the background probe reads it every second.
const nodeStatusMaxAge = 5 * time.Second

// nodeStatusRefreshSpacing bounds request-triggered status reads while the
// cached status is missing, failing or behind the database version: one at
// a time, at most one start per spacing, shared by every request waiting.
const nodeStatusRefreshSpacing = 10 * time.Millisecond

// failureLogEvery is the interval of the rate-limited node failure lines.
const failureLogEvery = 10 * time.Second

// nodeStatusObservation is one read of the node's status, stamped with when
// the read started.
type nodeStatusObservation struct {
	seq    uint64
	at     time.Time
	status nodepolicy.NodeStatus
	err    error
}

type nodeStatusTicket struct {
	seq uint64
	at  time.Time
}

// nodeStatusCache keeps the newest-STARTED observation: a slow read that began
// before a fresher one finished can never roll the cache back.
type nodeStatusCache struct {
	seq     atomic.Uint64
	current atomic.Pointer[nodeStatusObservation]
}

func (c *nodeStatusCache) begin(at time.Time) nodeStatusTicket {
	return nodeStatusTicket{seq: c.seq.Add(1), at: at}
}

func (c *nodeStatusCache) finish(t nodeStatusTicket, status nodepolicy.NodeStatus, err error) {
	o := &nodeStatusObservation{seq: t.seq, at: t.at, status: status, err: err}
	for {
		current := c.current.Load()
		if current != nil && current.seq > o.seq {
			return
		}
		if c.current.CompareAndSwap(current, o) {
			return
		}
	}
}

func (c *nodeStatusCache) load() *nodeStatusObservation { return c.current.Load() }

func newNodeExecutionBridge(source nodeFactVersion, node executionNodeClient, signer nodepolicy.Signer, network nodepolicy.Network, lifetime time.Duration, now func() time.Time) (*nodeExecutionBridge, error) {
	if source == nil || node == nil || len(signer.PrivateKey) != ed25519.PrivateKeySize || signer.KeyID == "" || lifetime < time.Second || lifetime > nodepolicy.MaxMessageLifetime {
		return nil, nodepolicy.ErrIdentity
	}
	if now == nil {
		now = time.Now
	}
	return &nodeExecutionBridge{source: source, node: node, signer: signer, network: network, lifetime: lifetime, now: now, kick: make(chan struct{}, 1)}, nil
}

// observe reads the node's status once and records it in the cache. A read
// ended by its own context (shutdown, an end of term) says nothing about the
// node and is not recorded.
func (b *nodeExecutionBridge) observe(ctx context.Context) {
	ticket := b.cache.begin(b.now())
	status, err := b.node.PolicyStatus(ctx)
	if err != nil && ctx.Err() != nil {
		return
	}
	b.cache.finish(ticket, status, err)
}

// probeNodeStatus is one tick of the background probe.
func (b *nodeExecutionBridge) probeNodeStatus(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	b.observe(ctx)
}

// startStatusProbe reads the node's status every interval, and at once after
// each fact publication, until ctx ends. It returns a function that waits for
// the probe to stop.
func (b *nodeExecutionBridge) startStatusProbe(ctx context.Context, interval time.Duration) func() {
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			b.probeNodeStatus(ctx)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			case <-b.kick:
			}
		}
	}()
	return func() { <-done }
}

func (b *nodeExecutionBridge) kickProbe() {
	select {
	case b.kick <- struct{}{}:
	default:
	}
}

// refreshAfter returns a status read that STARTED after the cache sequence
// mark, reading the node only when none exists yet. A request whose check
// failed passes the mark it took before reading the database fact version,
// so it never refuses on a status read older than that version, and requests
// waiting together share one read. Reads run one at a time and start at most
// once per nodeStatusRefreshSpacing, so a lagging or failing node costs a
// bounded number of calls, never one per request.
func (b *nodeExecutionBridge) refreshAfter(ctx context.Context, mark uint64) *nodeStatusObservation {
	b.slotOnce.Do(func() { b.refreshSlot = make(chan struct{}, 1) })
	select {
	case b.refreshSlot <- struct{}{}:
		defer func() { <-b.refreshSlot }()
	case <-ctx.Done():
		return b.cache.load()
	}
	if o := b.cache.load(); o != nil && o.seq > mark {
		return o
	}
	if wait := nodeStatusRefreshSpacing - time.Since(time.Unix(0, b.lastRefresh.Load())); wait > 0 {
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return b.cache.load()
		case <-timer.C:
		}
	}
	b.lastRefresh.Store(time.Now().UnixNano())
	// The read is shared by every waiter, so the caller that happens to run it
	// must not end it by going away, and a hung read must not hold the slot.
	read, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	b.observe(read)
	return b.cache.load()
}

// check applies every readiness rule to an observation at the database fact
// version. A stale or missing observation refuses; it never skips a rule, and
// the identity still carries the database version as its minimum, which the
// node enforces.
func (b *nodeExecutionBridge) check(o *nodeStatusObservation, version uint64) error {
	if o == nil || b.now().Sub(o.at) > nodeStatusMaxAge {
		return nodepolicy.ErrNodeUnavailable
	}
	if o.err != nil {
		return o.err
	}
	status := o.status
	if version == 0 || status.Network != b.network || status.ProtocolVersion != nodepolicy.ProtocolVersion {
		return nodepolicy.ErrNodeResponse
	}
	if status.Version > version {
		return nodepolicy.ErrFeedConflict
	}
	return status.RequireReady(b.now(), version)
}

// observingFactNode is the node as the publisher sees it: its status reads
// feed the cache, and a successful fact publication triggers an immediate
// probe, so the cache follows a fact change at once on the publishing
// instance.
type observingFactNode struct {
	node   nodepolicy.FactNode
	bridge *nodeExecutionBridge
}

func (o observingFactNode) PolicyStatus(ctx context.Context) (nodepolicy.NodeStatus, error) {
	ticket := o.bridge.cache.begin(o.bridge.now())
	status, err := o.node.PolicyStatus(ctx)
	if err == nil || ctx.Err() == nil {
		o.bridge.cache.finish(ticket, status, err)
	}
	return status, err
}

func (o observingFactNode) ApplyPolicy(ctx context.Context, wire []byte) (nodepolicy.AppliedState, error) {
	applied, err := o.node.ApplyPolicy(ctx, wire)
	if err == nil {
		o.bridge.kickProbe()
	}
	return applied, err
}

func (b *nodeExecutionBridge) readiness(ctx context.Context) (uint64, error) {
	version, err := b.source.NodePolicyVersion(ctx)
	if err != nil {
		return 0, nodepolicy.ErrNodeUnavailable
	}
	// Taken after the version read: a status read with a higher sequence
	// started after the database answered.
	mark := b.cache.seq.Load()
	if err := b.check(b.cache.load(), version); err == nil {
		return version, nil
	}
	return version, b.check(b.refreshAfter(ctx, mark), version)
}

// executionStatus is the readiness report (/ready and /status): a live node
// status read, started after the call began, shared by concurrent callers
// and rate-bounded like the request-path refresh, so readiness probes cannot
// crowd fact publication off the control lane.
func (b *nodeExecutionBridge) executionStatus(ctx context.Context) (uint64, nodepolicy.NodeStatus, error) {
	version, err := b.source.NodePolicyVersion(ctx)
	if err != nil {
		return 0, nodepolicy.NodeStatus{}, nodepolicy.ErrNodeUnavailable
	}
	mark := b.cache.seq.Load()
	o := b.refreshAfter(ctx, mark)
	if o == nil {
		return version, nodepolicy.NodeStatus{}, nodepolicy.ErrNodeUnavailable
	}
	if o.err != nil {
		return version, nodepolicy.NodeStatus{}, o.err
	}
	return version, o.status, b.check(o, version)
}

// handleReady reports whether execution can use current authoritative facts.
// @Summary Execution readiness
// @Description Returns 503 until the configured execution node has fresh policy facts matching the database. No private policy or identity data is returned.
// @Tags Health
// @Produce json
// @Success 200 {object} apimodels.ReadinessResponse
// @Failure 503 {object} apimodels.ReadinessResponse
// @Router /ready [get]
// @Router /ready [head]
func (s *Server) handleReady(c *gin.Context) {
	status := s.executionStatus(c.Request.Context())
	code, text := http.StatusOK, "ready"
	if !status.Ready {
		code, text = http.StatusServiceUnavailable, "not_ready"
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(code, apimodels.ReadinessResponse{Status: text})
}

func (s *Server) executionStatus(ctx context.Context) apimodels.ExecutionStatus {
	result := apimodels.ExecutionStatus{Mode: "legacy", Ready: true}
	if s.config == nil || !s.config.NodePolicy.Enabled() {
		return result
	}
	result.Mode, result.Ready, result.Reason = "reth", false, "execution_unavailable"
	if s.nodeExecution == nil {
		return result
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	desired, node, err := s.nodeExecution.executionStatus(ctx)
	result.DesiredVersion, result.AppliedVersion, result.ExpiresAt = desired, node.Version, node.ExpiresAt
	if err == nil {
		result.Ready = true
		result.Reason = ""
	} else if desired > 0 && node.Version < desired {
		result.Reason = "publication_pending"
	} else if node.Version > desired && desired > 0 {
		result.Reason = "version_conflict"
	} else if node.ExpiresAt > 0 && node.ExpiresAt <= s.nodeExecution.now().Unix() {
		result.Reason = "facts_expired"
	}
	return result
}
func (b *nodeExecutionBridge) PrepareIdentity(ctx context.Context, request NodeExecutionIdentityRequest) ([]byte, error) {
	version, err := b.readiness(ctx)
	if err != nil {
		return nil, err
	}
	at := b.now()
	identity := nodepolicy.Identity{Header: nodepolicy.Header{Network: b.network, IssuedAt: at.Unix(), ExpiresAt: at.Add(b.lifetime).Unix()}, Scope: request.Scope, ContextID: uuid.NewString(), PrincipalID: request.PrincipalID, OrgID: request.OrgID, Signer: request.Signer, BindingHash: request.BindingHash, MinSnapshotVersion: version}
	wire, err := b.signer.Seal("identity", identity)
	if err != nil {
		return nil, err
	}
	// Validate internal caller input with the shared strict wire contract before
	// emitting an envelope. This does not make a permission decision.
	verifier := nodepolicy.Verifier{Network: b.network, Keys: map[string]ed25519.PublicKey{b.signer.KeyID: b.signer.PrivateKey.Public().(ed25519.PublicKey)}, Now: b.now}
	if _, err := verifier.OpenIdentity(wire); err != nil {
		return nil, err
	}
	return wire, nil
}
func (b *nodeExecutionBridge) SubmitTransaction(ctx context.Context, identity []byte, raw string, metadata NodeSubmissionMetadata) (nodepolicy.Submission, error) {
	store, ok := b.source.(nodeSubmissionStore)
	if !ok {
		return nodepolicy.Submission{}, nodepolicy.ErrNodeUnavailable
	}
	verifier := nodepolicy.Verifier{Network: b.network, Keys: map[string]ed25519.PublicKey{b.signer.KeyID: b.signer.PrivateKey.Public().(ed25519.PublicKey)}, Now: b.now}
	i, err := verifier.OpenIdentity(identity)
	if err != nil || i.Scope != "transaction" {
		return nodepolicy.Submission{}, nodepolicy.ErrIdentity
	}
	intent := db.NodeSubmission{Network: b.network, TransactionHash: i.BindingHash, PrincipalID: i.PrincipalID, OrgID: i.OrgID, Signer: i.Signer, ContextID: i.ContextID, RawTransaction: raw, IdentityEnvelope: identity, SenderDID: metadata.SenderDID, VisibleTo: metadata.VisibleTo}
	if err := store.SaveNodeSubmission(ctx, intent); err != nil {
		return nodepolicy.Submission{}, nodepolicy.ErrNodeUnavailable
	}
	submitted, err := b.node.SubmitTransaction(ctx, identity, raw)
	if err != nil {
		return nodepolicy.Submission{}, err
	}
	// The durable queued intent already guarantees recovery if this update
	// fails after the node accepted. Do not claim submission failed in that case.
	if err := store.MarkNodeSubmissionAccepted(ctx, b.network, i.BindingHash); err != nil {
		if suppressed, ok := b.log.Allow("ack:"+nodeErrorClass(err), time.Now(), failureLogEvery); ok {
			slog.Warn("node submission acknowledgement pending", "tx", i.BindingHash, "error", err, "suppressed", suppressed)
		}
	}
	return submitted, nil
}
func (b *nodeExecutionBridge) Simulate(ctx context.Context, identity, request []byte) (json.RawMessage, error) {
	return b.node.Simulate(ctx, identity, request)
}

func loadNodePolicySigner(c config.NodePolicyConfig) (nodepolicy.Signer, error) {
	file, err := os.Open(c.PrivateKeyFile)
	if err != nil {
		return nodepolicy.Signer{}, fmt.Errorf("node policy signing key file is unavailable")
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(raw) > 4096 {
		return nodepolicy.Signer{}, fmt.Errorf("node policy signing key file is invalid")
	}
	encoded := strings.TrimSpace(string(raw))
	key, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(key) != encoded {
		return nodepolicy.Signer{}, fmt.Errorf("node policy signing key must be canonical base64")
	}
	switch len(key) {
	case ed25519.SeedSize:
		key = ed25519.NewKeyFromSeed(key)
	case ed25519.PrivateKeySize:
		if !bytes.Equal(ed25519.NewKeyFromSeed(key[:ed25519.SeedSize]), key) {
			return nodepolicy.Signer{}, fmt.Errorf("node policy signing key public half does not match its seed")
		}
	default:
		return nodepolicy.Signer{}, fmt.Errorf("node policy signing key must contain a 32-byte seed or 64-byte private key")
	}
	return nodepolicy.Signer{KeyID: c.KeyID, PrivateKey: ed25519.PrivateKey(key)}, nil
}

// newNodePolicyClient is the private-node client with the configured
// connection lanes; the RD-1112 harness builds it the same way.
func newNodePolicyClient(c config.NodePolicyConfig, network nodepolicy.Network) (*nodepolicy.Client, error) {
	control, transaction, recovery := c.LaneSizes()
	return nodepolicy.NewPooledClient(c.URL, c.Token, network, nodepolicy.Lanes{Control: control, Transaction: transaction, Recovery: recovery})
}

// nodeErrorClass maps a node-path error to a fixed class for log keys; error
// text never becomes a key.
func nodeErrorClass(err error) string {
	switch {
	case errors.Is(err, nodepolicy.ErrNodeUnavailable):
		return "unavailable"
	case errors.Is(err, nodepolicy.ErrNodeRejected):
		return "rejected"
	case errors.Is(err, nodepolicy.ErrNodeResponse):
		return "response"
	case errors.Is(err, nodepolicy.ErrNodeResync):
		return "resync"
	case errors.Is(err, nodepolicy.ErrSnapshotLag):
		return "snapshot_lag"
	case errors.Is(err, nodepolicy.ErrFeedConflict):
		return "feed_conflict"
	case errors.Is(err, nodepolicy.ErrIdentity):
		return "identity"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	default:
		return "other"
	}
}

func (s *Server) initNodePolicy() error {
	c := s.config.NodePolicy
	if err := c.Validate(); err != nil {
		return err
	}
	if !c.Enabled() {
		return nil
	}
	signer, err := loadNodePolicySigner(c)
	if err != nil {
		return err
	}
	network := nodepolicy.Network{ChainID: c.ChainID, DeploymentID: c.DeploymentID}
	client, err := newNodePolicyClient(c, network)
	if err != nil {
		return err
	}
	bridge, err := newNodeExecutionBridge(s.db, client, signer, network, c.IdentityTTL, nil)
	if err != nil {
		return err
	}
	publisher, err := nodepolicy.NewPublisher(nodepolicy.PublisherConfig{Network: network, ConsumerID: c.ConsumerID, Signer: signer, Source: s.db, Node: observingFactNode{node: client, bridge: bridge}, Lifetime: c.FactTTL})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.nodeExecution = bridge
	s.nodePolicyCancel = cancel
	s.nodePolicyDone = make(chan struct{})
	// Every instance probes the node's status (it serves requests whether or
	// not it publishes); the probe stops with the node-policy context.
	waitProbe := bridge.startStatusProbe(ctx, time.Second)
	report := func(err error) {
		if ctx.Err() == nil {
			slog.Warn("node policy publication pending", "error", err)
		}
	}
	// Exactly one OPS instance publishes facts and reconciles submissions at a
	// time. Every instance campaigns for the database lease; the others stand
	// by and take over within a publish interval if the holder disappears.
	// The shared acknowledgement cursor therefore keeps describing the node,
	// and deltas stay deltas instead of collapsing into full snapshots from
	// several publishers at once.
	go func() {
		defer close(s.nodePolicyDone)
		defer waitProbe()
		_ = nodepolicy.RunElected(ctx, s.db.NodePolicyLease(), c.PublishInterval, func(term context.Context) {
			slog.Info("node policy publisher elected", "consumer_id", c.ConsumerID)
			defer slog.Info("node policy publisher term ended", "consumer_id", c.ConsumerID)
			reconcilerDone := make(chan struct{})
			go func() { defer close(reconcilerDone); runNodeReconciler(term, s.db, client, network) }()
			_ = publisher.Run(term, c.PublishInterval, report)
			<-reconcilerDone
		}, report)
	}()
	return nil
}
