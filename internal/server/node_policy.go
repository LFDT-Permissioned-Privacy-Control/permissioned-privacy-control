package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
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
	"privacy-proxy/internal/proxy"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/gin-gonic/gin"
)

type nodeFactVersion interface {
	NodePolicyVersion(context.Context) (uint64, error)
}

// nodeFactClock is the single issuing clock (plan §4.8.3): the fact version
// and the database time in one read. A source without it signs at the host
// clock (unit fixtures).
type nodeFactClock interface {
	NodePolicyClock(context.Context) (uint64, time.Time, error)
}
type executionNodeClient interface {
	PolicyStatus(context.Context) (nodepolicy.NodeStatus, error)
	SubmitTransaction(context.Context, []byte, string) (nodepolicy.Submission, error)
	Simulate(context.Context, []byte, []byte) (json.RawMessage, error)
}
type nodeExecutionBridge struct {
	source   nodeFactVersion
	node     executionNodeClient
	signer   nodepolicy.Signer
	network  nodepolicy.Network
	lifetime time.Duration
	// txLifetime is the transaction-identity lease (0: lifetime).
	txLifetime time.Duration
	now        func() time.Time
	// tracking records each transaction's binding in the execution-tracking
	// database before transport (RD-1410).
	tracking *nodeTracking

	// cache holds the node's status, so preparing an identity reads only the
	// database fact version per request (RD-1410).
	cache       nodeStatusCache
	slotOnce    sync.Once
	refreshSlot chan struct{} // single flight for request-triggered refreshes
	lastRefresh atomic.Int64  // unix nanos (wall clock) when the last one started
	kick        chan struct{} // asks the probe for an immediate read
	log         loggate.Gate

	// behind is the current lag episode (RD-1411 §5.3): since when this
	// instance has seen the node below target, the database version it was
	// first seen behind. A new episode starts only once the node reached that
	// target.
	behindMu sync.Mutex
	behind   struct {
		target uint64
		since  time.Time
	}
	// factWaiters bounds the requests handed to the node's fact wait at once;
	// waiting holds a transaction-lane connection, so the rest are refused at
	// once. waiting maps an identity's context to when it took a slot.
	factWaiters chan struct{}
	waitingMu   sync.Mutex
	waiting     map[string]time.Time
}

// maxFactWaiters bounds requests waiting on the node for facts at once, a
// quarter of the default transaction lane (64), so waiting never starves the
// lane.
const maxFactWaiters = 16

// factWaiterLease releases a slot whose request never reached the node (for
// example a simulation refused by its audit write).
const factWaiterLease = 20 * time.Second

// nodeFactWaitBudget is how long after first seeing the node behind the
// database OPS still hands requests to a node that waits for facts itself
// (fact_wait_v1): the node's default OPS_NODE_POLICY_FACT_WAIT. Past it the
// node's wait would expire too, so OPS refuses at once, before any side
// effect, instead of holding a transaction connection per request.
const nodeFactWaitBudget = time.Second

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
	// changed is closed (and replaced) whenever a newer observation is
	// recorded, so requests can wait for the node's facts without polling.
	changedMu sync.Mutex
	changed   chan struct{}
}

// notify wakes everything waiting for a newer observation.
func (c *nodeStatusCache) notify() {
	c.changedMu.Lock()
	if c.changed != nil {
		close(c.changed)
		c.changed = nil
	}
	c.changedMu.Unlock()
}

// next returns a channel closed at the next recorded observation.
func (c *nodeStatusCache) next() <-chan struct{} {
	c.changedMu.Lock()
	defer c.changedMu.Unlock()
	if c.changed == nil {
		c.changed = make(chan struct{})
	}
	return c.changed
}

func (c *nodeStatusCache) begin(at time.Time) nodeStatusTicket {
	return nodeStatusTicket{seq: c.seq.Add(1), at: at}
}

func (c *nodeStatusCache) finish(t nodeStatusTicket, status nodepolicy.NodeStatus, err error) {
	c.store(&nodeStatusObservation{seq: t.seq, at: t.at, status: status, err: err})
}

func (c *nodeStatusCache) store(o *nodeStatusObservation) {
	for {
		current := c.current.Load()
		if current != nil && current.seq > o.seq {
			return
		}
		if c.current.CompareAndSwap(current, o) {
			c.notify()
			return
		}
	}
}

// applied records the node's acknowledgement of a fact publication (it
// holds version, digest and expiry now) on top of the newest ready
// observation, so requests on the publishing instance see the new facts
// without waiting for the next status read (F8). Anything other than a
// fresh, ready, error-free observation is left to the probe.
func (c *nodeStatusCache) applied(at time.Time, ack nodepolicy.AppliedState) {
	for {
		current := c.current.Load()
		if current == nil || current.err != nil || !current.status.Ready || ack.Version <= current.status.Version || at.Before(current.at) {
			return
		}
		status := current.status
		status.Version, status.Digest, status.ExpiresAt = ack.Version, ack.Digest, ack.ExpiresAt
		next := &nodeStatusObservation{seq: c.seq.Add(1), at: at, status: status}
		if c.current.CompareAndSwap(current, next) {
			c.notify()
			return
		}
		// A probe or another acknowledgement won after the load. Recheck
		// that observation rather than publishing a stale derived value
		// with a newly allocated sequence number.
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
	if status.Version < version && status.Ready && status.ExpiresAt > b.now().Unix() {
		// Ready on older facts: publication is pending. Every other rule
		// still applies at the node's own version.
		if err := status.RequireReady(b.now(), status.Version); err != nil {
			return err
		}
		if status.WaitsForFacts() && b.lagIsYoung(status.Version, version) {
			// The identity requires the database version; the node waits for
			// it (bounded) and refuses with -32012 if it does not arrive.
			return errFactWait
		}
		return nodepolicy.ErrFactsPending
	}
	return status.RequireReady(b.now(), version)
}

// errFactWait: the node is behind but waits for the facts itself; the request
// may go to it if a waiter slot is free (readiness turns it into nil).
var errFactWait = errors.New("node waits for the request's facts")

// lagIsYoung tracks the lag episode and reports whether it began less than
// nodeFactWaitBudget ago. An episode ends once the node reaches the version
// it was first seen behind, so a node still catching up does not get a new
// window per step, and a node restarted below it gets none.
func (b *nodeExecutionBridge) lagIsYoung(nodeVersion, version uint64) bool {
	now := b.now()
	b.behindMu.Lock()
	defer b.behindMu.Unlock()
	if b.behind.since.IsZero() || nodeVersion >= b.behind.target {
		b.behind.target, b.behind.since = version, now
	}
	return now.Sub(b.behind.since) < nodeFactWaitBudget
}

// acquireFactWait takes a waiter slot for an identity sent to the node's fact
// wait; false when every slot is taken.
func (b *nodeExecutionBridge) acquireFactWait(contextID string) bool {
	b.waitingMu.Lock()
	defer b.waitingMu.Unlock()
	if b.factWaiters == nil {
		b.factWaiters = make(chan struct{}, maxFactWaiters)
		b.waiting = map[string]time.Time{}
	}
	now := time.Now()
	for id, at := range b.waiting {
		if now.Sub(at) > factWaiterLease {
			delete(b.waiting, id)
			<-b.factWaiters
		}
	}
	select {
	case b.factWaiters <- struct{}{}:
		b.waiting[contextID] = now
		return true
	default:
		return false
	}
}

// awaitFacts waits until the cached node status holds at least version and
// is ready for it, at most until the current lag episode's fact-wait budget
// ends (nodeFactWaitBudget after the node was first seen behind) or ctx
// ends. It reports whether the node has the facts now.
func (b *nodeExecutionBridge) awaitFacts(ctx context.Context, version uint64, at time.Time) (uint64, time.Time, bool) {
	b.behindMu.Lock()
	remaining := b.behind.since.Add(nodeFactWaitBudget).Sub(b.now())
	b.behindMu.Unlock()
	timer := time.NewTimer(max(remaining, 0))
	defer timer.Stop()
	for {
		changed := b.cache.next()
		var err error
		version, at, err = b.checkClock(ctx, b.cache.load(), version, at)
		if err == nil {
			return version, at, true
		} else if !errors.Is(err, errFactWait) {
			return version, at, false // not a publication in flight any more
		}
		select {
		case <-changed:
		case <-timer.C:
			return version, at, false
		case <-ctx.Done():
			return version, at, false
		}
	}
}

// releaseFactWait frees the slot of an identity once its node call returned.
func (b *nodeExecutionBridge) releaseFactWait(contextID string) {
	b.waitingMu.Lock()
	defer b.waitingMu.Unlock()
	if _, ok := b.waiting[contextID]; ok {
		delete(b.waiting, contextID)
		<-b.factWaiters
	}
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
		o.bridge.cache.applied(o.bridge.now(), applied)
		o.bridge.kickProbe()
	}
	return applied, err
}

// currentBoot is the node's boot id from a fresh status read (Nil when the
// status is missing, stale or failing); ready also requires that the node is
// ready, so renewals go only to a node that can admit them.
func (b *nodeExecutionBridge) currentBoot() (uuid.UUID, bool) {
	boot, ready, _ := b.observedBoot()
	return boot, ready
}

// observedBoot is currentBoot with the sequence of the status read it came
// from, so a new boot id can be confirmed by a later, separate read.
func (b *nodeExecutionBridge) observedBoot() (uuid.UUID, bool, uint64) {
	o := b.cache.load()
	if o == nil || o.err != nil || b.now().Sub(o.at) > nodeStatusMaxAge {
		return uuid.Nil, false, 0
	}
	boot, err := uuid.Parse(o.status.BootID)
	if err != nil || !nodepolicy.ValidBootID(o.status.BootID) {
		return uuid.Nil, false, 0
	}
	return boot, o.status.Ready && o.status.ExpiresAt > b.now().Unix(), o.seq
}

// cachedBoot is currentBoot without the readiness requirement.
func (b *nodeExecutionBridge) cachedBoot() uuid.UUID {
	boot, _ := b.currentBoot()
	return boot
}

// clock reads the fact version and the issuing time (plan §4.8.3).
func (b *nodeExecutionBridge) clock(ctx context.Context) (uint64, time.Time, error) {
	if c, ok := b.source.(nodeFactClock); ok {
		return c.NodePolicyClock(ctx)
	}
	version, err := b.source.NodePolicyVersion(ctx)
	return version, b.now(), err
}

// checkClock rechecks the authoritative clock when a publication overtook
// the earlier DB read. A node still ahead of that fresh read remains a feed
// conflict; an ordinary concurrent commit must not refuse unaffected work.
func (b *nodeExecutionBridge) checkClock(ctx context.Context, o *nodeStatusObservation, version uint64, at time.Time) (uint64, time.Time, error) {
	err := b.check(o, version)
	if !errors.Is(err, nodepolicy.ErrFeedConflict) {
		return version, at, err
	}
	version, at, clockErr := b.clock(ctx)
	if clockErr != nil {
		return 0, time.Time{}, nodepolicy.ErrNodeUnavailable
	}
	return version, at, b.check(o, version)
}

// readiness returns the database fact version the request requires and the
// issuing time read with it. waits reports that the node is behind and will
// wait for that version itself.
func (b *nodeExecutionBridge) readiness(ctx context.Context) (version uint64, at time.Time, waits bool, err error) {
	version, at, err = b.clock(ctx)
	if err != nil {
		return 0, time.Time{}, false, nodepolicy.ErrNodeUnavailable
	}
	// Taken after the version read: a status read with a higher sequence
	// started after the database answered.
	mark := b.cache.seq.Load()
	version, at, err = b.checkClock(ctx, b.cache.load(), version, at)
	if err != nil && !errors.Is(err, errFactWait) {
		version, at, err = b.checkClock(ctx, b.refreshAfter(ctx, mark), version, at)
	}
	if errors.Is(err, errFactWait) {
		return version, at, true, nil
	}
	return version, at, false, err
}

// executionStatus is the readiness report (/ready and /status): a live node
// status read, started after the call began, shared by concurrent callers
// and rate-bounded like the request-path refresh, so readiness probes cannot
// crowd fact publication off the control lane.
func (b *nodeExecutionBridge) executionStatus(ctx context.Context) (uint64, nodepolicy.NodeStatus, error) {
	version, at, err := b.clock(ctx)
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
	version, _, err = b.checkClock(ctx, o, version, at)
	if err != nil && !errors.Is(err, errFactWait) {
		return version, o.status, err
	}
	return version, o.status, nil
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
		result.Reason = ReasonPublicationPending
	} else if node.Version > desired && desired > 0 {
		result.Reason = "version_conflict"
	} else if node.ExpiresAt > 0 && node.ExpiresAt <= s.nodeExecution.now().Unix() {
		result.Reason = "facts_expired"
	}
	return result
}
func (b *nodeExecutionBridge) PrepareIdentity(ctx context.Context, request NodeExecutionIdentityRequest) ([]byte, error) {
	// The fact version and the issue time come from one database read, so
	// identities from every OPS instance are ordered by one clock (§4.8.3).
	version, at, waits, err := b.readiness(ctx)
	if err != nil {
		return nil, err
	}
	contextID := uuid.NewString()
	if waits && !b.acquireFactWait(contextID) {
		// Every slot for the node's own fact wait is taken: wait here, holding
		// no node connection, for the publication in flight (bounded by the
		// lag episode's budget), instead of refusing a request whose facts
		// are about to arrive (P7 L5, F8).
		var ready bool
		version, at, ready = b.awaitFacts(ctx, version, at)
		if !ready {
			return nil, nodepolicy.ErrFactsPending
		}
		waits = false
	}
	lifetime := b.lifetime
	if request.Scope == "transaction" && b.txLifetime > 0 {
		lifetime = b.txLifetime
	}
	identity := nodepolicy.Identity{Header: nodepolicy.Header{Network: b.network, IssuedAt: at.Unix(), ExpiresAt: at.Add(lifetime).Unix()}, Scope: request.Scope, ContextID: contextID, PrincipalID: request.PrincipalID, OrgID: request.OrgID, Signer: request.Signer, BindingHash: request.BindingHash, MinSnapshotVersion: version}
	wire, err := b.signer.Seal("identity", identity)
	if err != nil {
		b.releaseFactWait(contextID)
		return nil, err
	}
	// Validate internal caller input with the shared strict wire contract before
	// emitting an envelope. This does not make a permission decision.
	verifier := nodepolicy.Verifier{Network: b.network, Keys: map[string]ed25519.PublicKey{b.signer.KeyID: b.signer.PrivateKey.Public().(ed25519.PublicKey)}, Now: b.now}
	if _, err := verifier.OpenIdentity(wire); err != nil {
		b.releaseFactWait(contextID)
		return nil, err
	}
	return wire, nil
}
func (b *nodeExecutionBridge) SubmitTransaction(ctx context.Context, identity []byte, raw string, metadata NodeSubmissionMetadata) (nodepolicy.Submission, error) {
	defer b.releaseFactWait(identityContextID(identity))
	if b.tracking == nil {
		return nodepolicy.Submission{}, nodepolicy.ErrNodeUnavailable
	}
	verifier := nodepolicy.Verifier{Network: b.network, Keys: map[string]ed25519.PublicKey{b.signer.KeyID: b.signer.PrivateKey.Public().(ed25519.PublicKey)}, Now: b.now}
	i, err := verifier.OpenIdentity(identity)
	if err != nil || i.Scope != "transaction" {
		return nodepolicy.Submission{}, nodepolicy.ErrIdentity
	}
	var admission db.TrackAdmission
	var result db.AdmitResult
	var inc uuid.UUID
	for attempt := 0; ; attempt++ {
		if admission, err = trackingAdmission(i, identity, raw, metadata); err != nil {
			return nodepolicy.Submission{}, nodepolicy.ErrIdentity
		}
		admission.ClaimBoot = b.cachedBoot()
		// The binding is durable before transport (I2, Q6 (a)): a node restart
		// cannot let another principal sharing the signer rebind this hash.
		result, inc, err = b.tracking.admit(ctx, admission)
		if err != nil {
			return nodepolicy.Submission{}, nodepolicy.ErrNodeUnavailable
		}
		needsResign := result.Outcome == db.AdmitIncomparable || (result.Outcome == db.AdmitKept && i.MinSnapshotVersion < result.MinVersion)
		if !needsResign {
			break
		}
		if attempt >= 2 {
			return nodepolicy.Submission{}, nodepolicy.ErrNodeUnavailable
		}
		// Re-read the current clock and sign again for incomparable envelopes
		// or a delayed attempt below the durable winner's fact floor. The
		// latter must never install stale authority in a restarted registry.
		again, err := b.PrepareIdentity(ctx, NodeExecutionIdentityRequest{Scope: "transaction", PrincipalID: i.PrincipalID, OrgID: i.OrgID, Signer: i.Signer, BindingHash: i.BindingHash})
		if err != nil {
			return nodepolicy.Submission{}, err
		}
		defer b.releaseFactWait(identityContextID(again))
		if i, err = verifier.OpenIdentity(again); err != nil {
			return nodepolicy.Submission{}, nodepolicy.ErrIdentity
		}
		identity = again
	}
	switch result.Outcome {
	case db.AdmitInvalid:
		return nodepolicy.Submission{}, nodepolicy.ErrIdentity
	case db.AdmitConflict:
		return nodepolicy.Submission{}, errBindingConflict
	case db.AdmitIncomparable:
		return nodepolicy.Submission{}, nodepolicy.ErrNodeUnavailable
	case db.AdmitOverLimit:
		return nodepolicy.Submission{}, errPendingLimit
	case db.AdmitPrincipalOverLimit:
		return nodepolicy.Submission{}, errPrincipalPendingLimit
	case db.AdmitOrgOverLimit:
		return nodepolicy.Submission{}, errOrgPendingLimit
	case db.AdmitFinal:
		// Already final for this principal: the transaction has executed;
		// answer as accepted without sending it again.
		return nodepolicy.Submission{TransactionHash: i.BindingHash, ContextID: i.ContextID, Status: "accepted"}, nil
	case db.AdmitInserted, db.AdmitResubmitted, db.AdmitRevived, db.AdmitKept:
		// Recorded (or covered by the recorded envelope): send it.
	default:
		// Fail closed: nothing that was not recorded is ever sent.
		return nodepolicy.Submission{}, nodepolicy.ErrNodeUnavailable
	}
	submitted, err := b.node.SubmitTransaction(ctx, identity, raw)
	if err != nil {
		var rejection *nodepolicy.PoolRejection
		switch {
		case errors.Is(err, nodepolicy.ErrFactsPending) && result.Outcome == db.AdmitInserted:
			// The node refused this request's only identity before admission
			// (-32012): the client retries the same raw transaction. Remove the
			// fresh, never-delivered binding so it carries no pending work.
			b.tracking.release(ctx, inc, admission.Hash, admission.ContextID)
			return nodepolicy.Submission{}, err
		case errors.As(err, &rejection):
			// A definitive pool answer for these bytes now (T18): stop
			// renewing, without finality (§4.8.1); it may still settle, and is
			// dropped only once a finalized nonce passes it.
			reason := db.TrackReasonNonceConflict
			if rejection.Reason == nodepolicy.PoolReplaced {
				reason = db.TrackReasonReplacedInPool
			}
			b.tracking.stop(ctx, inc, admission.Hash, result.Generation, reason)
			return nodepolicy.Submission{}, errPoolRejected
		case errors.Is(err, nodepolicy.ErrFactsPending):
			return nodepolicy.Submission{}, err
		default:
			// The intent is saved and still pending: the lease keeper delivers
			// it, so this request's outcome is unknown, not refused.
			return nodepolicy.Submission{}, fmt.Errorf("%w: %w", errSubmissionPending, err)
		}
	}
	// Acknowledged in memory only, against the answering boot (G35);
	// recorded with the next transition or the batched flush (R12.6).
	// Nothing more is written on the request path (G14). A kept (dominated)
	// attempt acknowledges nothing: the stored generation is not the one sent.
	answered, _ := uuid.Parse(submitted.BootID)
	if result.Written() && result.ContextID == admission.ContextID {
		b.tracking.ack(admission.Hash, result.Generation, inc, answered)
	}
	if answered != uuid.Nil && answered != b.cachedBoot() {
		b.kickProbe() // the node restarted: refresh the status and the keeper's boot
	}
	return submitted, nil
}

// BindingConflicts is the pre-compliance probe of the binding
// (bindingProber): the hash is bound to another principal, organisation or
// signer, or can no longer execute. An unreadable binding is an error (the
// request is refused as unavailable, not passed to compliance).
func (b *nodeExecutionBridge) BindingConflicts(ctx context.Context, hash []byte, principalID, orgID, signer string) (bool, error) {
	if b.tracking == nil || len(hash) != 32 {
		return false, errTrackingUnavailable
	}
	row, err := b.tracking.store.LookupTracked(ctx, hash)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, errTrackingUnavailable
	}
	if row.PrincipalID.String() != principalID || row.OrgID.String() != orgID {
		return true, nil
	}
	if row.Final() {
		return row.State == db.TrackDropped, nil // can never execute again
	}
	return !strings.EqualFold("0x"+hex.EncodeToString(row.Signer), signer), nil
}

// errBindingConflict: the signed transaction is bound to an earlier
// submission it does not match; refused before transport (G13).
var errBindingConflict = errors.New("transaction conflicts with an earlier submission")

// errPoolRejected: the node's pool refused the transaction's nonce (T18).
var errPoolRejected = errors.New("transaction pool rejected the transaction")

// errSubmissionPending: the intent was saved but its delivery failed; the
// lease keeper delivers it, so the transaction may still execute.
var errSubmissionPending = errors.New("transaction delivery pending")

// Network is the execution network this bridge signs for.
func (b *nodeExecutionBridge) Network() nodepolicy.Network { return b.network }

// errPendingLimit: the global pending-work limit is reached (plan §4.8.2).
var errPendingLimit = errors.New("pending execution work limit reached")

// errPrincipalPendingLimit: the submitting principal's own pending-work limit
// is reached (plan §4.8.2, B4).
var errPrincipalPendingLimit = errors.New("principal pending execution work limit reached")

// errOrgPendingLimit: the organization's pending-work limit is reached (all
// of its principals together, plan §4.8.2, B4).
var errOrgPendingLimit = errors.New("organization pending execution work limit reached")

// trackingAdmission is the tracking-database row of a signed transaction
// identity. The envelope is stored by hash only.
func trackingAdmission(i nodepolicy.Identity, identity []byte, raw string, metadata NodeSubmissionMetadata) (db.TrackAdmission, error) {
	var a db.TrackAdmission
	hash, err := hex.DecodeString(strings.TrimPrefix(i.BindingHash, "0x"))
	if err != nil || len(hash) != 32 {
		return a, nodepolicy.ErrIdentity
	}
	signer, err := hex.DecodeString(strings.TrimPrefix(i.Signer, "0x"))
	if err != nil || len(signer) != 20 {
		return a, nodepolicy.ErrIdentity
	}
	rawBytes, err := hex.DecodeString(strings.TrimPrefix(raw, "0x"))
	if err != nil {
		return a, nodepolicy.ErrIdentity
	}
	var transaction types.Transaction
	if err := transaction.UnmarshalBinary(rawBytes); err != nil || transaction.Nonce() > 1<<63-1 || i.MinSnapshotVersion > 1<<63-1 {
		return a, nodepolicy.ErrIdentity
	}
	principal, err := uuid.Parse(i.PrincipalID)
	if err != nil {
		return a, nodepolicy.ErrIdentity
	}
	org, err := uuid.Parse(i.OrgID)
	if err != nil {
		return a, nodepolicy.ErrIdentity
	}
	contextID, err := uuid.Parse(i.ContextID)
	if err != nil {
		return a, nodepolicy.ErrIdentity
	}
	envelope := sha256.Sum256(identity)
	a = db.TrackAdmission{Hash: hash, PrincipalID: principal, OrgID: org, Signer: signer, Nonce: transaction.Nonce(), ContextID: contextID, EnvelopeHash: envelope[:], ExpiresAt: time.Unix(i.ExpiresAt, 0), MinVersion: i.MinSnapshotVersion, Raw: rawBytes}
	if len(metadata.VisibleTo) > 0 {
		a.VisibleTo, a.VisibleSender = metadata.VisibleTo, metadata.SenderDID
	}
	return a, nil
}
func (b *nodeExecutionBridge) Simulate(ctx context.Context, identity, request []byte) (json.RawMessage, error) {
	defer b.releaseFactWait(identityContextID(identity))
	return b.node.Simulate(ctx, identity, request)
}

// identityContextID reads the context id of an identity envelope this
// instance signed ("" if it cannot); it only keys the fact-wait slot.
func identityContextID(wire []byte) string {
	var envelope nodepolicy.Envelope
	var i struct {
		ContextID string `json:"context_id"`
	}
	if json.Unmarshal(wire, &envelope) != nil || json.Unmarshal(envelope.Payload, &i) != nil {
		return ""
	}
	return i.ContextID
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
	client, err := nodepolicy.NewPooledClient(c.URL, c.Token, network, nodepolicy.Lanes{Control: control, Transaction: transaction, Recovery: recovery})
	if err == nil && c.ControlURL != "" {
		err = client.WithControlEndpoint(c.ControlURL)
	}
	return client, err
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
	case errors.Is(err, nodepolicy.ErrFactsPending):
		return "facts_pending"
	case errors.Is(err, errPendingLimit):
		return "pending_limit"
	case errors.Is(err, errPrincipalPendingLimit):
		return "principal_pending_limit"
	case errors.Is(err, errOrgPendingLimit):
		return "org_pending_limit"
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

// runNodePolicyNotifications connects the database's fact-stream
// notifications to this instance (RD-1411 §5.2, §5.4) until ctx ends: a fact
// change wakes the publisher (only the elected term reads wake), an
// acknowledgement refreshes the node status cache through kick, and a
// resubscription does both, since notifications may have been missed. Losing
// the subscription is logged at most once per failureLogEvery.
func runNodePolicyNotifications(ctx context.Context, listen func(context.Context, db.NodePolicyListener) error, wake chan<- struct{}, kick func()) {
	signal := func() {
		select {
		case wake <- struct{}{}:
		default:
		}
	}
	var lost loggate.Gate
	_ = listen(ctx, db.NodePolicyListener{
		Changed: func(uint64) { signal() },
		Applied: func(uint64) { kick() },
		Connected: func() {
			signal()
			kick()
		},
		Lost: func(err error) {
			if suppressed, ok := lost.Allow("listen", time.Now(), failureLogEvery); ok {
				slog.Warn("node policy notifications interrupted; publishing on the timer until resubscribed", "error", err, "suppressed", suppressed)
			}
		},
	})
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
	// Every system decision is audited in the durable buffer before it
	// commits (plan §4.8.6); without the buffer none could be taken.
	if s.auditBuffer == nil {
		return fmt.Errorf("OPS_NODE_POLICY_MODE=reth requires AUDIT_BUFFER_DIR: system decisions (such as recording a finalized transaction) are audited in the durable buffer before they commit")
	}
	if s.tracking, err = openExecutionTracking(s.config, s.db, network); err != nil {
		return err
	}
	txTTL, maxAge := c.TransactionLease()
	renewal, err := c.RenewalPlan()
	if err != nil {
		return err
	}
	slog.Info("node policy lease keeper", "transaction_identity_ttl", renewal.TTL, "renewal_window_opens", renewal.WindowOpens, "renewal_margin", renewal.Margin, "max_age", renewal.MaxAge,
		"renewal_budget_per_s", renewal.Budget, "renewable_limit", renewal.RenewLimit, "reorg_headroom", renewal.ReorgHeadroom, "pending_limit", renewal.AdmitLimit, "principal_pending_limit", renewal.PrincipalLimit, "org_pending_limit", renewal.OrgLimit)
	s.tracking.payloadKeep = nodeTxPayloadKeepFor(maxAge)
	client, err := newNodePolicyClient(c, network)
	if err != nil {
		return err
	}
	bridge, err := newNodeExecutionBridge(s.db, client, signer, network, c.IdentityTTL, nil)
	if err != nil {
		return err
	}
	bridge.txLifetime = txTTL
	schemaCtx, cancelSchema := context.WithTimeout(context.Background(), time.Minute)
	err = s.db.CheckNodePolicySchema(schemaCtx)
	if err == nil {
		// The replay floor exists before any effect may apply (absent = refuse).
		err = s.db.EnsureNodeTxEffectsFloor(schemaCtx, network)
	}
	if err == nil {
		// Partitions exist before the first finalization (K25); a maintenance
		// step that timed out is retried by the retention pass.
		err = ensureTrackingPartitions(schemaCtx, s.tracking.admin, s.tracking.keep())
	}
	cancelSchema()
	if err != nil {
		return fmt.Errorf("node policy: %w", err)
	}
	tracking := newNodeTracking(s.tracking.runtime, s.tracking.meta.Incarnation, s.tracking.adopt(network))
	tracking.limits = db.TrackLimits{Global: renewal.AdmitLimit, Principal: renewal.PrincipalLimit, Org: renewal.OrgLimit}
	bridge.tracking = tracking
	if s.retentionCleaner != nil {
		s.retentionCleaner.AttachTracking(trackingRetention{admin: s.tracking.admin, main: s.db, network: network, keep: s.tracking.keep()}, s.config.RetentionNodeSubmissions)
	}
	// Public chain evidence for the lease keeper (eviction, dropped): the
	// node's public RPC, read with the deployment's upstream credential.
	var chain nodeChainReader
	if s.proxy != nil {
		header := s.config.RPCAPIKeyHeader
		if header == "" {
			header = proxy.DefaultAPIKeyHeader
		}
		apiKey := s.config.RPCAPIKey
		chain = rpcChain{forward: func(ctx context.Context, body []byte) ([]byte, int, error) {
			return s.proxy.ForwardWithAPIKeyHeaderContext(ctx, body, header, apiKey, "")
		}}
	}
	rechecker := &admissionRechecker{ac: s.rbacAccessCtrl, compliance: s.complianceChecker, network: network, strictVisibleTo: s.config.ReadProfile.Strict()}
	wake := make(chan struct{}, 1)
	publisher, err := nodepolicy.NewPublisher(nodepolicy.PublisherConfig{Network: network, ConsumerID: c.ConsumerID, Signer: signer, Source: s.db, Node: observingFactNode{node: client, bridge: bridge}, Lifetime: c.FactTTL, Wake: wake})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.nodeExecution = bridge
	s.nodeOwnershipEvidence = client
	s.nodePolicyCancel = cancel
	s.nodePolicyDone = make(chan struct{})
	// Every instance probes the node's status (it serves requests whether or
	// not it publishes); the probe stops with the node-policy context.
	waitProbe := bridge.startStatusProbe(ctx, time.Second)
	waitTracking := tracking.run(ctx)
	// Fact changes wake the publisher and acknowledgements refresh every
	// instance's node status at once; both timers stay as fallback.
	notifyDone := make(chan struct{})
	go func() {
		defer close(notifyDone)
		runNodePolicyNotifications(ctx, s.db.ListenNodePolicy, wake, bridge.kickProbe)
	}()
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
		defer waitTracking()
		defer func() { <-notifyDone }()
		_ = nodepolicy.RunElected(ctx, s.db.NodePolicyLease(), c.PublishInterval, func(term context.Context) {
			slog.Info("node policy publisher elected", "consumer_id", c.ConsumerID)
			defer slog.Info("node policy publisher term ended", "consumer_id", c.ConsumerID)
			reconcilerDone := make(chan struct{})
			reconciler := newNodeReconciler(tracking, s.db, client, s.auditBuffer, network)
			reconciler.batched = func() bool {
				o := bridge.cache.load()
				return o != nil && o.err == nil && o.status.HasCapability(nodepolicy.CapabilityTransactionStatuses)
			}
			reconciler.notFound = func() bool {
				o := bridge.cache.load()
				return o != nil && o.err == nil && o.status.HasCapability(nodepolicy.CapabilityTransactionNotFound)
			}
			if s.metrics != nil {
				alerts := s.metrics.NodeTrackingAlertsTotal
				reconciler.alert = func(kind string) { alerts.WithLabelValues(kind).Inc() }
			}
			reconciler.keeper = &nodeKeeper{node: client, chain: chain, checker: rechecker, clock: s.db, signer: signer, network: network, ttl: txTTL, maxAge: maxAge, budget: renewal.Budget, boot: bridge.observedBoot, now: time.Now}
			go func() { defer close(reconcilerDone); runNodeReconciler(term, reconciler) }()
			_ = publisher.Run(term, c.PublishInterval, report)
			<-reconcilerDone
		}, report)
	}()
	return nil
}
