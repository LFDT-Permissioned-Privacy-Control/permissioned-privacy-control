package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	gethcommon "github.com/ethereum/go-ethereum/common"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"

	"privacy-proxy/internal/metrics"
	"privacy-proxy/internal/nodeapproval"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/tracer"
)

// The legacy execution path for eth_sendRawTransaction: runtime trace
// authorization and V1 signed approvals. Reth mode (OPS_NODE_POLICY_MODE=reth)
// never reaches it: Process hands every execution method to the node path
// first (see docs/architecture/security-perimeter.md).

// processRawTransaction handles eth_sendRawTransaction with RLP decoding.
// This method is ONLY allowed when runtime tracing is enabled, because we need
// to trace all call targets to validate cross-org isolation.
func (p *JSONRPCProcessor) processRawTransaction(ctx context.Context, req *ProcessRequest) *ProcessResult {
	start := time.Now()

	// eth_sendRawTransaction requires runtime tracing for security
	if p.runtimeTracer == nil || !p.runtimeTracer.IsEnabled() {
		p.recordRPCOutcome(req.Method, "tracing_required", start)
		p.logAccess(ctx, req, http.StatusForbidden)
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusForbidden,
				Message:    "eth_sendRawTransaction requires runtime tracing to be enabled for security validation",
			},
		}
	}

	// Extract and decode the raw transaction
	rawTxHex, err := extractRawTxHex(req.Params)
	if err != nil {
		// Opaque client message; raw extract/RLP error stays in slog. (RD-1178 / RD-934)
		slog.Warn("invalid raw transaction", slog.String("user", req.UserID), slog.Any("err", err))
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusBadRequest,
				Message:    "invalid raw transaction",
			},
		}
	}

	// Decode RLP to get transaction details
	from, to, data, value, txNonce, err := decodeRawTransaction(rawTxHex)
	if err != nil {
		slog.Warn("failed to decode raw transaction", slog.String("user", req.UserID), slog.Any("err", err))
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusBadRequest,
				Message:    "failed to decode raw transaction",
			},
		}
	}

	// Determine the operation type and required claims.
	// Only deployments need a claim gate; write access is controlled by the
	// method allowlist (eth_sendTransaction must be in allowed_methods).
	var requiredClaims []rbac.Claim
	isDeployment := to == ""
	if isDeployment {
		requiredClaims = []rbac.Claim{rbac.ClaimDeploy}
	}

	// Build RBAC access check request
	// For raw transactions, we use eth_sendTransaction for classification
	// since the operation is equivalent
	accessReq := &rbac.AccessCheckRequest{
		UserExternalID:   req.UserID,
		OrgID:            req.OrgID,
		Method:           "eth_sendTransaction", // Use sendTransaction for RBAC classification
		Params:           buildTxParams(from, to, data, value),
		TargetAddress:    to,
		FunctionSelector: extractSelector(data),
		RequiredClaims:   requiredClaims,
	}

	// Check RBAC access
	evaluation, err := evaluateAccessRequest(ctx, p.rbacAccessCtrl, accessReq)
	if err != nil {
		slog.Error("RBAC access check failed", "method", req.Method, "error", err)
		p.recordRPCOutcome(req.Method, "error", start)
		p.logAccess(ctx, req, http.StatusInternalServerError, http.StatusNotFound)
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusNotFound,
				Message:    "method not found",
			},
		}
	}
	result := evaluation.AccessResult

	// RD-1135: stamp the resolved org onto subsequent access-log rows (RBAC
	// denial, concurrency/rate-limit, trace denials, success). Write-once.
	// CheckAccess attributes both allows and in-check denies to the resolved
	// org (RD-1199); empty stays NULL (anonymous, org-free metadata, and
	// pre-org denials: unknown user, ban, KYC, global blocklist) →
	// super-admin-only rows.
	req.resolvedOrgID = result.OrgID

	if !result.Allowed {
		realStatus := http.StatusForbidden
		req.denialReason = ReasonMethodNotAllowed
		if result.AuthRequired {
			realStatus = http.StatusUnauthorized
			req.denialReason = ReasonAuthRequired
		}
		slog.Info("RBAC access denied", "method", req.Method, "user", req.UserID, "ip", req.ClientIP, "auth_required", result.AuthRequired)
		slog.Debug("RBAC denial details", "method", req.Method, "user", req.UserID, "reason", result.Reason)
		p.recordRPCOutcome(req.Method, "rbac_denied", start)
		p.recordRBACDecision("denied")
		p.logAccess(ctx, req, realStatus, http.StatusNotFound)
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusNotFound,
				Message:    "method not found",
			},
		}
	}
	p.recordRBACDecision("allowed")

	// RD-1299: a strict refusal of visibleTo precedes tracing and compliance.
	if res := p.strictProfileRejectsVisibleTo(ctx, req, true); res != nil {
		return res
	}

	// Concurrency gate moves ABOVE the trace path (RD-915 F5). Mirrors
	// the Process() path. Acquire before any trace so the cap covers
	// the trace itself, not just downstream forwarding.
	if p.concurrencyLimiter != nil && !p.concurrencyLimiter.TryAcquire(req.UserID) {
		if p.metrics != nil {
			p.metrics.ConcurrencyRejectionsTotal.Inc()
		}
		p.recordRPCOutcome(req.Method, "concurrent_limit", start)
		req.denialReason = ReasonConcurrencyLimited // RD-1137
		p.logAccess(ctx, req, http.StatusTooManyRequests)
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusTooManyRequests,
				Message:    "too many concurrent requests",
			},
		}
	}
	if p.concurrencyLimiter != nil {
		defer p.concurrencyLimiter.Release(req.UserID)
	}

	// Runtime tracing validation. For non-deploy raw transactions
	// (to != "") and for deploys (to == ""). Pre-M10 deploys skipped
	// tracing entirely, leaving constructor frames unvalidated; M10
	// closes that by routing deploys through validateDeployWithTracing.
	// The bytecode analyzer keeps running as a thinner fallback for
	// operators without debug_* on the upstream node, but the
	// authoritative gate is the trace.
	var prepared *nodeapproval.Prepared
	if p.nodeApprovals != nil {
		// No producer can take an approval: refuse before the node spends a preflight on it.
		if !p.nodeApprovals.Accepting() {
			return p.refuseApprovalDelivery(ctx, req, start)
		}
		if limited := p.limitPreflight(ctx, req, start); limited != nil {
			return limited
		}
		prepared, err = p.nodeApprovals.Prepare(ctx, rawTxHex)
		if err != nil {
			slog.Warn("signed preflight failed", "error", err)
			p.recordRPCOutcome(req.Method, "preflight_unavailable", start)
			req.denialReason = ReasonTracingUnavailable
			p.logAccess(ctx, req, http.StatusForbidden)
			return &ProcessResult{Error: &ProcessError{StatusCode: http.StatusForbidden, Message: "signed preflight unavailable or unsupported transaction", Reason: ReasonTracingUnavailable}}
		}
	}
	var runtimeCreateTargets []rbac.CreateTarget
	if prepared != nil {
		// Root EOA transfers keep the existing RBAC/compliance policy. The pinned
		// trace proves no contract or nested call is being skipped.
		if !prepared.PlainValueTransfer {
			targets, traceErr := p.validateRawTxWithPreparedTrace(ctx, req, from, to, data, value, prepared)
			if traceErr != nil {
				p.recordRPCOutcome(req.Method, "send_trace_denied", start)
				req.denialReason = traceErr.Reason
				p.logAccess(ctx, req, traceErr.StatusCode)
				return &ProcessResult{Error: traceErr}
			}
			runtimeCreateTargets = targets
		}
	} else if to != "" {
		skipTrace := false
		if isSimpleValueTransfer(data) {
			// Only skip tracing for simple value transfers to EOAs.
			// Contracts can execute receive()/fallback() which may make cross-org calls.
			hasCode, err := p.runtimeTracer.HasCode(ctx, to)
			if err == nil && !hasCode {
				skipTrace = true // EOA - safe to skip tracing
			}
			// If err or hasCode: fall through to tracing
		}
		if !skipTrace {
			rawRuntimeCreateTargets, traceErr := p.validateRawTxWithTracing(ctx, req, from, to, data, value)
			if traceErr != nil {
				p.recordRPCOutcome(req.Method, "send_trace_denied", start)
				req.denialReason = traceErr.Reason // RD-1137
				p.logAccess(ctx, req, traceErr.StatusCode)
				return &ProcessResult{
					Error: traceErr,
				}
			}
			runtimeCreateTargets = rawRuntimeCreateTargets
		}
	} else if p.runtimeTracer != nil && p.runtimeTracer.IsEnabled() {
		// M10: raw-tx contract deployment. Trace + validate.
		user, err := p.rbacAccessCtrl.Store().GetUserByExternalID(ctx, req.UserID)
		if err != nil || user == nil {
			p.recordRPCOutcome(req.Method, "send_trace_denied", start)
			req.denialReason = ReasonTracingUnavailable // RD-1137
			p.logAccess(ctx, req, http.StatusForbidden)
			return &ProcessResult{
				Error: &ProcessError{StatusCode: http.StatusForbidden, Message: sendTraceDenyTracerError, Reason: ReasonTracingUnavailable},
			}
		}
		memberships, err := p.rbacAccessCtrl.Store().ListActiveUserMembershipsWithDetails(ctx, user.ID)
		if err != nil {
			p.recordRPCOutcome(req.Method, "send_trace_denied", start)
			req.denialReason = ReasonTracingUnavailable // RD-1137
			p.logAccess(ctx, req, http.StatusForbidden)
			return &ProcessResult{
				Error: &ProcessError{StatusCode: http.StatusForbidden, Message: sendTraceDenyTracerError, Reason: ReasonTracingUnavailable},
			}
		}
		userOrgIDs := make(map[string]bool)
		for _, m := range memberships {
			if m.Group != nil {
				userOrgIDs[m.Group.OrgID] = true
			}
		}
		userHasDeploy := p.userHasDeployClaim(ctx, memberships)
		deployTargets, traceErr := p.validateDeployWithTracing(ctx, req, user.ID, from, data, value, userOrgIDs, userHasDeploy)
		if traceErr != nil {
			p.recordRPCOutcome(req.Method, "send_trace_denied", start)
			req.denialReason = traceErr.Reason // RD-1137
			p.logAccess(ctx, req, traceErr.StatusCode)
			return &ProcessResult{
				Error: traceErr,
			}
		}
		runtimeCreateTargets = deployTargets
	}

	// Travel rule compliance check (after RBAC + tracing, before rate limiting)
	if compErr := p.checkCompliance(ctx, req, result.OrgID, result.UserID, from, to, data, value); compErr != nil {
		return compErr
	}

	// Extract and strip visibleTo before forwarding. RD-1163: accept a top-level
	// `visibleTo`/`privateFor` (DIDs and/or ETH addresses, resolved fail-closed)
	// alongside the params[1] form; union them. Top-level is read first (the param
	// extractor rebuilds the body and would otherwise drop it). Only accepted on
	// contract calls — plain transfers have no event logs.
	topRaw := extractAndStripTopLevelVisibleTo(req)
	paramDIDs := extractAndStripRawTxVisibleTo(req)
	var vtResolver ethAddressResolver
	if r, ok := p.rbacAccessCtrl.Store().(ethAddressResolver); ok {
		vtResolver = r
	}
	resolvedTop, capErr := resolveTopLevelVisibleTo(ctx, vtResolver, topRaw)
	if capErr != nil {
		return &ProcessResult{Error: capErr}
	}
	rawTxVisibleTo := unionVisibleToDIDs(paramDIDs, resolvedTop)
	if len(rawTxVisibleTo) > visibleToMaxSize {
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusBadRequest,
				Message:    fmt.Sprintf("visibleTo list exceeds maximum size of %d entries", visibleToMaxSize),
			},
		}
	}
	if len(rawTxVisibleTo) > 0 {
		if isSimpleValueTransfer(data) || to == "" {
			return &ProcessResult{
				Error: &ProcessError{
					StatusCode: http.StatusBadRequest,
					Message:    "visibleTo is only supported for contract calls that emit event logs",
				},
			}
		}
	}

	// Concurrency limit acquired earlier (above the trace path) — see
	// the block following recordRBACDecision("allowed") in this function.

	// Resolve API key (group-specific or default)
	apiKey := result.RPCAPIKey
	if apiKey == "" {
		apiKey = p.defaultRPCAPIKey
	}
	apiKeyHeader := p.resolveAPIKeyHeader()

	// Check circuit breaker
	if p.circuitBreaker != nil && p.circuitBreaker.IsOpen(apiKey) {
		if p.metrics != nil {
			p.metrics.CircuitBreakerTripsTotal.WithLabelValues(maskAPIKey(apiKey)).Inc()
		}
		p.recordRPCOutcome(req.Method, "circuit_open", start)
		req.denialReason = ReasonRateLimited // RD-1137 (upstream rate limited)
		p.logAccess(ctx, req, http.StatusTooManyRequests)
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusTooManyRequests,
				Message:    "upstream rate limited, retry in 1s",
			},
		}
	}

	// Pre-register plain CREATE for raw transactions (nonce is embedded in the signed tx).
	var rawTxPlainCreateAddr string
	if isDeployment && (prepared == nil || prepared.SurvivingCreations[strings.ToLower(gethcrypto.CreateAddress(gethcommon.HexToAddress(from), txNonce).Hex())]) {
		fromAddr := gethcommon.HexToAddress(from)
		contractAddr := gethcrypto.CreateAddress(fromAddr, txNonce)
		addrStr := strings.ToLower(contractAddr.Hex())
		note := fmt.Sprintf("plain CREATE pending (raw tx): deployer=%s org=%s", result.UserID, result.OrgID)
		if preErr := p.rbacAccessCtrl.Store().PreRegisterPlainCreate(ctx, result.OrgID, addrStr, note); preErr != nil {
			slog.Warn("plain CREATE pre-registration failed for raw tx", "error", preErr)
		} else {
			rawTxPlainCreateAddr = addrStr
		}
	}

	// Pre-register runtime CREATE/CREATE2 addresses discovered during trace validation.
	var runtimeCreateAddrs []string
	if len(runtimeCreateTargets) > 0 {
		runtimeCreateAddrs = p.preRegisterRuntimeCreates(ctx, result.OrgID, runtimeCreateTargets)
	}

	// Queue only after every OPS gate has passed. Delivery has process lifetime,
	// runs independently of forwarding, and does not wait for a Reth ACK.
	if prepared != nil {
		if err := p.nodeApprovals.Enqueue(prepared); err != nil {
			// No transaction was forwarded. Release the registrations made above.
			for _, addr := range append(runtimeCreateAddrs, rawTxPlainCreateAddr) {
				if addr != "" {
					if cleanupErr := p.rbacAccessCtrl.Store().DeletePreregisteredAddressByAddress(context.Background(), addr); cleanupErr != nil {
						slog.Warn("failed to clean up creation after approval queue failure", "address", addr, "error", cleanupErr)
					}
				}
			}
			return p.refuseApprovalDelivery(ctx, req, start)
		}
	}
	if prepared != nil {
		p.nodeApprovals.TraceForward(prepared)
	}
	// Forward the original raw transaction to node
	forwardStart := time.Now()
	responseBody, statusCode, err := p.proxy.ForwardWithAPIKeyHeader(req.Body, apiKeyHeader, apiKey, req.ClientIP)
	if p.metrics != nil {
		p.metrics.RPCNodeForwardDuration.WithLabelValues(metrics.NormalizeRPCMethod(req.Method)).Observe(time.Since(forwardStart).Seconds())
	}

	// Circuit breaker: track upstream 429s
	if p.circuitBreaker != nil {
		if statusCode == http.StatusTooManyRequests {
			if p.metrics != nil {
				p.metrics.UpstreamRateLimitTotal.WithLabelValues(maskAPIKey(apiKey)).Inc()
			}
			p.circuitBreaker.Trip(apiKey)
		} else if statusCode == http.StatusOK {
			p.circuitBreaker.Reset(apiKey)
		}
	}

	if err != nil {
		p.recordRPCOutcome(req.Method, "forward_error", start)
		// Clean up pre-registration on forward failure.
		if rawTxPlainCreateAddr != "" {
			if delErr := p.rbacAccessCtrl.Store().DeletePreregisteredAddressByAddress(
				context.Background(), rawTxPlainCreateAddr); delErr != nil {
				slog.Warn("failed to clean up plain CREATE pre-registration", "address", rawTxPlainCreateAddr, "error", delErr)
			}
		}
		for _, addr := range runtimeCreateAddrs {
			if delErr := p.rbacAccessCtrl.Store().DeletePreregisteredAddressByAddress(
				context.Background(), addr); delErr != nil {
				slog.Warn("failed to clean up runtime create pre-registration on forward error", "address", addr, "error", delErr)
			}
		}
		p.logAccess(ctx, req, http.StatusBadGateway)
		// Opaque client message; raw upstream error stays in slog. (RD-1178 / RD-934)
		slog.Warn("failed to forward raw transaction", slog.String("method", req.Method), slog.String("user", req.UserID), slog.Any("err", err))
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusBadGateway,
				Message:    "failed to forward request",
			},
		}
	}

	// Handle plain CREATE pre-registration tracking/cleanup.
	if rawTxPlainCreateAddr != "" {
		var rpcResp struct {
			Result string `json:"result"`
			Error  *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		nodeAccepted := statusCode == http.StatusOK &&
			err == nil &&
			json.Unmarshal(responseBody, &rpcResp) == nil &&
			rpcResp.Error == nil &&
			rpcResp.Result != ""

		if nodeAccepted {
			// Track and start background receipt polling.
			p.rbacAccessCtrl.TrackPlainCreateDeployment(rpcResp.Result, result.OrgID, result.UserID, rawTxPlainCreateAddr)
			p.pollAndFinalizePlainCreate(rpcResp.Result, rawTxPlainCreateAddr, result.OrgID, result.UserID)
		} else {
			// Node rejected the tx — delete the pre-registration immediately.
			if delErr := p.rbacAccessCtrl.Store().DeletePreregisteredAddressByAddress(
				context.Background(), rawTxPlainCreateAddr); delErr != nil {
				slog.Warn("failed to clean up plain CREATE pre-registration", "address", rawTxPlainCreateAddr, "error", delErr)
			}
		}
	}

	// Handle runtime CREATE/CREATE2 tracking/cleanup.
	if len(runtimeCreateAddrs) > 0 {
		var rpcResp2 struct {
			Result string `json:"result"`
			Error  *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		nodeAccepted := statusCode == http.StatusOK &&
			err == nil &&
			json.Unmarshal(responseBody, &rpcResp2) == nil &&
			rpcResp2.Error == nil &&
			rpcResp2.Result != ""

		if nodeAccepted {
			if prepared != nil {
				go p.pollAndFinalizeRuntimeCreates(rpcResp2.Result, runtimeCreateAddrs, result.OrgID, result.UserID, prepared.SurvivingCreations)
			} else {
				go p.pollAndFinalizeRuntimeCreates(rpcResp2.Result, runtimeCreateAddrs, result.OrgID, result.UserID)
			}
		} else {
			// Node rejected — clean up pre-registrations
			for _, addr := range runtimeCreateAddrs {
				if delErr := p.rbacAccessCtrl.Store().DeletePreregisteredAddressByAddress(
					context.Background(), addr); delErr != nil {
					slog.Warn("failed to clean up runtime create pre-registration", "address", addr, "error", delErr)
				}
			}
		}
	}

	// System-link the sender's ETH address to their DID.
	if statusCode == http.StatusOK && from != "" && req.UserID != "" {
		if err := p.rbacAccessCtrl.Store().SystemLinkEthAddress(ctx, req.UserID, from); err != nil {
			slog.Warn("failed to system-link eth address", "user", req.UserID, "address", from, "error", err)
		}
	}

	// M7 (security audit follow-up): write the raw-tx visibleTo rule
	// into the outbox; reconciler promotes to tx_visible_to. Same
	// rationale as the eth_sendTransaction path above.
	if len(rawTxVisibleTo) > 0 && statusCode == http.StatusOK {
		if txHash := extractTxHashFromResult(responseBody); txHash != "" {
			if saver, ok := p.txVisibilityStore.(TxVisibilitySaver); ok {
				if err := saver.EnqueuePendingTxVisibility(ctx, txHash, rawTxVisibleTo, req.UserID, result.OrgID); err != nil {
					slog.Error("visibleTo outbox enqueue failed for raw tx; tx is on-chain but recipients won't see it",
						"tx", txHash, "recipients", len(rawTxVisibleTo), "sender", req.UserID, "org", result.OrgID, "error", err)
				} else if p.visibilityKick != nil {
					p.visibilityKick() // drain now so recipients see it within ms, not at the next backstop tick
				}
			}
		}
	}

	// Log successful access
	p.recordRPCOutcome(req.Method, "success", start)
	p.logAccess(ctx, req, statusCode)

	return &ProcessResult{
		StatusCode:   statusCode,
		ResponseBody: responseBody,
	}
}

func (p *JSONRPCProcessor) validateRawTxWithPreparedTrace(ctx context.Context, req *ProcessRequest, from, to, data, value string, prepared *nodeapproval.Prepared) ([]rbac.CreateTarget, *ProcessError) {
	// Get user info for trace validation
	user, err := p.rbacAccessCtrl.Store().GetUserByExternalID(ctx, req.UserID)
	if err != nil || user == nil {
		return nil, &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    "failed to get user for trace validation",
			Reason:     ReasonTracingUnavailable,
		}
	}

	// Get user's org memberships (active only).
	memberships, err := p.rbacAccessCtrl.Store().ListActiveUserMembershipsWithDetails(ctx, user.ID)
	if err != nil {
		return nil, &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    "failed to get user memberships for trace validation",
			Reason:     ReasonTracingUnavailable,
		}
	}

	userOrgIDs := make(map[string]bool)
	for _, m := range memberships {
		if m.Group != nil {
			userOrgIDs[m.Group.OrgID] = true
		}
	}

	// Perform the trace
	var traceResult *tracer.TraceResult
	if prepared != nil {
		traceResult = prepared.Trace
	}
	if traceResult == nil {
		traceResult, err = p.runtimeTracer.TraceTransaction(ctx, from, to, data, value)
	}
	if err != nil {
		slog.Warn("raw send trace: upstream tracer error",
			slog.String("user", req.UserID), slog.String("to", to), slog.Any("err", err))
		return nil, &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    sendTraceDenyTracerError,
			Reason:     ReasonTracingUnavailable,
		}
	}

	if traceResult == nil {
		slog.Warn("raw send trace: nil result",
			slog.String("user", req.UserID), slog.String("to", to))
		return nil, &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    sendTraceDenyTracerError,
			Reason:     ReasonTracingUnavailable,
		}
	}

	// Determine if user has deploy claim from any of their memberships
	userHasDeploy := p.userHasDeployClaim(ctx, memberships)

	// RD-1053: intra-org grant scoping (same knob as the other send paths).
	traceOpts, optErr := p.intraOrgGrantTraceOptions(ctx, user.ID, to, userOrgIDs)
	if optErr != nil {
		slog.Warn("raw send trace: intra-org grant resolution failed",
			slog.String("user", req.UserID), slog.Any("err", optErr))
		return nil, &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    sendTraceValidatorError,
			Reason:     ReasonTracingUnavailable,
		}
	}

	// Validate the trace against org isolation rules
	validator := p.traceValidator
	if prepared != nil {
		validator = validator.WithCodeHashFetcher(prepared)
		traceOpts = append(traceOpts, rbac.WithPreflightCreations(prepared.FreshCreations), rbac.WithPreflightValueRecipients(prepared.NoCodeRecipients))
	}
	validationResult, err := validator.ValidateTrace(ctx, userOrgIDs, traceResult, userHasDeploy, traceOpts...)
	if err != nil {
		slog.Warn("raw send trace: validator error",
			slog.String("user", req.UserID), slog.Any("err", err))
		return nil, &ProcessError{
			StatusCode: http.StatusInternalServerError,
			Message:    sendTraceValidatorError,
			Reason:     ReasonTracingUnavailable,
		}
	}

	if !validationResult.Allowed {
		slog.Info("raw send trace: denial",
			slog.String("user", req.UserID), slog.String("to", to))
		slog.Debug("raw send trace: denial detail",
			slog.String("user", req.UserID),
			slog.String("reason", validationResult.Reason),
			slog.String("denied_target", validationResult.DeniedTarget))
		return nil, &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    sendTraceDenyMessage(validationResult.Reason),
			Reason:     ReasonCrossOrg,
		}
	}

	targets := validationResult.CreateTargets
	if prepared != nil {
		targets = nil
		for _, target := range validationResult.CreateTargets {
			if prepared.SurvivingCreations[strings.ToLower(target.Address)] {
				targets = append(targets, target)
			}
		}
	}
	return targets, nil
}

// validateRawTxWithTracing performs runtime trace validation for raw transactions.
// Returns the list of CREATE/CREATE2 targets discovered during tracing (may be nil),
// and a ProcessError if validation fails.
func (p *JSONRPCProcessor) validateRawTxWithTracing(ctx context.Context, req *ProcessRequest, from, to, data, value string) ([]rbac.CreateTarget, *ProcessError) {
	return p.validateRawTxWithPreparedTrace(ctx, req, from, to, data, value, nil)
}
