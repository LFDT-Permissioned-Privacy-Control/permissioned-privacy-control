package rbac

import (
	"context"
	"encoding/json"
	"privacy-proxy/internal/readprivacyabi"
	"strings"
)

// ABIProvider looks up the ABI for a contract address. Returns empty string if
// the ABI is not available. Addresses are lowercase with 0x prefix.
type ABIProvider interface {
	GetContractABI(address string) string
}

// DynamicPayloadAllower is an optional interface implemented by ABIProvider
// instances that also know whether a contract has been opted out of the
// M15 dynamic-payload drop gate (`contracts.events_allow_dynamic_payload`).
//
// Pre-M15, RedactLogs and FilterEventLogs scanned only AddressTy +
// bytes32-typed STATIC slots of an event's non-indexed params for
// embedded private addresses. Dynamic types — `bytes`, `string`,
// dynamic arrays, dynamic structs — were passed through verbatim, so
// any contract that embedded addresses inside a `bytes` payload (bridge
// contracts, forwarders, smart-wallet calldata, etc.) leaked foreign-
// org addresses to any viewer who could read the event log.
//
// Default-fix (close-by-default): when this interface is implemented
// AND the contract returns false for IsEventsAllowDynamicPayload, the
// filter drops the entire log if the matched event's ABI declares any
// dynamic non-indexed parameter. Admins, participants, and visibleTo-
// unlocked viewers are unaffected — the drop slots in AFTER those
// bypasses, mirroring the explorer-side gate in redactor.go.
//
// The optional-interface pattern (type-assertion in FilterEventLogs)
// keeps the legacy two-method ABIProvider interface intact: callers
// that don't implement DynamicPayloadAllower (most tests) silently
// disable the gate, which is the pre-M15 behaviour. Production server
// startup wires storeABIProvider, which implements both.
type DynamicPayloadAllower interface {
	IsEventsAllowDynamicPayload(address string) bool
}

// TxVisibilityProvider looks up per-tx visibleTo rules from the database.
type TxVisibilityProvider interface {
	GetBatchTxVisibility(ctx context.Context, txHashes []string) (map[string][]string, error)
}

// TxVisibilityContext provides per-tx visibleTo data for the current filter pass.
// When non-nil, it extends (never restricts) the existing event rule filtering:
// if a log's topic0 matches an event rule but param rules fail, the viewer's DID
// is checked against the tx's visibleTo list as a fallback.
//
// UnlockableContracts (RD-874) carries the per-contract pre-computation
// of the visibleTo unlock semantic. The map key is a lowercase
// 0x-prefixed contract address; the value is true iff
// `contract.allow_visibleto_unlock` is set AND the viewer holds an
// eligible group membership on the contract (see
// UnlockableContracts / IsViewerEligibleForVisibleToUnlock for the gate). When the map
// reports true for a log's emitting contract AND the viewer is in the
// tx's visibleTo set, the log passes the filter unconditionally —
// bypassing the deny-when-no-ABI gate, event_rules, and param_rules
// for that one tx. Empty / nil map = unlock disabled, additive
// behaviour applies.
type TxVisibilityContext struct {
	ViewerDID           string              // The DID of the user viewing the logs
	TxVisibility        map[string][]string // tx_hash (lowercase) -> visible_to_dids
	UnlockableContracts map[string]bool     // contract address (lowercase) -> unlock pre-resolved true

	// ParticipantTxHashes (RD-1162) is the pre-resolved set of transaction
	// hashes (lowercase) the viewer participated in — their linked address is
	// the tx `from` or `to`. When a log belongs to one of these txs AND the
	// viewer holds a grant on the emitting contract, the log is admitted even
	// if the event is not in the viewer's event_rules allowlist and carries no
	// address of theirs — they authored/participated in the tx and already
	// know its contents. Populated by the RPC layer: the receipt path derives
	// it from the receipt's from/to; the eth_getLogs path resolves each tx's
	// sender via a batched upstream eth_getTransactionByHash. Empty/nil = no
	// participant admission (backward compatible).
	ParticipantTxHashes map[string]bool
}

// logEntry is the minimal structure needed to inspect an Ethereum log for
// event filtering. Fields mirror the JSON-RPC log representation.
type logEntry struct {
	Address string   `json:"address"`
	Topics  []string `json:"topics"`
	Data    string   `json:"data"`
}

// FilterEventLogs filters a slice of raw JSON log entries based on the caller's
// event rules from their effective permissions.
//
// Semantics:
//   - If no event_rules are configured (nil or []): deny all logs for that contract.
//   - If event_rules are configured: allowlist mode — only listed topic0s pass.
//   - For rules with ParamRules ("self" constraints): the log must also have
//     the caller's address in the constrained parameter positions (OR semantics
//     across multiple ParamRules on the same event).
//   - Union semantics across grants: if any grant allows the event, it passes.
//   - Per-tx visibleTo: if topic0 matches an event rule but param rules fail,
//     the viewer's DID is checked against the tx's visibleTo list as a fallback.
//     This is purely additive — it never restricts existing access.
//   - **No resolvable ABI ⇒ deny-all** for the emitting contract regardless
//     of event_rules (RD-875, closes decisions.md §2 G5). Without an ABI we
//     cannot decode non-indexed `address`-typed parameters from the log's
//     `data` blob, so private addresses embedded there would leak verbatim.
//     Operators must register an ABI (custom upload, or set `token_type` on
//     the contract for the built-in registry per RD-793) before any event
//     access can take effect. Admin-bypass viewers (`isAdminByContract`)
//     are unaffected — they see everything regardless.
//
// userAddresses are the caller's linked ETH addresses (lowercase 0x-prefixed).
// perms contains the resolved effective permissions with ContractAccess and EventRules.
// abiProvider supplies contract ABIs for param rule decoding. When non-nil
// and it returns "" for a contract, that contract's logs are denied (RD-875).
// When nil, the ABI gate is disabled — used by tests that don't wire an ABI
// provider; production paths always pass a non-nil provider.
// visCtx provides optional per-tx visibleTo data (may be nil for backward compat).
// FilterEventLogs filters a slice of log entries.
//
// `isAdminByContract` is an ORG-SCOPED map populated by the caller: the
// key is the contract's lowercased address, and the entry is true iff
// the viewer holds the admin claim in THAT CONTRACT'S OWNING ORG (not
// merged across all orgs the viewer belongs to). This is the admin
// bypass input — a viewer with ClaimAdmin on a contract in a different
// org MUST NOT appear here for this contract. See
// JSONRPCProcessor.viewerAdminContracts for the resolver.
//
// The scoping matters even though migration 035 enforces unique address
// → one org at the schema level: belt + braces. If that invariant ever
// weakens (manual DB edit, future multi-org feature, migration bug),
// the runtime check still denies cross-org admin leaks.
//
// FilterEventLogs returns the admitted raw logs only. A caller that renders
// admitted logs to a client MUST use FilterEventLogsDetailed and honour each
// log's payload policy (RD-1300): the raw logs here still carry every
// embedded address.
func FilterEventLogs(
	profile ReadProfile,
	logs []json.RawMessage,
	perms *EffectivePermissions,
	userAddresses []string,
	abiProvider ABIProvider,
	visCtx *TxVisibilityContext,
	isAdminByContract map[string]bool,
) []json.RawMessage {
	if len(logs) == 0 {
		return logs
	}
	admitted := FilterEventLogsDetailed(profile, logs, perms, userAddresses, abiProvider, visCtx, isAdminByContract)
	out := make([]json.RawMessage, len(admitted))
	for i, a := range admitted {
		out[i] = a.Raw
	}
	return out
}

// AdmittedLog is one log that passed admission, together with the payload
// policy the shared decision attached to it (RD-1300). The policy travels with
// the log object from admission to rendering; it is never serialised or
// re-derived, so it cannot drift onto another log.
type AdmittedLog struct {
	Raw     json.RawMessage
	Payload LogPayloadPolicy
}

// FilterEventLogsDetailed is FilterEventLogs returning, for every admitted log,
// the payload policy decided by DecideLogEmitter for that exact log: its own
// emitting contract and its own transaction hash. Order is preserved. The read
// profile is a required argument (RD-1299); under strict each log's
// IndexedSelf fact is resolved from the emitter's ABI.
func FilterEventLogsDetailed(
	profile ReadProfile,
	logs []json.RawMessage,
	perms *EffectivePermissions,
	userAddresses []string,
	abiProvider ABIProvider,
	visCtx *TxVisibilityContext,
	isAdminByContract map[string]bool,
) []AdmittedLog {
	// Fail-closed: if permissions couldn't be resolved, deny all logs.
	if len(logs) == 0 || perms == nil {
		return []AdmittedLog{}
	}

	// Build lowercase address set for O(1) lookup.
	addrSet := make(map[string]bool, len(userAddresses))
	for _, a := range userAddresses {
		addrSet[strings.ToLower(a)] = true
	}

	strict := profile.Strict()
	var selfMatcher *IndexedSelfMatcher
	if strict {
		selfMatcher = NewIndexedSelfMatcher()
	}

	filtered := make([]AdmittedLog, 0, len(logs))
	for _, rawLog := range logs {
		var entry logEntry
		if err := json.Unmarshal(rawLog, &entry); err != nil {
			continue // skip malformed
		}

		contractAddr := strings.ToLower(entry.Address)

		// Resolve the per-log facts, then defer the admit/deny verdict to the
		// shared decision engine (rbac.DecideLogEmitter, RD-1214/RD-1300) so the
		// RPC filter and the explorer redactor apply the SAME policy and cannot
		// drift. Each fact below mirrors a gate that used to live inline here;
		// the engine encodes the (unchanged) gate order and semantics.
		access := perms.GetContractAccess(contractAddr)

		facts := LogEmitterFacts{
			// Admin bypass (org-scoped, pre-computed): admin in the emitter's
			// owning org sees all its logs. Caller scopes this per-contract.
			IsAdmin: isAdminByContract[contractAddr],
			// RD-874 visibleTo unlock: allow_visibleto_unlock + eligible +
			// listed in THIS log's own tx visibleTo (the only standalone-grant
			// path, and the only source of LogPayloadFull).
			Unlocked: visCtx != nil && visCtx.UnlockableContracts[contractAddr] && isViewerInVisibleTo(visCtx, rawLog),
			// Grant eligibility (RD-874/RD-1208): a ContractAccess entry exists.
			HasGrant: access != nil,
			// RD-1162 participant/sender (grant-bounded inside the engine).
			IsParticipant: logTxIsParticipant(visCtx, rawLog),
			// Ordinary visibleTo — additive param-rule fallback only.
			InVisibleTo: isViewerInVisibleTo(visCtx, rawLog),
			HasTopic0:   len(entry.Topics) > 0,
		}

		// RD-875 deny-when-no-ABI: without a resolvable ABI, non-indexed
		// address params in `data` can't be decoded/redacted. A nil abiProvider
		// disables the gate (test ergonomics; production always injects one).
		var contractABI string
		if abiProvider != nil {
			contractABI = abiProvider.GetContractABI(contractAddr)
			facts.ABIResolvable = contractABI != ""
		} else {
			facts.ABIResolvable = true
		}

		// M15 dynamic-payload drop: the matched event declares a dynamic
		// non-indexed param and the contract is not opted out. Only meaningful
		// with a resolvable ABI and a topic0.
		if contractABI != "" && facts.HasTopic0 {
			allowDynamic := false
			if dpa, ok := abiProvider.(DynamicPayloadAllower); ok {
				allowDynamic = dpa.IsEventsAllowDynamicPayload(contractAddr)
			}
			facts.DynamicPayloadDropped = !allowDynamic && eventHasDynamicNonIndexedParam(contractABI, entry.Topics[0])
		}

		// Strict read profile (RD-1299): the log must name one of the viewer's
		// linked addresses in an ABI-indexed address parameter. Without a
		// resolvable ABI (including a nil provider) it never does.
		if strict {
			facts.IndexedSelf = selfMatcher.Match(contractABI, entry.Topics, entry.Data, addrSet)
		}

		// event_rules resolution — only needed when a grant exists (the engine
		// drops no-grant emitters before consulting rules).
		if access != nil {
			switch {
			case access.EventRules != nil && access.EventRules.IsWildcard():
				facts.Rules = LogEventRulesWildcard
			default:
				rules := eventRulesGetRules(access.EventRules)
				if len(rules) == 0 {
					facts.Rules = LogEventRulesDeny
				} else {
					facts.Rules = LogEventRulesAllowlist
					if facts.HasTopic0 {
						topic0 := strings.ToLower(entry.Topics[0])
						facts.EventAllowed = eventAllowed(topic0, entry, rules, addrSet, contractAddr, abiProvider)
						facts.Topic0Allowlisted = eventTopic0Matches(topic0, rules)
					}
				}
			}
		}

		if d := DecideLogEmitter(profile, facts); d.Admit {
			filtered = append(filtered, AdmittedLog{Raw: rawLog, Payload: d.Payload})
		}
	}

	return filtered
}

// isViewerInVisibleTo checks if the viewer's DID appears in the visibleTo
// list for the transaction that produced this log entry.
func isViewerInVisibleTo(visCtx *TxVisibilityContext, rawLog json.RawMessage) bool {
	if visCtx == nil || visCtx.ViewerDID == "" || len(visCtx.TxVisibility) == 0 {
		return false
	}
	var logMeta struct {
		TransactionHash string `json:"transactionHash"`
	}
	if err := json.Unmarshal(rawLog, &logMeta); err != nil || logMeta.TransactionHash == "" {
		return false
	}
	dids, ok := visCtx.TxVisibility[strings.ToLower(logMeta.TransactionHash)]
	if !ok {
		return false
	}
	for _, did := range dids {
		if did == visCtx.ViewerDID {
			return true
		}
	}
	return false
}

// logTxIsParticipant reports whether the transaction that produced this log
// entry is one the caller participated in (their linked address is the tx
// from/to), per the pre-resolved visCtx.ParticipantTxHashes set (RD-1162).
// Nil/empty context or set = no participant information (backward compatible:
// callers that do not resolve senders leave it nil and this returns false).
func logTxIsParticipant(visCtx *TxVisibilityContext, rawLog json.RawMessage) bool {
	if visCtx == nil || len(visCtx.ParticipantTxHashes) == 0 {
		return false
	}
	var logMeta struct {
		TransactionHash string `json:"transactionHash"`
	}
	if err := json.Unmarshal(rawLog, &logMeta); err != nil || logMeta.TransactionHash == "" {
		return false
	}
	return visCtx.ParticipantTxHashes[strings.ToLower(logMeta.TransactionHash)]
}

// eventTopic0Matches checks if the given topic0 matches any event rule's Topic0,
// without checking param rules. Used to determine if visibleTo should be
// considered as a fallback (topic0 must be in the allowlist).
func eventTopic0Matches(topic0 string, rules []EventRule) bool {
	for _, rule := range rules {
		if strings.EqualFold(rule.Topic0, topic0) {
			return true
		}
	}
	return false
}

// eventAllowed checks if a log with the given topic0 is allowed by any of the
// event rules. Returns true if the event is in the allowlist and all param
// constraints are satisfied.
func eventAllowed(
	topic0 string,
	entry logEntry,
	rules []EventRule,
	addrSet map[string]bool,
	contractAddr string,
	abiProvider ABIProvider,
) bool {
	for _, rule := range rules {
		if !strings.EqualFold(rule.Topic0, topic0) {
			continue
		}

		// Topic0 matches this rule.
		// nil or empty ParamRules = no constraints, topic0 match is sufficient.
		if len(rule.ParamRules) == 0 {
			return true
		}

		// Check param rules: at least one "self" constraint must match (OR semantics).
		if checkEventParamRules(entry, rule.ParamRules, addrSet, contractAddr, abiProvider) {
			return true
		}
	}
	return false
}

// checkEventParamRules checks if the caller satisfies any of the param rule
// constraints on an event. OR semantics: if ANY constrained parameter matches,
// the check passes.
//
// Supported must_be values:
//   - "self"     — param must encode one of the caller's linked addresses
//   - "0x..."    — param must match the given literal hex value (type-aware comparison)
func checkEventParamRules(
	entry logEntry,
	paramRules []ParamRule,
	addrSet map[string]bool,
	contractAddr string,
	abiProvider ABIProvider,
) bool {
	var abiJSON string
	if abiProvider != nil {
		abiJSON = abiProvider.GetContractABI(contractAddr)
	}
	return MatchesEventParamRules(
		EventLogInputs{
			ContractAddress: entry.Address,
			Topics:          entry.Topics,
			Data:            entry.Data,
		},
		paramRules,
		addrSet,
		abiJSON,
	)
}

// eventRulesGetRules safely extracts the rules slice from an EventRulesField pointer.
// Returns nil if the pointer is nil or if the field is in wildcard/deny mode.
func eventRulesGetRules(f *EventRulesField) []EventRule {
	if f == nil {
		return nil
	}
	return f.GetRules()
}

func eventHasDynamicNonIndexedParam(contractABI, topic0 string) bool {
	return readprivacyabi.EventHasDynamicNonIndexedParam(contractABI, topic0)
}
