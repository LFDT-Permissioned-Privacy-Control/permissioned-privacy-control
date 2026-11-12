package explorer

import (
	"context"
	"encoding/json"
	"privacy-proxy/internal/explorerdata"
	"privacy-proxy/internal/explorerprivacy"
	"privacy-proxy/internal/readprivacyabi"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"

	"privacy-proxy/internal/rbac"
)

// VisibilityMap maps an address (lowercase) to its resolved visibility level
type VisibilityMap = explorerdata.VisibilityMap

// visibilityMapFromDetailed projects the level-only VisibilityMap out of a
// detailed visibility result (RD-1123). GetBatchVisibilityDetailed is an exact
// superset of GetBatchVisibility: both DB methods iterate the same deduplicated
// address set, initialise every address to VisibilityHidden, and resolve each
// level through identical ownership, precompile and org-contract access branches.
// The detailed variant additionally carries Reason / Visible metadata. Therefore
// detailed[addr].Level == plain[addr] for every address, and deriving the plain
// map from the detailed one lets each Redact* entry point issue ONE visibility
// query instead of two — eliminating a redundant per-request DB round-trip with
// no change to the levels the redactor sees.
func visibilityMapFromDetailed(detailed map[string]AddressVisibility) VisibilityMap {
	return explorerdata.VisibilityMapFromDetailed(detailed)
}

// ContractStore is the minimal interface RedactionEngine needs from the explorer store.
type ContractStore interface {
	GetContract(ctx context.Context, address string) (*Contract, error)
}

// EventRuleChecker resolves event-level access rules for a viewer on a
// given contract address. The interface mirrors the RPC-side event-rule
// resolution (see rbac.FilterEventLogs) so the explorer redactor and the
// JSON-RPC filter behave identically — required by the Layer 1 / Layer 2
// symmetry invariant in REDACTION_SPEC.md.
//
// Returns a tri-state EventRulesResolution:
//   - Wildcard == true                  ⇒ all events for this contract are
//     visible to the viewer; allowlist
//     is irrelevant. Mirrors the
//     rbac.EventRulesField{"*"} state.
//   - Wildcard == false, len(Rules) > 0 ⇒ allowlist mode; only listed
//     topic0s pass.
//   - Wildcard == false, len(Rules) == 0 ⇒ **deny-all** (RD-842 / RD-888).
//     Same as `event_rules: null` in
//     the database — operator intent
//     is "no events visible until
//     rules are configured." Anonymous
//     logs (no topic0) are also
//     blocked in this mode.
//
// Implementations MUST return the deny-all state when there is no
// applicable grant for the viewer on the contract. **Never default to
// allow-on-missing** — that was the pre-RD-888 behaviour and the cause of
// the RPC/explorer symmetry break (RPC denied, explorer leaked).
type EventRuleChecker interface {
	// GetEventRulesForContract returns the viewer's event-rule resolution
	// for a contract address. See the interface docstring for tri-state
	// semantics.
	GetEventRulesForContract(ctx context.Context, viewerDID string, contractAddress string) EventRulesResolution
}

// EventRulesResolution describes a viewer's event-rule access for one
// contract. See EventRuleChecker docstring for tri-state semantics.
type EventRulesResolution = explorerprivacy.EventRulesResolution

// EventRuleInfo is a lightweight event rule representation used by the
// redactor. Topic0 is the event signature hash (0x-prefixed, lowercase).
//
// ParamRules are optional per-parameter constraints that mirror the RPC
// layer's rbac.EventRule.ParamRules field. When present, a log whose
// topic0 matches this rule must additionally satisfy at least one of
// the param-rule constraints (OR semantics) — typed against the
// contract's ABI. When empty, topic0 match alone is sufficient.
//
// Pre-this fix the explorer's EventRuleInfo carried only Topic0, so
// param-rule constraints configured on a grant (e.g.
// `{topic0: Transfer, params: [{index: 0, must_be: self}]}`) were
// silently ignored — RPC enforced them, explorer leaked. The audit
// classified this as HIGH because it lets viewers see Transfer logs
// for *other* people's transfers on a contract where the operator
// intended "only your own transfers."
type EventRuleInfo = explorerprivacy.EventRuleInfo

// ABIResolver resolves the ABI for a contract address using the same
// "custom upload first, then built-in registry fallback" semantics as
// rbac.ResolveContractABI. Centralised here so the explorer redactor and
// the JSON-RPC layer (storeABIProvider in internal/server) consult one
// source of truth — required by the access/visibility symmetry invariant
// in REDACTION_SPEC.md.
//
// Returns the empty string when no ABI is resolvable (no custom upload
// AND no built-in match for the contract's metadata.token_type). Callers
// must treat empty as "no resolvable ABI" — the deny-when-no-ABI gate
// (RD-889 / mirrors RD-875 at the RPC layer) drops logs from such
// contracts rather than risk leaking private addresses embedded in
// non-indexed event data parameters that we cannot decode.
type ABIResolver interface {
	Resolve(ctx context.Context, address string) string
}

// AdminContractsResolver returns the subset of supplied contract
// addresses where the viewer holds admin-equivalent privileges (tier-2
// org-admin OR tier-3 per-contract admin claim). The result mirrors the
// JSON-RPC layer's processor_event_rules.go::viewerAdminContracts
// resolver so both layers honour the same admin-bypass set per
// (viewer, contract) — required by the access/visibility symmetry
// invariant in REDACTION_SPEC.md.
//
// When wired (via RedactionEngine.SetAdminContractsResolver) the
// redactor uses the returned map to bypass the deny-when-no-ABI gate
// (RD-889) for admin viewers — exactly as rbac.FilterEventLogs does
// at the RPC layer with its isAdminByContract input.
//
// Implementations MUST be org-scoped: a contract C in Org B's
// ownership must NOT appear admin-true for a viewer who is admin only
// in Org A, even if both orgs ever held the same address (defense in
// depth against migration 035 ever weakening). Unregistered or
// lookup-failed addresses are silently omitted (admin = false).
type AdminContractsResolver interface {
	Resolve(ctx context.Context, viewerDID string, addresses []string) map[string]bool
}

// VisibleToUnlockResolver returns the subset of supplied contract
// addresses where the per-contract `allow_visibleto_unlock` flag is set
// AND the viewer is eligible for the unlock — both gates from RD-874.
// The map is consumed by Phase 4 of RedactLogs along with the
// ListedTxHashes opt: when both the contract is unlockable AND the
// log's tx hash is one the viewer is genuinely listed on, the log passes unredacted
// (bypasses event_rules, param_rules, and the deny-when-no-ABI gate).
//
// Implementations MUST be org-scoped: a viewer who is in another org
// must never appear unlock-eligible for a contract whose owning org
// they are not a member of. Same defence as AdminContractsResolver.
//
// This resolver mirrors the JSON-RPC layer's
// `buildVisibleToUnlockableMap` so both layers honour the same unlock
// set per (viewer, contract) — required by the access/visibility
// symmetry invariant in REDACTION_SPEC.md.
type VisibleToUnlockResolver interface {
	Resolve(ctx context.Context, viewerDID string, addresses []string) map[string]bool
}

// DynamicPayloadAllowedResolver returns, for a batch of contract
// addresses, the subset whose operator has explicitly opted out of the
// M15 dynamic-payload drop gate (`events_allow_dynamic_payload = true`).
// Mirrors the JSON-RPC layer's storeABIProvider.IsEventsAllowDynamicPayload
// so both layers honour the same operator attestation per contract —
// required by the access/visibility symmetry invariant in
// REDACTION_SPEC.md.
//
// Returns a lowercase-address → bool map. Missing or false entries
// mean "drop dynamic-payload events for non-Full viewers" (close-by-
// default). True means "operator attests the dynamic payload is safe;
// pass through" — used for standard ERC-20 / ERC-721 contracts where
// `string symbol` / `bytes metadata` cannot contain foreign-org address
// material.
//
// Implementations MUST scope reads to the canonical contracts table by
// address; cross-org leakage is impossible here because the gate is a
// contract-level attestation, not a viewer-level one.
type DynamicPayloadAllowedResolver interface {
	Resolve(ctx context.Context, addresses []string) map[string]bool
}

// ParticipantEventSlots is the canonical map of "events that name participants
// by indexed address topics" → which 1-based topic slots are address-typed.
// Used by LogParticipantResolver implementations and by RedactTransactions
// to recognise a viewer as a tx participant via event-log evidence (RD-939).
//
// Why an explicit list rather than "any indexed address in any event":
// over-broad inference (e.g. accepting a third-party operator address as a
// participant signal for everyone in that log) would cause false-positive
// reveals — the inverse of the bug we're fixing here. The signatures below
// are the ERC-standard events whose slot semantics are unambiguously
// "from / to / operator / owner / spender" (i.e. a counterparty), so the
// viewer-on-topic test is sound by construction.
//
// Topic0 hashes (keccak256 of the canonical signature):
//
//	Transfer(address,address,uint256)
//	   0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef
//	Approval(address,address,uint256)
//	   0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925
//	ApprovalForAll(address,address,bool)
//	   0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31
//	TransferSingle(address,address,address,uint256,uint256)
//	   0xc3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62
//	TransferBatch(address,address,address,uint256[],uint256[])
//	   0x4a39dc06d4c0dbc64b70af90fd698a233a518aa5d07e595d983b8c0526c8f7fb
//	Deposit(address,uint256)      (WETH)
//	   0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c
//	Withdrawal(address,uint256)   (WETH)
//	   0x7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65
var ParticipantEventSlots = readprivacyabi.ParticipantCatalog()

// LogParticipantStore returns the subset of tx hashes where the viewer is
// a participant via event-log evidence. A viewer counts as a log
// participant when one of their linked ETH addresses appears in any of the
// address-typed indexed topic slots of an accepted ParticipantEventSlots
// signature on a log emitted by that tx.
//
// This is the participant signal that catches token mints to the viewer,
// approvals granted to/by the viewer, ERC-1155 batch transfers, and
// WETH-style wrappers — none of which surface in tx.from / tx.to and most
// of which are missed by the (legacy, hardcoded) calldata heuristic when
// the contract uses a non-standard function selector. See RD-939 for the
// origin bug (custom mint(address,…,…) calldata + Transfer event log,
// viewer was dropped).
//
// Implementations MUST filter on ParticipantEventSlots only — accepting any
// indexed address in any event would falsely flag uninvolved bystanders
// (operator-of-someone-else's-transfer). Returns lowercase tx hashes.
type LogParticipantStore interface {
	FindLogParticipantTxs(ctx context.Context, viewerAddrs []string, txHashes []string) (map[string]bool, error)
}

// RedactionEngine handles the bulk redaction of explorer data based on user grants
type RedactionEngine struct {
	store                         ContractStore
	db                            Database // The main Open Privacy Suite DB for RBAC checks
	eventRuleChecker              EventRuleChecker
	abiResolver                   ABIResolver
	adminContractsResolver        AdminContractsResolver
	visibleToUnlockResolver       VisibleToUnlockResolver
	dynamicPayloadAllowedResolver DynamicPayloadAllowedResolver
	logParticipantStore           LogParticipantStore
	txDataResolver                TxDataResolver
	pseudonymKey                  []byte // RD-1164 #8: HMAC key for address pseudonyms (nil = unkeyed HMAC, still non-reversible)

	// readProfile is the deployment-wide read privacy profile (RD-1299),
	// fixed at construction. The zero value (unset) is enforced as strict,
	// so an engine whose profile was never wired fails closed.
	readProfile rbac.ReadProfile
}

// Database interface for the methods RedactionEngine needs from the main DB
type Database interface {
	GetBatchVisibility(ctx context.Context, viewerDID string, addresses []string) (VisibilityMap, error)
	GetBatchVisibilityDetailed(ctx context.Context, viewerDID string, addresses []string) (map[string]AddressVisibility, error)
	// GetLinkedAddresses returns the lowercase ETH addresses linked to a DID.
	GetLinkedAddresses(ctx context.Context, did string) ([]string, error)
	// GetBatchEventAccess checks which contracts the viewer has event/log access to.
	// Returns a map of lowercase contract address -> bool (true = has event access).
	// A viewer has event access if they are an org admin or have a contract_grant
	// with non-empty event_rules (event_rules IS NOT NULL AND event_rules != '[]').
	GetBatchEventAccess(ctx context.Context, viewerDID string, contractAddresses []string) (map[string]bool, error)
}

// NewRedactionEngine builds a redaction engine. The read profile is required
// (RD-1299): pass the configured PRIVACY_READ_PROFILE value.
func NewRedactionEngine(store ContractStore, db Database, profile rbac.ReadProfile) *RedactionEngine {
	return &RedactionEngine{
		store:       store,
		db:          db,
		readProfile: profile,
	}
}

// ReadProfile reports the read privacy profile this engine enforces.
func (r *RedactionEngine) ReadProfile() rbac.ReadProfile {
	return r.readProfile
}

// SetEventRuleChecker sets an optional event rule checker for log-level filtering.
func (r *RedactionEngine) SetEventRuleChecker(checker EventRuleChecker) {
	r.eventRuleChecker = checker
}

// SetAdminContractsResolver wires the unified admin-contracts resolver
// (RD-890 — closes the tier-3 admin bypass asymmetry between RPC and
// explorer). When set:
//   - Phase 4 computes a per-call admin map for the contracts emitting
//     logs in this batch.
//   - Admin viewers bypass the deny-when-no-ABI gate (RD-889) for those
//     specific contracts — mirroring rbac.FilterEventLogs's
//     isAdminByContract bypass at the RPC layer.
//
// Without this resolver wired, admins fall through to the regular gates
// — strictly fail-closed but creates UX surprise for tier-3 admins
// (logs visible via eth_getLogs but not via the explorer endpoint).
// Production server startup wires it.
func (r *RedactionEngine) SetAdminContractsResolver(resolver AdminContractsResolver) {
	r.adminContractsResolver = resolver
}

// SetVisibleToUnlockResolver wires the per-contract visibleTo unlock
// resolver (RD-874). When set, Phase 4 of RedactLogs treats logs from
// unlock-eligible contracts as fully visible for the duration of any
// transaction the viewer is listed in via visibleTo — bypassing
// event_rules, param_rules, and the deny-when-no-ABI gate for that
// specific tx. Without the resolver wired the unlock branch is
// disabled and the redactor falls back to the additive visibleTo
// behaviour. Production server startup wires it.
func (r *RedactionEngine) SetVisibleToUnlockResolver(resolver VisibleToUnlockResolver) {
	r.visibleToUnlockResolver = resolver
}

// SetDynamicPayloadAllowedResolver wires the M15 per-contract opt-out
// resolver. When set, Phase 4 of RedactLogs drops logs whose matching
// event declares any dynamic non-indexed parameter for contracts where
// the operator has NOT opted out — close-by-default. Mirrors the
// JSON-RPC layer's storeABIProvider.IsEventsAllowDynamicPayload so both
// layers agree per contract.
//
// Without this resolver wired, the M15 drop gate stays disabled —
// dynamic-payload events pass through unredacted. Production server
// startup MUST wire it; legacy tests without explicit M15 coverage skip
// the gate.
func (r *RedactionEngine) SetDynamicPayloadAllowedResolver(resolver DynamicPayloadAllowedResolver) {
	r.dynamicPayloadAllowedResolver = resolver
}

// SetABIResolver wires the unified ABI resolver (RD-889 / Stage 2 of the
// RPC↔explorer redaction unification, RD-887). When set:
//   - Phase 3 (data-field address scanning) consults the resolver instead
//     of the explorer's local ContractStore — gives the explorer access
//     to the built-in ABI registry (ERC-20 / ERC-721 from
//     metadata.token_type) that was previously RPC-layer-only.
//   - Phase 4 applies the deny-when-no-ABI gate: logs from a contract
//     with no resolvable ABI are dropped, mirroring rbac.FilterEventLogs
//     at the RPC layer (RD-875 / decisions.md §2 G5).
//
// Without this resolver wired, the redactor falls back to the
// pre-RD-889 ContractStore-based ABI lookup and skips the deny gate —
// keeping legacy tests passing. Production server startup MUST wire it.
func (r *RedactionEngine) SetABIResolver(resolver ABIResolver) {
	r.abiResolver = resolver
}

// SetPseudonymKey wires the HMAC key used to derive address pseudonyms
// (RD-1164 #8). With a key set, pseudonyms are non-reversible AND
// non-enumerable; with nil they are still non-reversible (HMAC) but a
// candidate address can be recomputed. Production server startup wires
// cfg.ExplorerPseudonymKey via wireExplorerRedactor.
func (r *RedactionEngine) SetPseudonymKey(key []byte) {
	r.pseudonymKey = key
}

// SetLogParticipantStore wires the log-based participant detector (RD-939
// Stage A). Without this resolver the redactor falls back to tx.from /
// tx.to and the legacy hardcoded calldata heuristic, which misses
// participants reached only via event-log topics (the original Dave bug:
// custom-selector mint with viewer in Transfer's `to` topic).
//
// Production server startup MUST wire it; tests that don't care can leave
// it unset (RedactTransactions degrades gracefully — no log signal, but
// the other paths still fire).
func (r *RedactionEngine) SetLogParticipantStore(store LogParticipantStore) {
	r.logParticipantStore = store
}

// TxDataResolver gives the redactor the parent-transaction data it needs to
// judge rows derived from a transaction under the strict read profile
// (RD-1299): a token-transfer row survives only if the Transfer log it derives
// from is admitted by the strict event predicate, and an internal call only if
// the viewer is a participant of its parent transaction. In production this is
// the explorer backend (SQL store or chain-indexer client).
type TxDataResolver interface {
	GetTransaction(ctx context.Context, hash string) (*Transaction, error)
	GetLogsByTransaction(ctx context.Context, txHash string) ([]Log, error)
}

// TxDataBatchResolver is an optional extension of a TxDataResolver that loads
// many transactions, or the logs of many transactions, in one round trip. The
// strict profile resolves a whole page through it when the data source
// implements it (the SQL store); otherwise it falls back to one TxDataResolver
// call per distinct transaction hash. Unknown hashes are simply absent.
type TxDataBatchResolver interface {
	GetTransactionsByHashes(ctx context.Context, hashes []string) ([]Transaction, error)
	GetLogsByTransactions(ctx context.Context, txHashes []string) ([]Log, error)
}

// SetTxDataResolver wires the parent-transaction data source for the strict
// read profile. Without it, strict drops every token-transfer and internal-call
// row (fail closed); the standard profile never consults it.
func (r *RedactionEngine) SetTxDataResolver(res TxDataResolver) {
	r.txDataResolver = res
}

// resolveContractABI returns the resolved ABI JSON for an address, or
// json.RawMessage(nil) when no ABI is resolvable. Prefers the unified
// ABIResolver (covers built-in registry fallback); falls back to the
// explorer's ContractStore for legacy callers that haven't wired the
// resolver. Pre-RD-889 the only path was ContractStore.
func (r *RedactionEngine) resolveContractABI(ctx context.Context, address string) json.RawMessage {
	if r.abiResolver != nil {
		if abi := r.abiResolver.Resolve(ctx, address); abi != "" {
			return json.RawMessage(abi)
		}
		return nil
	}
	if r.store != nil {
		contract, err := r.store.GetContract(ctx, address)
		if err != nil || contract == nil {
			return nil
		}
		return contract.ABI
	}
	return nil
}

// extractUniqueAddresses gets all unique from/to addresses from a list of transactions
func extractUniqueAddresses(txs []Transaction) []string {
	addrMap := make(map[string]bool)
	for _, tx := range txs {
		if tx.From != "" {
			addrMap[strings.ToLower(tx.From)] = true
		}
		if tx.HasRecipient() {
			addrMap[strings.ToLower(*tx.To)] = true
		}
		// RD-1143: include the deployed-contract address on CREATE receipts so
		// its visibility is resolved in the same batch and it can be field-level
		// redacted below. Nil for non-CREATE txs and factory/CREATE2 deploys
		// (the receipt only carries contractAddress for a top-level CREATE).
		if tx.ContractAddress != nil && *tx.ContractAddress != "" {
			addrMap[strings.ToLower(*tx.ContractAddress)] = true
		}
	}

	var addrs []string
	for addr := range addrMap {
		addrs = append(addrs, addr)
	}
	return addrs
}

// isViewerInCalldata checks if any of the viewer's addresses appear as an
// address parameter in the transaction's input data. This detects participation
// in contract calls where the actual counterparty is encoded in calldata rather
// than in the tx-level "to" field (e.g., ERC20 transfer(address,uint256)).
//
// Supported function selectors:
//   - ERC-20  0xa9059cbb: transfer(address to, uint256 amount)
//   - ERC-20  0x23b872dd: transferFrom(address from, address to, uint256 amount)
//   - ERC-20  0x095ea7b3: approve(address spender, uint256 amount)
//   - ERC-721 0x42842e0e: safeTransferFrom(address from, address to, uint256 tokenId)
//   - ERC-721 0xb88d4fde: safeTransferFrom(address from, address to, uint256 tokenId, bytes data)
//   - ERC-721 0xa22cb465: setApprovalForAll(address operator, bool approved)
//   - ERC-1155 0xf242432a: safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes data)
//   - ERC-1155 0x2eb2c2d6: safeBatchTransferFrom(address from, address to, uint256[] ids, uint256[] amounts, bytes data)
//
// M14: pre-fix this covered only the three ERC-20 selectors. Viewers
// who were encoded recipients of ERC-721 / ERC-1155 transfers silently
// lost the participant override — they saw [PRIVATE] for transactions
// where they were the actual counterparty.
func isViewerInCalldata(inputData string, viewerAddrs map[string]bool) bool {
	return readprivacyabi.IsViewerInCalldata(inputData, viewerAddrs)
}

// isViewerInCalldataABI is the RD-939 Stage B successor to the hardcoded
// `isViewerInCalldata` selector switch. It decodes the calldata against
// the called contract's registered ABI (resolved via abiResolver — the
// same path EventRuleChecker uses) and returns true when any decoded
// address-typed argument matches one of the viewer's linked addresses.
//
// Posture:
//   - Requires both abiResolver wired AND an ABI resolvable for tx.To.
//     When ABI is absent we return false rather than guess — same
//     fail-closed stance as RD-889 for log decoding. The log-based
//     participant signal (Stage A) covers most missing-ABI cases.
//   - Walks composite arg types (slice / array / single struct embed)
//     down to single addresses. Catches multi-recipient batch calls
//     where one of the recipients is the viewer.
//   - Returns false on any parse error rather than panicking — calldata
//     can be malformed or use a different ABI than the registered one
//     (e.g. proxy patterns); we never want a decoder error to redact
//     incorrectly.
//
// Why a method on RedactionEngine rather than a free function: it needs
// access to r.abiResolver, which is configured per engine. The legacy
// free `isViewerInCalldata` stays free because it's a fixed heuristic.
func (r *RedactionEngine) isViewerInCalldataABI(ctx context.Context, tx Transaction, viewerAddrs map[string]bool) bool {
	if r.abiResolver == nil || len(viewerAddrs) == 0 {
		return false
	}
	if !tx.HasRecipient() {
		return false // CREATE — no callee, no ABI to resolve.
	}
	abiJSON := r.abiResolver.Resolve(ctx, strings.ToLower(*tx.To))
	if abiJSON == "" {
		return false
	}
	return readprivacyabi.IsViewerInCalldataABI(tx.InputData, abiJSON, viewerAddrs)
}

// anyAddressMatches recursively walks an unpacked ABI value looking for
// any common.Address that matches an entry in viewerAddrs (keys are
// lowercase hex, with 0x prefix). Handles single addresses, []address,
// and arbitrary nesting of slices/arrays. Other concrete types (uint,
// bool, string, bytes) are ignored — only address-typed slots count.
//
// Struct fields are not walked because go-ethereum's ABI decoder
// surfaces struct args as map[string]any only for events with named
// non-indexed fields, not for function inputs. Function struct inputs
// come back as anonymous structs at the type level but the reflect
// path below covers them too.
func anyAddressMatches(v any, viewerAddrs map[string]bool) bool {
	return readprivacyabi.AnyAddressMatches(v, viewerAddrs)
}

// RedactOpts provides optional overrides for transaction redaction.
type RedactOpts = explorerprivacy.RedactOpts
type RedactStats = explorerprivacy.RedactStats

// RedactTransactions applies privacy rules to a list of transactions.
// Optional RedactOpts can override drop behavior for visibleTo transactions.
func (r *RedactionEngine) RedactTransactions(ctx context.Context, txs []Transaction, viewerDID string, opts ...RedactOpts) ([]Transaction, error) {
	if len(txs) == 0 {
		return txs, nil
	}

	var ropts RedactOpts
	if len(opts) > 0 {
		ropts = opts[0]
	}
	viewerIsAdmin := ropts.ViewerIsAdmin

	// RD-1299 strict read profile: a transaction is returned only to its
	// participant (tx from/to), as on the RPC (rbac.DecideTxEnvelope). The
	// admin claim, the admin audit view, visibleTo shares, the RD-1009
	// transfer-participant union and calldata/log-derived participation grant
	// nothing. Disclosure grants apply only through the grant API.
	strict := r.readProfile.Strict()
	if strict {
		viewerIsAdmin = false
		ropts.ListedTxHashes = nil
	}

	// 1. Extract unique addresses
	uniqueAddrs := extractUniqueAddresses(txs)

	// 2. Get batch visibility. GetBatchVisibilityDetailed is an exact superset
	// of GetBatchVisibility (same levels + reason metadata), so we issue ONE
	// query and project the level-only map out of it (RD-1123). The detailed
	// map drives AddressMetadata below; the plain
	// map drives base level resolution — both from the same fetch.
	visibilityMapDetailed, err := r.db.GetBatchVisibilityDetailed(ctx, viewerDID, uniqueAddrs)
	if err != nil {
		return nil, err
	}

	// 2b. Get the viewer's linked addresses for participant visibility.
	// If the viewer is a participant (from or to) in a transaction, the counterparty
	// address should be visible in that specific transaction — the viewer already
	// knows who they sent to / received from via their own wallet.
	viewerAddrs := make(map[string]bool)
	if viewerDID != "" {
		linked, err := r.db.GetLinkedAddresses(ctx, viewerDID)
		if err != nil {
			return nil, err
		}
		for _, a := range linked {
			viewerAddrs[strings.ToLower(a)] = true
		}
	}

	// 2c. (RD-939 Stage A) Resolve log-based participant signals for this
	// batch in a single store call. A viewer is a log participant in a tx
	// when one of their linked addresses appears in an indexed address
	// topic of any ParticipantEventSlots event emitted by that tx — the
	// only signal that catches custom-selector mints to the viewer,
	// approvals, ERC-1155 transfers, WETH wrappers, etc. (See
	// LogParticipantStore docstring for the closed list and rationale.)
	//
	// Degrades gracefully: if the store isn't wired (legacy tests), if the
	// viewer has no linked addresses, or if the query errors out, we just
	// skip the log signal — tx.from/to and the legacy calldata heuristic
	// still apply.
	logParticipantTxs := make(map[string]bool)
	if !strict && r.logParticipantStore != nil && len(viewerAddrs) > 0 && len(txs) > 0 {
		addrSlice := make([]string, 0, len(viewerAddrs))
		for a := range viewerAddrs {
			addrSlice = append(addrSlice, a)
		}
		hashes := make([]string, 0, len(txs))
		for i := range txs {
			hashes = append(hashes, strings.ToLower(txs[i].Hash))
		}
		if found, err := r.logParticipantStore.FindLogParticipantTxs(ctx, addrSlice, hashes); err == nil {
			logParticipantTxs = found
		}
	}

	calldataParticipants := make([]bool, len(txs))
	if !strict {
		for i, tx := range txs {
			calldataParticipants[i] = r.isViewerInCalldataABI(ctx, tx, viewerAddrs)
		}
	}
	redactedTxs, err := explorerprivacy.RedactTransactions(explorerprivacy.TransactionInput{Rows: txs, Profile: r.readProfile, Detailed: visibilityMapDetailed, ViewerAddresses: viewerAddrs, LogParticipants: logParticipantTxs, CalldataParticipants: calldataParticipants, PseudonymKey: r.pseudonymKey}, ropts)
	if err != nil {
		return nil, err
	}
	if strict {
		return redactedTxs, nil
	}

	// Strip token transfer info from transactions where the viewer lacks event access
	// to the target contract. Token transfers are derived from Transfer event logs,
	// so they should only be visible when the viewer has event/log access.
	if !viewerIsAdmin {
		tokenContractAddrs := make(map[string]bool)
		for i := range redactedTxs {
			if redactedTxs[i].TokenTransferCount > 0 && redactedTxs[i].HasRecipient() {
				tokenContractAddrs[strings.ToLower(*redactedTxs[i].To)] = true
			}
		}
		if len(tokenContractAddrs) > 0 {
			addrs := make([]string, 0, len(tokenContractAddrs))
			for a := range tokenContractAddrs {
				addrs = append(addrs, a)
			}
			eventAccess, err := r.db.GetBatchEventAccess(ctx, viewerDID, addrs)
			if err != nil {
				return nil, err
			}
			redactedTxs = explorerprivacy.ApplyTransactionEventAccess(redactedTxs, eventAccess)
		}
	}

	return redactedTxs, nil
}

func removeCategory(cats []string, remove string) []string {
	return explorerprivacy.RemoveCategory(cats, remove)
}

// RedactTransfers applies privacy rules to a list of token transfers.
// Like RedactTransactions, participants (viewer is sender or receiver) get a
// visibility override so they can see the transfer amount and counterparty.
func (r *RedactionEngine) RedactTransfers(ctx context.Context, transfers []TokenTransfer, viewerDID string, opts ...RedactOpts) ([]TokenTransfer, error) {
	if len(transfers) == 0 {
		return transfers, nil
	}

	addrMap := make(map[string]bool)
	for _, t := range transfers {
		if t.From != "" {
			addrMap[strings.ToLower(t.From)] = true
		}
		if t.To != "" {
			addrMap[strings.ToLower(t.To)] = true
		}
	}
	addrs := make([]string, 0, len(addrMap))
	for a := range addrMap {
		addrs = append(addrs, a)
	}

	// Single visibility fetch (RD-1123): the detailed map is a superset of the
	// plain one, so derive plain levels from it instead of querying twice.
	visMapDetailed, err := r.db.GetBatchVisibilityDetailed(ctx, viewerDID, addrs)
	if err != nil {
		return nil, err
	}

	// Get viewer's linked addresses for participant visibility override.
	viewerAddrs := make(map[string]bool)
	if viewerDID != "" {
		linked, err := r.db.GetLinkedAddresses(ctx, viewerDID)
		if err != nil {
			return nil, err
		}
		for _, a := range linked {
			viewerAddrs[strings.ToLower(a)] = true
		}
	}

	var ropts RedactOpts
	if len(opts) > 0 {
		ropts = opts[0]
	}
	viewerIsAdminT := ropts.ViewerIsAdmin

	// RD-1299 strict read profile: a token-transfer row is a rendering of the
	// Transfer event it derives from, so it survives only when that exact log
	// (tx hash, log index) is admitted by the strict event predicate — the
	// same decision eth_getLogs applies. Its counterparty is rendered at its own
	// visibility (as the log's embedded address is masked), its amount kept (a
	// value, not an address). Admin, the audit view, visibleTo and the RD-1009
	// union and disclosure grants provide no additional access.
	strict := r.readProfile.Strict()
	var strictAdmitted map[string]bool
	if strict {
		viewerIsAdminT = false
		ropts.ListedTxHashes = nil
		strictAdmitted, err = r.strictAdmittedTransferLogs(ctx, transfers, viewerDID)
		if err != nil {
			return nil, err
		}
	}

	rendered := explorerprivacy.RedactTransfers(explorerprivacy.TransferInput{Rows: transfers, Profile: r.readProfile, Detailed: visMapDetailed, ViewerAddresses: viewerAddrs, StrictAdmitted: strictAdmitted, PseudonymKey: r.pseudonymKey}, ropts)
	result, exempt := rendered.Rows, rendered.EventAccessExempt

	// Strip transfers where the viewer lacks event access to the token contract.
	if !viewerIsAdminT && len(result) > 0 {
		tokenAddrs := make(map[string]bool)
		for _, t := range result {
			if t.TokenAddress != "" {
				tokenAddrs[strings.ToLower(t.TokenAddress)] = true
			}
		}
		if len(tokenAddrs) > 0 {
			addrs := make([]string, 0, len(tokenAddrs))
			for a := range tokenAddrs {
				addrs = append(addrs, a)
			}
			eventAccess, err := r.db.GetBatchEventAccess(ctx, viewerDID, addrs)
			if err != nil {
				return nil, err
			}
			result, err = explorerprivacy.ApplyTransferEventAccess(result, exempt, eventAccess)
			if err != nil {
				return nil, err
			}
		}
	}

	return result, nil
}

// transferLogKey identifies the log a token-transfer row derives from.
func transferLogKey(txHash string, logIndex int) string {
	return explorerprivacy.TransferLogKey(txHash, logIndex)
}

// strictAdmittedTransferLogs returns the (tx hash, log index) keys of the logs
// behind these transfer rows that the strict event predicate admits for the
// viewer, evaluated by RedactLogsWithOpts on the logs themselves (RD-1299). The
// page costs one log lookup (batched when the data source supports it, else one
// per distinct transaction) and ONE log-redaction pass over every row's log. No
// data source → nothing is admitted (fail closed).
func (r *RedactionEngine) strictAdmittedTransferLogs(ctx context.Context, transfers []TokenTransfer, viewerDID string) (map[string]bool, error) {
	admitted := make(map[string]bool)
	if r.txDataResolver == nil || viewerDID == "" {
		return admitted, nil
	}
	wanted := make(map[string]bool, len(transfers))
	var hashes []string
	seen := make(map[string]bool)
	for _, t := range transfers {
		h := strings.ToLower(t.TxHash)
		if h == "" {
			continue
		}
		wanted[transferLogKey(h, t.LogIndex)] = true
		if !seen[h] {
			seen[h] = true
			hashes = append(hashes, h)
		}
	}
	if len(hashes) == 0 {
		return admitted, nil
	}
	logs, err := r.strictTxLogs(ctx, hashes)
	if err != nil {
		return nil, err
	}
	// Only the logs the rows derive from are judged; each log is decided on
	// its own, so judging them together equals judging them per transaction.
	var behind []Log
	for _, l := range logs {
		if wanted[transferLogKey(l.TxHash, l.LogIndex)] {
			behind = append(behind, l)
		}
	}
	if len(behind) == 0 {
		return admitted, nil
	}
	kept, err := r.RedactLogsWithOpts(ctx, behind, viewerDID, nil)
	if err != nil {
		return nil, err
	}
	for _, l := range kept {
		admitted[transferLogKey(l.TxHash, l.LogIndex)] = true
	}
	return admitted, nil
}

// strictTxLogs returns the logs of the given distinct, lower-case transaction
// hashes: one batched lookup when the data source supports it, else one lookup
// per hash. Callers have checked r.txDataResolver != nil.
func (r *RedactionEngine) strictTxLogs(ctx context.Context, hashes []string) ([]Log, error) {
	if b, ok := r.txDataResolver.(TxDataBatchResolver); ok {
		return b.GetLogsByTransactions(ctx, hashes)
	}
	var out []Log
	for _, h := range hashes {
		logs, err := r.txDataResolver.GetLogsByTransaction(ctx, h)
		if err != nil {
			return nil, err
		}
		out = append(out, logs...)
	}
	return out, nil
}

// renderStrictTransfer renders a token-transfer row admitted under the strict
// profile: each side at its own visibility level (the viewer's own address is
// Full; another user's private address is [PRIVATE], as the log masks it), the
// zero address as-is, and the amount kept.
func (r *RedactionEngine) renderStrictTransfer(t TokenTransfer, fromLevel, toLevel VisibilityLevel, detailed map[string]AddressVisibility) TokenTransfer {
	return explorerprivacy.RenderStrictTransfer(t, fromLevel, toLevel, detailed, r.pseudonymKey)
}

// RedactInternalTransactions applies privacy rules to a list of internal transactions.
// Like RedactTransactions, participants get a visibility override.
func (r *RedactionEngine) RedactInternalTransactions(ctx context.Context, itxs []InternalTransaction, viewerDID string, opts ...RedactOpts) ([]InternalTransaction, error) {
	if len(itxs) == 0 {
		return itxs, nil
	}

	var ropts RedactOpts
	if len(opts) > 0 {
		ropts = opts[0]
	}

	// RD-1299 strict read profile: an internal call is part of its parent
	// transaction's trace, so it is returned only to a participant of that
	// parent (tx from/to, the rbac.DecideTxEnvelope rule), resolved per parent
	// from the chain data. Admin, the audit view, visibleTo and the RD-1009
	// union and disclosure grants provide no additional access.
	strict := r.readProfile.Strict()
	if strict {
		ropts.ListedTxHashes = nil
	}
	var parents map[string]*Transaction
	if strict {
		var err error
		if parents, err = r.strictParentTxs(ctx, itxs); err != nil {
			return nil, err
		}
	}

	addrMap := make(map[string]bool)
	for _, t := range itxs {
		if t.From != "" {
			addrMap[strings.ToLower(t.From)] = true
		}
		if t.To != nil && *t.To != "" {
			addrMap[strings.ToLower(*t.To)] = true
		}
	}
	addrs := make([]string, 0, len(addrMap))
	for a := range addrMap {
		addrs = append(addrs, a)
	}

	// Single visibility fetch (RD-1123): derive plain levels from the detailed
	// superset rather than querying GetBatchVisibility separately.
	visMapDetailed, err := r.db.GetBatchVisibilityDetailed(ctx, viewerDID, addrs)
	if err != nil {
		return nil, err
	}

	// Get viewer's linked addresses for participant visibility override.
	viewerAddrs := make(map[string]bool)
	if viewerDID != "" {
		linked, err := r.db.GetLinkedAddresses(ctx, viewerDID)
		if err != nil {
			return nil, err
		}
		for _, a := range linked {
			viewerAddrs[strings.ToLower(a)] = true
		}
	}

	return explorerprivacy.RedactInternalTransactions(explorerprivacy.InternalInput{Rows: itxs, Profile: r.readProfile, Detailed: visMapDetailed, ViewerAddresses: viewerAddrs, Parents: parents, PseudonymKey: r.pseudonymKey}, ropts)
}

// strictParentTxs resolves the parent transactions of a page of internal calls
// for the strict profile, keyed by lower-case hash: one batched lookup when the
// data source supports it, else one lookup per distinct parent. No data source
// or an unknown parent → absent, which admits nothing (fail closed).
func (r *RedactionEngine) strictParentTxs(ctx context.Context, itxs []InternalTransaction) (map[string]*Transaction, error) {
	parents := make(map[string]*Transaction)
	if r.txDataResolver == nil {
		return parents, nil
	}
	var hashes []string
	seen := make(map[string]bool)
	for _, t := range itxs {
		h := strings.ToLower(t.TxHash)
		if h != "" && !seen[h] {
			seen[h] = true
			hashes = append(hashes, h)
		}
	}
	if len(hashes) == 0 {
		return parents, nil
	}
	if b, ok := r.txDataResolver.(TxDataBatchResolver); ok {
		txs, err := b.GetTransactionsByHashes(ctx, hashes)
		if err != nil {
			return nil, err
		}
		for i := range txs {
			tx := txs[i]
			parents[strings.ToLower(tx.Hash)] = &tx
		}
		return parents, nil
	}
	for _, h := range hashes {
		tx, err := r.txDataResolver.GetTransaction(ctx, h)
		if err != nil {
			return nil, err
		}
		if tx != nil {
			parents[h] = tx
		}
	}
	return parents, nil
}

// extractTopicAddress checks if a 32-byte topic hex string encodes an address
// collectLogTopics flattens an explorer.Log's separate Topic0..Topic3
// pointers into the contiguous topics[0..N] slice that
// rbac.MatchesEventParamRules expects. Trailing nils stop the slice —
// once a Topic_i is nil, deeper Topic_(i+1)..Topic_3 are not appended,
// matching how the RPC layer's logEntry.Topics is shaped (only as
// long as the actual indexed-topic count for the event).
func collectLogTopics(l Log) []string { return readprivacyabi.CollectLogTopics(l) }

// using the standard zero-padding convention (12 zero bytes = 24 zero hex chars prefix after "0x").
// Returns the lowercase "0x"-prefixed address and true if the pattern matches, otherwise "", false.
func extractTopicAddress(topic string) (string, bool) {
	return readprivacyabi.ExtractTopicAddress(topic)
}

// redactTopicAddress converts a visibility-redacted embedded address back into a
// zero-padded 32-byte topic value.
func redactTopicAddress(addr string, level VisibilityLevel) string {
	return readprivacyabi.RedactTopicAddress(addr, level)
}

// RedactLogAddressFields zeroes every embedded address in a log's topics and
// ABI-decoded non-indexed data that is NOT VisibilityFull for the viewer, per
// visMap. It is the single field-level redaction primitive shared by the
// explorer redactor (RedactionEngine.RedactLogsWithOpts) and the RPC log filter
// (server.FilterLogsWithEventRules), so both layers hide EXACTLY the same
// embedded addresses for a given (viewer, log) — symmetry by construction
// (RD-1214, completing RD-887).
//
// It performs NO admission decision (that is rbac.DecideLogEmitter,
// resolved upstream) and NO metadata emission (explorer-only, and only for the
// addresses this primitive leaves visible). Both callers resolve visMap from the
// SAME source — db.GetBatchVisibilityDetailed — so the per-address verdict is
// identical on the two layers by construction.
//
// topics is topic0..topicN in slot order (nil entries preserved in place). data
// is the raw hex data field; contractABI + topic0 drive the non-indexed data
// scan (a no-op when either is absent — the caller's deny-when-no-ABI gate has
// already run, so an admitted log always has a resolvable ABI in production).
func RedactLogAddressFields(topics []*string, data string, contractABI json.RawMessage, topic0 *string, visMap VisibilityMap) ([]*string, string) {
	return readprivacyabi.RedactLogAddressFields(topics, data, contractABI, topic0, visMap)
}

// ExtractLogAddresses returns every embedded address (indexed topics +
// ABI-decoded non-indexed data), lowercased and de-duplicated, in a log. It is
// the companion to RedactLogAddressFields: a caller collects these addresses,
// resolves their visibility (db.GetBatchVisibilityDetailed), builds a visMap,
// then calls RedactLogAddressFields. Sharing this extractor means the RPC log
// filter and the explorer redactor consider the SAME address set (RD-1214).
func ExtractLogAddresses(topics []*string, data string, contractABI json.RawMessage, topic0 *string) []string {
	return readprivacyabi.ExtractLogAddresses(topics, data, contractABI, topic0)
}

// redactTopicField redacts a single topic field if it embeds a private address.
// If the topic does not embed a recognised address pattern it is returned unchanged.
func redactTopicField(topic *string, visMap VisibilityMap) *string {
	return readprivacyabi.RedactTopicField(topic, visMap)
}

// eventHasDynamicNonIndexedParam mirrors rbac.eventHasDynamicNonIndexedParam:
// reports whether the event matching topic0 in contractABI declares any
// non-indexed parameter of a dynamically-sized ABI type (`bytes`,
// `string`, dynamic arrays / fixed arrays of dynamic types, or tuples
// containing any dynamic field).
//
// Drives the M15 drop gate (security audit follow-up to RD-915). When
// true, the redactor drops the entire log for non-Full viewers (unless
// the contract is opted out via DynamicPayloadAllowedResolver, or the
// viewer has an admin / participant / visibleTo bypass — those resolve
// before this check).
//
// Conservatively returns false on ABI parse failure or unknown topic0
// — at that point the deny-when-no-ABI gate (RD-889) has already taken
// over.
func eventHasDynamicNonIndexedParam(contractABI json.RawMessage, topic0 string) bool {
	return readprivacyabi.EventHasDynamicNonIndexedParamJSON(contractABI, topic0)
}

// isDynamicABIType mirrors rbac.isDynamicABIType — bytes / string /
// slice / array-of-dynamic / tuple-with-any-dynamic are dynamic; fixed
// types (bytesN, intN, uintN, bool, address, function, hash) are static.
func isDynamicABIType(t abi.Type) bool { return readprivacyabi.IsDynamicABIType(t) }

// extractDataAddresses parses the ABI-encoded Data field of a log and returns the lowercase
// "0x"-prefixed addresses found in any non-indexed address-typed parameter slots.
// Returns nil if the ABI cannot be parsed, the event is not found, or no address params exist.
func extractDataAddresses(data string, contractABI json.RawMessage, topic0 *string) []string {
	return readprivacyabi.ExtractDataAddresses(data, contractABI, topic0)
}

// redactLogData scans the ABI-encoded Data field of a log for non-indexed address parameters
// and zeros any slot whose address is private (non-Full visibility).
// Returns the original data unchanged if no ABI is registered, the event is not found,
// no address fields exist, or the data cannot be decoded.
func redactLogData(data string, contractABI json.RawMessage, topic0 *string, visMap VisibilityMap) string {
	return readprivacyabi.RedactLogData(data, contractABI, topic0, visMap)
}

// RedactLogs applies privacy rules to event logs.
// The log Address field is the contract that emitted the event.
// Hidden contracts are dropped; pseudonymous/redacted contracts have their address masked
// and topic/data stripped to prevent correlation.
// For logs from visible contracts, each topic is additionally scanned for embedded EOA/contract
// addresses (zero-padded 32-byte form). Any embedded address that is private is zeroed out.
// When the emitting contract has a registered ABI, the non-indexed Data field is also scanned
// for address-typed parameters and any private addresses are zeroed.
// RedactLogs applies privacy rules to transaction logs. If participantAddrs
// contains the viewer's addresses (e.g. from the parent tx's from/to), logs
// from Redacted contracts are kept (with topics/data intact) instead of being
// stripped — the viewer is a direct participant and already knows the contract.
func (r *RedactionEngine) RedactLogs(ctx context.Context, logs []Log, viewerDID string, participantAddrs ...string) ([]Log, error) {
	return r.RedactLogsWithOpts(ctx, logs, viewerDID, nil, participantAddrs...)
}

// RedactLogsWithOpts is RedactLogs with visibleTo support.
func (r *RedactionEngine) RedactLogsWithOpts(ctx context.Context, logs []Log, viewerDID string, opts *RedactOpts, participantAddrs ...string) ([]Log, error) {
	var visibleTxHashes, listedTxHashes map[string]bool
	if opts != nil {
		visibleTxHashes = opts.VisibleTxHashes
		listedTxHashes = opts.ListedTxHashes
	}
	if len(logs) == 0 {
		return logs, nil
	}

	// Build set of viewer's own linked addresses. Propagate DB errors —
	// silently treating a lookup failure as "no linked addresses" was
	// the pre-fix behaviour and would quietly disable the participant
	// override and the "self" param-rule constraint, leaving the viewer
	// with strictly less access than the policy says they should have.
	// Better to fail the request than to over- or under-redact silently.
	viewerAddrs := make(map[string]bool)
	if viewerDID != "" {
		linked, err := r.db.GetLinkedAddresses(ctx, viewerDID)
		if err != nil {
			return nil, err
		}
		for _, a := range linked {
			viewerAddrs[strings.ToLower(a)] = true
		}
	}

	// Phase 1: collect emitting contract addresses and do an initial batch lookup.
	addrMap := make(map[string]bool)
	for _, l := range logs {
		if l.Address != "" {
			addrMap[strings.ToLower(l.Address)] = true
		}
	}
	addrs := make([]string, 0, len(addrMap))
	for a := range addrMap {
		addrs = append(addrs, a)
	}

	// Single visibility fetch (RD-1123): the detailed map carries both the
	// level (for visMap) and the reason (for masterMeta), so one query replaces
	// the previous GetBatchVisibility + GetBatchVisibilityDetailed pair.
	visMapDetailed, err := r.db.GetBatchVisibilityDetailed(ctx, viewerDID, addrs)
	if err != nil {
		return nil, err
	}
	visMap := visibilityMapFromDetailed(visMapDetailed)
	masterMeta := make(map[string]VisibilityReason)
	for k, v := range visMapDetailed {
		masterMeta[k] = v.Reason
	}

	// Check if viewer is actually a participant in the parent tx.
	isParticipant := false
	for _, pa := range participantAddrs {
		if pa != "" && viewerAddrs[strings.ToLower(pa)] {
			isParticipant = true
			break
		}
	}

	// Phase 2: for logs that will be kept (full/pseudonymous or participant override),
	// scan topics for embedded addresses not yet in visMap.
	extraAddrMap := make(map[string]bool)
	for _, l := range logs {
		level := visMap[strings.ToLower(l.Address)]
		// Redacted/hidden contracts are scanned if viewer is a participant
		// or the tx is in the viewer's visibleTo set.
		logVisibleTo := visibleTxHashes[strings.ToLower(l.TxHash)]
		if (level == VisibilityHidden || level == VisibilityRedacted) && !isParticipant && !logVisibleTo {
			continue
		}
		for _, t := range []*string{l.Topic0, l.Topic1, l.Topic2, l.Topic3} {
			if t == nil {
				continue
			}
			addr, ok := extractTopicAddress(*t)
			if !ok {
				continue
			}
			if _, alreadyKnown := visMap[addr]; !alreadyKnown {
				extraAddrMap[addr] = true
			}
		}
	}

	if len(extraAddrMap) > 0 {
		extraAddrs := make([]string, 0, len(extraAddrMap))
		for a := range extraAddrMap {
			extraAddrs = append(extraAddrs, a)
		}
		// Single fetch (RD-1123): derive level + reason from the detailed map.
		extraVisMapDetailed, err := r.db.GetBatchVisibilityDetailed(ctx, viewerDID, extraAddrs)
		if err != nil {
			return nil, err
		}
		for k, v := range extraVisMapDetailed {
			visMap[k] = v.Level
			masterMeta[k] = v.Reason
		}
	}

	// Phase 3: ABI-based data scanning for logs from visible/pseudonymous contracts.
	// Fetch ABIs for each unique emitter, extract address-typed non-indexed params from
	// the Data field, and resolve their visibility so they can be zeroed if private.
	//
	// ABI source (RD-889 / Stage 2): when SetABIResolver has been called, the
	// resolver is consulted — that path includes the built-in registry
	// fallback (ERC-20 / ERC-721 from metadata.token_type) so the explorer
	// agrees with the RPC layer's storeABIProvider on "is this contract's
	// ABI resolvable?". When the resolver is not wired, fall back to the
	// pre-RD-889 ContractStore lookup so legacy tests keep working.
	contractABIs := make(map[string]json.RawMessage) // address → ABI (nil if not found)
	if r.store != nil || r.abiResolver != nil {
		abiDataAddrMap := make(map[string]bool)
		for _, l := range logs {
			level := visMap[strings.ToLower(l.Address)]
			if level == VisibilityHidden || level == VisibilityRedacted || l.Data == "" || l.Topic0 == nil {
				continue
			}
			addrKey := strings.ToLower(l.Address)
			if _, cached := contractABIs[addrKey]; !cached {
				contractABIs[addrKey] = r.resolveContractABI(ctx, addrKey)
			}
			if len(contractABIs[addrKey]) == 0 {
				continue
			}
			for _, a := range extractDataAddresses(l.Data, contractABIs[addrKey], l.Topic0) {
				if _, alreadyKnown := visMap[a]; !alreadyKnown {
					abiDataAddrMap[a] = true
				}
			}
		}
		if len(abiDataAddrMap) > 0 {
			abiDataAddrs := make([]string, 0, len(abiDataAddrMap))
			for a := range abiDataAddrMap {
				abiDataAddrs = append(abiDataAddrs, a)
			}
			// Single fetch (RD-1123): derive level + reason from the detailed map.
			abiVisMapDetailed, err2 := r.db.GetBatchVisibilityDetailed(ctx, viewerDID, abiDataAddrs)
			if err2 != nil {
				return nil, err2
			}
			for k, v := range abiVisMapDetailed {
				visMap[k] = v.Level
				masterMeta[k] = v.Reason
			}
		}
	}

	// Phase 3b: resolve event rules for each unique emitting contract (if checker is set).
	eventRulesMap := make(map[string]EventRulesResolution) // address -> tri-state resolution
	eventRulesResolved := make(map[string]bool)            // true once we've called the checker for an address
	if r.eventRuleChecker != nil && viewerDID != "" {
		for addr := range addrMap {
			eventRulesMap[addr] = r.eventRuleChecker.GetEventRulesForContract(ctx, viewerDID, addr)
			eventRulesResolved[addr] = true
		}
	}

	// Phase 3c (RD-890): resolve admin-equivalent privileges per emitting
	// contract for the viewer. Mirrors rbac.FilterEventLogs's
	// isAdminByContract input — admins bypass the deny-when-no-ABI gate
	// below (admin already has full access in the contract's owning org;
	// withholding logs because the operator hasn't uploaded an ABI is
	// a UX-only restriction at that level, not a security one).
	//
	// Resolved once per call (one DB pass) rather than per-log to keep
	// the hot path cheap. When the resolver is not wired, this stays an
	// empty map and the bypass simply doesn't fire.
	adminContracts := map[string]bool{}
	if r.adminContractsResolver != nil && viewerDID != "" && len(addrMap) > 0 {
		uniqueAddrs := make([]string, 0, len(addrMap))
		for a := range addrMap {
			uniqueAddrs = append(uniqueAddrs, a)
		}
		adminContracts = r.adminContractsResolver.Resolve(ctx, viewerDID, uniqueAddrs)
	}

	// Phase 3d (RD-874): resolve the per-contract visibleTo unlock map.
	// True for contracts where (a) `allow_visibleto_unlock` is set in the
	// DB AND (b) the viewer is unlock-eligible there (rbac.UnlockableContracts
	// — the same helper the RPC's buildVisibleToUnlockableMap calls). Combined
	// with the per-tx ListedTxHashes check below, this drives the unlock
	// branch in Phase 4, so RPC and explorer agree on the (viewer, contract,
	// tx) triple.
	unlockableContracts := map[string]bool{}
	// The unlock only fires on a tx the viewer is listed on, so skip the
	// eligibility lookups entirely when this page has no listed tx.
	if r.visibleToUnlockResolver != nil && viewerDID != "" && len(addrMap) > 0 && len(listedTxHashes) > 0 {
		uniqueAddrs := make([]string, 0, len(addrMap))
		for a := range addrMap {
			uniqueAddrs = append(uniqueAddrs, a)
		}
		unlockableContracts = r.visibleToUnlockResolver.Resolve(ctx, viewerDID, uniqueAddrs)
	}

	// Phase 3e (M15): resolve the per-contract dynamic-payload opt-out
	// flag for emitting contracts. Drives the drop gate in Phase 4:
	// events whose ABI declares any dynamic non-indexed param are
	// dropped for non-Full viewers unless the contract is opted out
	// (close-by-default). One DB pass per call.
	allowDynamicPayload := map[string]bool{}
	if r.dynamicPayloadAllowedResolver != nil && len(addrMap) > 0 {
		uniqueAddrs := make([]string, 0, len(addrMap))
		for a := range addrMap {
			uniqueAddrs = append(uniqueAddrs, a)
		}
		allowDynamicPayload = r.dynamicPayloadAllowedResolver.Resolve(ctx, uniqueAddrs)
	}

	// Per-call memo of the ABI resolver (uncached DB lookup), so resolving the
	// ABI fact for every candidate log costs one lookup per emitter.
	abiByContract := make(map[string]string)
	resolveABIOnce := func(addr string) string {
		if r.abiResolver == nil {
			return ""
		}
		if v, ok := abiByContract[addr]; ok {
			return v
		}
		// Phase 3 already asked the same resolver (resolveContractABI prefers
		// it when wired), including for emitters that have no ABI.
		if raw, ok := contractABIs[addr]; ok {
			abiByContract[addr] = string(raw)
			return string(raw)
		}
		v := r.abiResolver.Resolve(ctx, addr)
		abiByContract[addr] = v
		return v
	}

	resolvedABIs := make(map[string]string)
	for _, l := range logs {
		addr := strings.ToLower(l.Address)
		level := visMap[addr]
		if level == VisibilityHidden {
			continue
		}
		if !adminContracts[addr] && !(unlockableContracts[addr] && listedTxHashes[strings.ToLower(l.TxHash)]) && level != VisibilityFull {
			continue
		}
		if _, ok := resolvedABIs[addr]; !ok {
			resolvedABIs[addr] = resolveABIOnce(addr)
		}
	}
	return explorerprivacy.RedactLogs(explorerprivacy.LogInput{Rows: logs, Profile: r.readProfile, Visibility: visMap, MasterMetadata: masterMeta, ViewerAddresses: viewerAddrs, Participant: isParticipant, Rules: eventRulesMap, RulesResolved: eventRulesResolved, AdminContracts: adminContracts, UnlockableContracts: unlockableContracts, AllowDynamicPayload: allowDynamicPayload, ContractABIs: contractABIs, ResolvedABIs: resolvedABIs, ABIResolverAbsent: r.abiResolver == nil, PseudonymKey: r.pseudonymKey}, opts)
}

// RedactAddress redacts a single address based on visibility for the viewer.
func (r *RedactionEngine) RedactAddress(ctx context.Context, address string, viewerDID string) (string, error) {
	visMap, err := r.db.GetBatchVisibility(ctx, viewerDID, []string{strings.ToLower(address)})
	if err != nil {
		return "[REDACTED]", err
	}
	level := visMap[strings.ToLower(address)]
	return r.applyRedaction(address, level), nil
}

// RedactTokenHolders applies privacy rules to token holder list.
// Holders with hidden addresses are dropped; others have their address masked.
func (r *RedactionEngine) RedactTokenHolders(ctx context.Context, holders []TokenHolder, viewerDID string) ([]TokenHolder, error) {
	if len(holders) == 0 {
		return holders, nil
	}

	addrMap := make(map[string]bool)
	for _, h := range holders {
		if h.Address != "" {
			addrMap[strings.ToLower(h.Address)] = true
		}
	}
	addrs := make([]string, 0, len(addrMap))
	for a := range addrMap {
		addrs = append(addrs, a)
	}

	visMap, err := r.db.GetBatchVisibility(ctx, viewerDID, addrs)
	if err != nil {
		return nil, err
	}

	return explorerprivacy.RedactTokenHolders(explorerprivacy.HolderInput{Rows: holders, Visibility: visMap, PseudonymKey: r.pseudonymKey})
}

// isNonIdentifiable returns true if the visibility level means the viewer
// cannot identify the address — it will render as "[PRIVATE]" either way.
func isNonIdentifiable(level VisibilityLevel) bool { return explorerprivacy.IsNonIdentifiable(level) }

// isZeroEVMAddress reports whether addr is the canonical EVM zero address.
// It is a protocol constant, never a private identity.
func isZeroEVMAddress(addr string) bool { return explorerprivacy.IsZeroEVMAddress(addr) }

// applyRedaction modifies an address string based on its visibility level
func (r *RedactionEngine) applyRedaction(address string, level VisibilityLevel) string {
	return explorerprivacy.ApplyRedaction(address, level, r.pseudonymKey)
}
