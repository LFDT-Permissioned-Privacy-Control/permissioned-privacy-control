package explorerprivacy

import (
	"encoding/json"
	"privacy-proxy/internal/explorerdata"
	"privacy-proxy/internal/readprivacy"
	"privacy-proxy/internal/readprivacyabi"
)

// Facts are resolved before this pure boundary. The kernel performs no I/O and
// makes no claim that caller-supplied values are provenance or permissions.
// V1 adapters keep their old lookup/error behavior. V2 current-fact assemblers
// must validate complete bounded context before invoking these row renderers.
type Transaction = explorerdata.Transaction
type TokenTransfer = explorerdata.TokenTransfer
type InternalTransaction = explorerdata.InternalTransaction
type Log = explorerdata.Log
type TokenHolder = explorerdata.TokenHolder
type JSONString = explorerdata.JSONString
type VisibilityMap = explorerdata.VisibilityMap
type VisibilityLevel = explorerdata.VisibilityLevel
type VisibilityReason = explorerdata.VisibilityReason
type AddressVisibility = explorerdata.AddressVisibility

const (
	VisibilityFull            = explorerdata.VisibilityFull
	VisibilityPseudonymous    = explorerdata.VisibilityPseudonymous
	VisibilityRedacted        = explorerdata.VisibilityRedacted
	VisibilityHidden          = explorerdata.VisibilityHidden
	ReasonParticipantOverride = explorerdata.ReasonParticipantOverride
	ReasonVisibleToGrant      = explorerdata.ReasonVisibleToGrant
)

type RedactOpts struct {
	// VisibleTxHashes is the set of tx hashes whose transaction rows are
	// always kept for the viewer: genuine visibleTo shares plus the RD-1009
	// transfer-participant union. Membership alone only keeps the tx row
	// (RedactTransactions) — it keeps no transfer or internal-frame row and
	// reveals no address; reveals are keyed on ListedTxHashes (a genuine
	// share) only (RD-1316).
	VisibleTxHashes map[string]bool

	// ListedTxHashes is the set of tx hashes whose visibleTo row genuinely
	// lists the viewer (tx_visible_to only — never the RD-1009
	// transfer-participant union that also feeds VisibleTxHashes). It is the
	// only input the redactors accept for "the sender listed this viewer on
	// this tx": the address reveal on tx, transfer and internal rows (RD-1316),
	// and the RD-874 visibleTo log unlock and ordinary param-rule fallback
	// (RD-1307). A nil map lists nothing (fail-closed).
	ListedTxHashes map[string]bool

	// ParentParticipants are the parent transaction's from/to addresses,
	// threaded into RedactInternalTransactions by the single-hash handler
	// (/transactions/:hash/internal). Used ONLY for the RD-1122 per-side
	// reveal: when one of the viewer's linked EOAs is a parent participant,
	// the parent's two parties (already shown at the tx/Overview level) are
	// revealed across nested trace frames so the originator's direct
	// counterparty isn't over-redacted. Empty for the block- and
	// address-scoped internal-tx handlers, which have no single parent tx.
	ParentParticipants []string

	// ViewerIsAdmin indicates the viewer has admin-level access (org admin
	// or admin claim). Admins see all contract activity including txs from
	// private users — G10 non-participant drop does not apply to admins.
	ViewerIsAdmin bool

	// OrgAdminViewUserTxs gates the elevated admin audit view. It is the
	// per-request mirror of config.OrgAdminViewUserTxs. When true AND the
	// viewer is an admin, user↔user rows that are otherwise dropped
	// (both sides non-identifiable, deploys from private EOAs, internal
	// txs between private EOAs) are kept and their value/amount is
	// preserved. Counterparty addresses still render as [PRIVATE] — this is
	// a volume/timing audit view, not real-address visibility. Default false
	// reproduces the strict privacy behaviour exactly.
	OrgAdminViewUserTxs bool

	// Stats, when non-nil, accumulates redaction outcomes the caller cares
	// about. It is mutated through the pointer so it survives RedactOpts
	// being passed by value. Used to drive per-request audit logging.
	Stats *RedactStats
}

// RedactStats accumulates side-channel counts from a redaction pass so the
// caller can react (e.g. emit an audit-log entry) without re-deriving them.
type RedactStats struct {
	// AdminUserTxsRevealed counts rows the elevated org-admin audit view
	// (OrgAdminViewUserTxs) exposed: rows strict privacy would have dropped,
	// and union-kept rows with both sides (or the deployer) private, whose
	// value only the audit view reveals (RD-1316).
	AdminUserTxsRevealed int
}

// adminAuditView reports whether the elevated org-admin audit view applies
// for this redaction pass.
func (o RedactOpts) AdminAuditView() bool {
	return o.ViewerIsAdmin && o.OrgAdminViewUserTxs
}

// recordAdminReveal bumps the reveal counter when stats tracking is enabled.
func (o RedactOpts) RecordAdminReveal() {
	if o.Stats != nil {
		o.Stats.AdminUserTxsRevealed++
	}
}

type EventRulesResolution struct {
	// Wildcard true ⇒ all events visible, allowlist ignored.
	Wildcard bool
	// Rules is the allowlist of (topic0) entries. Honoured only when
	// Wildcard is false. Empty Rules with Wildcard=false ⇒ deny-all.
	Rules []EventRuleInfo
}

type EventRuleInfo struct {
	Topic0     string
	ParamRules []readprivacyabi.ParamRule
}

type TransactionInput struct {
	Rows                 []Transaction
	Profile              readprivacy.ReadProfile
	Detailed             map[string]AddressVisibility
	ViewerAddresses      map[string]bool
	LogParticipants      map[string]bool
	CalldataParticipants []bool // position-aligned, not hash keyed; duplicate rows retain semantics
	PseudonymKey         []byte
}
type TransferInput struct {
	Rows            []TokenTransfer
	Profile         readprivacy.ReadProfile
	Detailed        map[string]AddressVisibility
	ViewerAddresses map[string]bool
	StrictAdmitted  map[string]bool
	PseudonymKey    []byte
}
type TransferOutput struct {
	Rows              []TokenTransfer
	EventAccessExempt []bool
}
type InternalInput struct {
	Rows            []InternalTransaction
	Profile         readprivacy.ReadProfile
	Detailed        map[string]AddressVisibility
	ViewerAddresses map[string]bool
	Parents         map[string]*Transaction
	PseudonymKey    []byte
}
type LogInput struct {
	Rows                []Log
	Profile             readprivacy.ReadProfile
	Visibility          VisibilityMap
	MasterMetadata      map[string]VisibilityReason
	ViewerAddresses     map[string]bool
	Participant         bool // only the original endpoint's actual participation input
	Rules               map[string]EventRulesResolution
	RulesResolved       map[string]bool
	AdminContracts      map[string]bool
	UnlockableContracts map[string]bool
	AllowDynamicPayload map[string]bool
	ContractABIs        map[string]json.RawMessage
	ResolvedABIs        map[string]string
	ABIResolverAbsent   bool // legacy adapter posture; V2 always supplies current registry
	PseudonymKey        []byte
}
type HolderInput struct {
	Rows         []TokenHolder
	Visibility   VisibilityMap
	PseudonymKey []byte
}
