// Package disclosuredata supplies bounded protected-read queries, rendering and source contracts.
package disclosuredata

import (
	"context"
	"privacy-proxy/internal/disclosurepolicy"
	"privacy-proxy/internal/networkidentity"
	"time"
)

type Digest string                            // canonical sha256: +64 lowercase hex; never a free-form identifier
type NetworkBinding = networkidentity.Binding // tiny stdlib-only shared helper; Key()([32]byte,error)

type Count string  // canonical unsigned decimal uint64, zero="0", no sign/leadingzero/exponent
type Amount string // canonical unsigned decimal uint256

type View string

const (
	List    View = "list"
	Detail  View = "detail"
	Resolve View = "resolve"
	Report  View = "report"
)

type Query struct {
	Version         uint8                      `json:"v"`
	Resource        disclosurepolicy.Resource  `json:"resource"`
	View            View                       `json:"view"`
	TargetActorIDs  []string                   `json:"targetActorIds,omitempty"`
	Addresses       []string                   `json:"addresses,omitempty"`
	DataTime        *disclosurepolicy.Interval `json:"dataTime,omitempty"`
	Level           *disclosurepolicy.Level    `json:"level,omitempty"`
	Limit           *uint16                    `json:"limit,omitempty"`
	Cursor          *string                    `json:"cursor,omitempty"`
	AddressID       *string                    `json:"addressId,omitempty"`
	TransactionHash *string                    `json:"transactionHash,omitempty"`
}

// Decoder rejects null/unknown/duplicate properties before ExactDecode.
// Normalization only narrows an already-authorized ORIGINAL whole case scope.
// It performs no token verification, case lookup or source call.

type SourceKind string

const (
	WalletSource    SourceKind = "wallet"
	ActivitySource  SourceKind = "activity"
	HistorySource   SourceKind = "history"
	FinanceSource   SourceKind = "finance"
	SanctionsSource SourceKind = "sanctions"
)

type SourcePlan struct {
	Version      uint8
	BundleDigest Digest
	NetworkKey   Digest
	Profile      string // closed legacy Version1 or explicitly retained Version2 profile
	PlanDigest   Digest
	Resources    []disclosurepolicy.Resource // sorted, unique, exact actually supported set
}

// Immutable references name qualified owned source cuts, never URLs or authority tokens.
// Activity ref ID names an immutable SEALED audit chain head, excluding buffered/unlogged operations.
// Legacy History ref ID names an immutable coverage/canonical cut incl R.
// Explicit retained Version2 History instead names a source basis, not an
// immutable list of rows, a ROOT or an A2 birth proof.
// Wallet ref ID is exact current snapshot digest; Finance ref ID is the exact retained scoped row sample.
type SourceRef struct {
	Kind SourceKind
	ID   Digest
}
type SourceDescriptor struct {
	Version        uint8
	Kind           SourceKind
	Reference      Digest
	NetworkKey     Digest
	Epoch          Digest
	Generation     string // canonical nonzero UUID
	PlanDigest     Digest
	FormatDigest   Digest
	CoverageDigest Digest
	AsOf           time.Time // UTC microsecond-truncated observation; never logical completion order
	Population     string    // closed per-kind literals in contract.json
}
type ReadScope struct {
	Namespace          Digest
	CaseID             string
	CaseVersion        int64
	RecipientActorID   string
	DataOrganizationID string
	BundleDigest       Digest
	RuleDigest         Digest
	EffectiveUntil     time.Time
	Query              NormalizedQuery
}

// Owned operational adapters are named TCB. Implementations and real source qualification
// belong to B/C/D; no untrusted HTTP caller can provide one. SliceA tests can fake this
// interface but are expressly not a delivered-data proof or a mounted production source.
type Sources interface {
	Plan() SourcePlan // detached immutable actual selected assembly, no policy DB
	Open(context.Context, ReadScope, []SourceRef) (Snapshot, error)
}
type Snapshot interface {
	Descriptors() []SourceDescriptor // detached sorted<=5, exact required kinds, no extras
	Read(context.Context, ReadScope, *Position /* authenticatedAfter, nil initial */) (Facts, error)
	CheckCurrent(context.Context) error // outside case lock: epoch/fault/recovery readiness
	Close()
}

type Provenance struct {
	Source             Digest
	DataOrganizationID string
	TargetActorIDs     []string
	Kind               string // closed per-record population literal, not a Verified=true flag
}
type WalletFact struct {
	ActorID    string
	Address    [20]byte
	AcceptedAt time.Time
}
type AddressFact struct {
	Provenance Provenance
	Address    [20]byte
	ENSName    *string // optional only from a separately qualified bounded source
}
type ActivityFact struct {
	Provenance        Provenance
	ID                string // canonical UUID for v2; attested legacy IDs normalized during import
	ProducerID        string // canonical UUID
	RunID             string // canonical UUID
	CompletionOrdinal Count
	ObservedAt        time.Time
	Method            string
	StatusCode        uint16
	TrustedIP         *string
}
type TransactionFact struct {
	Provenance       Provenance
	Hash             [32]byte
	BlockHash        [32]byte
	BlockNumber      Count
	TransactionIndex uint32
	BlockTime        int64
	From             [20]byte
	To               *[20]byte // nil is creation, never substitute zero address
	Value            Amount
	GasUsed          Count                  // actual qualified receipt
	Status           uint8                  // exactly0or1 from actual qualified receipt
	Direction        string                 // incoming|outgoing|self from query-scoped current participant set
	Full             *TransactionDetailFact // permitted only detail+Full; never fetched for lower levels
}
type TransactionDetailFact struct {
	SignedLegacyGasPrice *Amount // only type0/1, never a dynamic cap
	EffectiveGasPrice    Amount  // actual MINED receipt effectiveGasPrice; wire gasPrice
	BlockBaseFeePerGas   *Amount // canonical header; required dynamic profile cross-check
	GasLimit             Count
	MaxFeePerGas         *Amount
	MaxPriorityFeePerGas *Amount
	Nonce                Count
	Type                 uint8
	Input                string // canonical0x-prefixed lowercase even hex, <=1MiB text
	Error                *string
	RevertReason         *string
	ContractAddress      *[20]byte
}
type MethodCount struct {
	Method                    string
	Total, Successful, Failed Count
}
type ActivityAggregate struct {
	Total, Successful, Failed Count
	Methods                   []MethodCount // sortedunique<=512; includes ALL scoped retained SEALED rows at the chain head
}
type SanctionMatch struct {
	Address  [20]byte
	SourceID string
	Reason   string
}
type SanctionsAggregate struct {
	Status             string // clear|hit|not-applicable
	Matches            []SanctionMatch
	ScopedAddressCount uint16
	SourceDigest       Digest
	CheckedAt          time.Time
}
type ComplianceEvidence struct {
	ID              Count
	Provenance      Provenance
	TransactionHash [32]byte
	DecisionAt      time.Time
	Decision        string // allowed|denied
	Monitored       bool
	Kind            string // root_native|root_erc20|admission_only (not_detected is coverage)
	Reason          string // Full only; never leak free text at lower level
	PolicyDigest    Digest
	QuoteDigest     *Digest
	Quote           *QuoteFact // present iff actual qualified snapshot; Full output only
	Coverage        string     // existing actual admission.Event coverage, validated on source read
	RecordID        *string
}
type QuoteFact struct {
	ID, Currency, SourceID, Value string // Value canonical existing finite fiat scalar, <=512bytes
	ProviderAsOf, FetchedAt       time.Time
	Digest                        Digest
}
type ComplianceAggregate struct {
	Activity  ActivityAggregate
	Sanctions SanctionsAggregate
	Evidence  []ComplianceEvidence // sortedbounded<=100, reportTooBroad rather thantruncate
	KYC       string               // literal not_evaluated inA unless a separately approved actual source added
}
type Position struct {
	Kind        SourceKind
	Activity    *ActivityPosition
	Transaction *TransactionPosition
	Address     *AddressPosition
}
type ActivityPosition struct {
	ObservedAtMicros  int64
	ProducerID, RunID string
	CompletionOrdinal Count
	RecordID          string
}
type TransactionPosition struct {
	BlockNumber      Count
	TransactionIndex uint32
	Hash             [32]byte
}
type AddressPosition struct{ Address [20]byte } // one grouped row per address
// Exactly ONE branch, matching normalized resource/view. Aggregates are complete-or-error.
// addresses/resolve INPUT may contain COMPLETE<=4096 qualified candidates; OUTPUT is one/404.
// Full tx detail INPUT one qualifiedtx; renderer compares locator ONLY against its actually
// in-scope target From/To participants using same bounded Wallets. Retained list
// sources resolve an optional address locator with the same configured render keys.
// Paged Read must prove page+lookahead or source exhaustion; no budget-exhausted false end.
// Page keys strictly ASCENDING+unique and>authenticatedAfter; do not sort malformed source.
type Facts struct {
	Addresses       []AddressFact
	Activities      []ActivityFact
	Transactions    []TransactionFact
	ActivitySummary *ActivityAggregate
	Sanctions       *SanctionsAggregate
	Compliance      *ComplianceAggregate
	End             bool
	Next            *Position
	Wallets         []WalletFact // ONE total<=4096 unioned snapshot; split query targets vs viewer by ActorID
	// Viewer-only facts never broaden target scope. Input actors<=257 when Mine is needed.
}

type Key struct {
	ID    string
	Bytes []byte
}
type Keys struct {
	Active   Key
	Previous *Key
}
type RenderContext struct {
	PreparedAt                                   time.Time // service-owned output observation; never source/cursor freshness
	Namespace                                    Digest
	CaseID, DataOrganizationID, RecipientActorID string
	Keys                                         Keys
	Query                                        NormalizedQuery
	EffectiveUntil                               time.Time
}

// Result is opaque and can only be produced by the closed validator/renderer.
// It has no RawMessage/map/[]byte escape hatch. Its JSON branches are closed and checked by MarshalJSON.

type CursorBinding struct {
	Namespace        Digest
	CaseID           string
	CaseVersion      int64
	RecipientActorID string
	BundleDigest     Digest
	RuleDigest       Digest
	QueryDigest      Digest
	RenderGeneration Digest
	SourcePlanDigest Digest
}

type CoverageDTO struct {
	Status            string   `json:"status"` // COMPLETE_AT_CUT or explicitly RETAINED_AT_READ
	Populations       []string `json:"populations"`
	SourceCutDigest   Digest   `json:"sourceCutDigest,omitempty"`
	SourceBasisDigest Digest   `json:"sourceBasisDigest,omitempty"`
	PreparedAt        int64    `json:"preparedAt"`
}
type AddressDTO struct {
	AddressID      string   `json:"addressId"`
	Display        string   `json:"display"`
	Address        *string  `json:"address,omitempty"`        // Full only
	TargetActorIDs []string `json:"targetActorIds,omitempty"` // Full only
	ENSName        *string  `json:"ensName,omitempty"`        // Full+qualified only
	IsMine         *bool    `json:"isMine,omitempty"`         // Full/Pseudonymous only
}
type TransactionDTO struct {
	BlockNumber      Count   `json:"blockNumber"`
	TransactionIndex uint32  `json:"transactionIndex"`
	BlockTime        int64   `json:"blockTime"`
	GasUsed          Count   `json:"gasUsed"`
	Status           uint8   `json:"status"`
	Direction        string  `json:"direction"`
	From             string  `json:"from"`
	To               *string `json:"to"`                        // required null for creation
	TransactionHash  *string `json:"transactionHash,omitempty"` // Full only
	Value            *Amount `json:"value,omitempty"`           // Full only
	AddressID        *string `json:"addressId,omitempty"`       // Full only; case-bound in-scope target participant for detail
}
type TransactionDetailDTO struct {
	TransactionDTO
	GasPrice             Amount  `json:"gasPrice"` // ACTUAL MINED effective price, never dynamic cap
	GasLimit             Count   `json:"gasLimit"`
	MaxFeePerGas         *Amount `json:"maxFeePerGas,omitempty"`
	MaxPriorityFeePerGas *Amount `json:"maxPriorityFeePerGas,omitempty"`
	Nonce                Count   `json:"nonce"`
	Type                 uint8   `json:"type"`
	Input                string  `json:"input"`
	Error                *string `json:"error,omitempty"`
	RevertReason         *string `json:"revertReason,omitempty"`
	ContractAddress      *string `json:"contractAddress,omitempty"`
}
type ActivityDTO struct {
	RecordID   string  `json:"recordId"`
	Method     string  `json:"method"`
	StatusCode uint16  `json:"statusCode"`
	Time       int64   `json:"time"`
	ActorID    *string `json:"actorId,omitempty"`   // Full only
	IPAddress  *string `json:"ipAddress,omitempty"` // Full+trusted only
}
type MethodCountDTO struct {
	Method     string `json:"method"`
	Total      Count  `json:"total"`
	Successful Count  `json:"successful"`
	Failed     Count  `json:"failed"`
}
type SummaryDTO struct {
	Total           Count            `json:"total"`
	Successful      Count            `json:"successful"`
	Failed          Count            `json:"failed"`
	MethodBreakdown []MethodCountDTO `json:"methodBreakdown"`
}
type SanctionMatchDTO struct {
	Address  AddressDTO `json:"address"`
	SourceID string     `json:"sourceId"`
	Reason   *string    `json:"reason,omitempty"` // Full only; free text can contain identity
}
type SanctionsDTO struct {
	Status             string             `json:"status"` // clear|hit|not-applicable
	ScopedAddressCount uint16             `json:"scopedAddressCount"`
	SourceDigest       Digest             `json:"sourceDigest"`
	CheckedAt          int64              `json:"checkedAt"`
	Matches            []SanctionMatchDTO `json:"matches"`
}
type QuoteDTO struct {
	ID           string `json:"id"`
	Currency     string `json:"currency"`
	SourceID     string `json:"sourceId"`
	Value        string `json:"value"`
	ProviderAsOf int64  `json:"providerAsOf"`
	FetchedAt    int64  `json:"fetchedAt"`
	Digest       Digest `json:"digest"`
}
type ComplianceEvidenceDTO struct {
	ID              Count     `json:"id"`
	Population      string    `json:"population"` // literal ADMISSION_DECISION
	Time            int64     `json:"time"`
	Kind            string    `json:"kind"`
	Decision        string    `json:"decision"`  // allowed|denied
	Monitored       bool      `json:"monitored"` // never turn monitor-mode allowed into compliant
	Coverage        string    `json:"coverage"`
	PolicyDigest    Digest    `json:"policyDigest"`
	QuoteDigest     *Digest   `json:"quoteDigest,omitempty"`
	Quote           *QuoteDTO `json:"quote,omitempty"`           // Full only
	TransactionHash *string   `json:"transactionHash,omitempty"` // Full only
	RecordID        *string   `json:"recordId,omitempty"`        // Full only
	Reason          *string   `json:"reason,omitempty"`          // Full only
}
type ComplianceDTO struct {
	Activity  SummaryDTO              `json:"activity"`
	Sanctions SanctionsDTO            `json:"sanctions"`
	KYC       string                  `json:"kyc"` // literal not_evaluated
	Evidence  []ComplianceEvidenceDTO `json:"evidence"`
}

// Each page is exactly {items:[]typedDTO,nextCursor:*string}; singleton exactly
// {item:typedDTO}. Reports are their exact DTO above. Result's private branch
// selector and MarshalJSON reject multiple/missing/wrong-resource branches.

// Shared PRE-ALLOCATION budget for each owned adapter operation and renderer preflight.
// Fixed limits:2MiB aggregate raw STRING/BYTE occurrences and16384 container entries.
// Checked subtraction/division before any sum/product; no dedup credit for repeated refs.
