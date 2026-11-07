// Package disclosurepolicy compiles immutable disclosure rules. It does not
// verify identities, store cases, fetch data or establish legal authority.
package disclosurepolicy

const (
	APIVersion = "ops.disclosure-policy/v1alpha1"
	Kind       = "DisclosurePolicy"
)

type Source struct {
	APIVersion string       `json:"apiVersion"`
	Kind       string       `json:"kind"`
	Rules      []RuleSource `json:"rules"`
}
type GroupRef struct {
	OrganizationID string `json:"organizationId"`
	GroupID        string `json:"groupId"`
}
type Viewers struct {
	Groups []GroupRef `json:"groups"`
	Actors []string   `json:"actors"`
}
type Targets struct {
	Mode   string   `json:"mode"`
	Actors []string `json:"actors"`
}
type Addresses struct {
	Mode   string   `json:"mode"`
	Values []string `json:"values"`
}
type Interval struct {
	Start int64 `json:"start"`
	End   int64 `json:"end"`
}
type Validity struct {
	NotBefore int64 `json:"notBefore"`
	ExpiresAt int64 `json:"expiresAt"`
}
type Resource string
type Level string

const (
	ActivityLogs     Resource = "activity_logs"
	Transactions     Resource = "transactions"
	Events           Resource = "events"
	AddressHistory   Resource = "addresses"
	ActivitySummary  Resource = "activity_summary"
	SanctionsReport  Resource = "sanctions_report"
	ComplianceReport Resource = "compliance_report"
	Redacted         Level    = "redacted"
	Pseudonymous     Level    = "pseudonymous"
	Full             Level    = "full"
	MaxCaseSeconds            = 30 * 24 * 60 * 60
	MaxUnixSeconds            = int64(253402300799)
)

type RuleSource struct {
	ID                 string     `json:"id"`
	DataOrganizationID string     `json:"dataOrganizationId"`
	Viewers            Viewers    `json:"viewers"`
	Targets            Targets    `json:"targets"`
	Resources          []Resource `json:"resources"`
	Addresses          Addresses  `json:"addresses"`
	DataTime           Interval   `json:"dataTime"`
	MaxLevel           Level      `json:"maxLevel"`
	Validity           Validity   `json:"validity"`
	MaxCaseSeconds     int64      `json:"maxCaseSeconds"`
}

// Scope always names concrete target actors and resources. All-address breadth
// must be explicit, and applies only to qualified data belonging to the targets.
type Scope struct {
	TargetActors []string   `json:"targetActors"`
	Resources    []Resource `json:"resources"`
	Addresses    Addresses  `json:"addresses"`
	DataTime     Interval   `json:"dataTime"`
	Level        Level      `json:"level"`
}

// OrganizationGroupIndex is used only while compiling one selected bundle.
// The compiled catalog retains no callback into mutable authority.
type OrganizationGroupIndex interface {
	HasOrganization(string) bool
	HasGroup(string, string) bool
}

type Limits struct {
	MaxDocumentBytes int
	MaxJSONDepth     int
	MaxRules         int
	MaxGroups        int
	MaxActors        int
	MaxAddresses     int
}

func DefaultLimits() Limits { return Limits{1 << 20, 32, 1024, 128, 256, 1024} }
func (l Limits) Valid() bool {
	return l.MaxDocumentBytes > 0 && l.MaxDocumentBytes <= 1<<30 && l.MaxJSONDepth > 0 && l.MaxJSONDepth <= 256 && l.MaxRules > 0 && l.MaxRules <= 1<<20 && l.MaxGroups > 0 && l.MaxGroups <= 1<<20 && l.MaxActors > 0 && l.MaxActors <= 1<<20 && l.MaxAddresses > 0 && l.MaxAddresses <= 1<<20
}
