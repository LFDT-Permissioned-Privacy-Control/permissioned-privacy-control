package policybundle

import (
	"encoding/json"

	"privacy-proxy/internal/policycore"
)

type Kind string

const (
	Groups           Kind = "groups"
	ContractRegistry Kind = "contract-registry"
	ExecutionRules   Kind = "execution-rules"
)

type wireDocument struct {
	APIVersion     string          `json:"apiVersion"`
	Kind           Kind            `json:"kind"`
	OrganizationID string          `json:"organizationId"`
	Spec           json.RawMessage `json:"spec"`
}

type GroupsSpec struct {
	Groups []Group `json:"groups"`
}

type Group struct {
	ID                 string     `json:"id"`
	Slug               string     `json:"slug"`
	Name               string     `json:"name"`
	Description        string     `json:"description"`
	IsOrgAdmin         bool       `json:"isOrgAdmin"`
	IsOrgReadonlyAdmin bool       `json:"isOrgReadonlyAdmin"`
	AllowedMethods     []string   `json:"allowedMethods"`
	Claims             []string   `json:"claims"`
	VerboseErrors      bool       `json:"verboseErrors"`
	RpcCredential      *SecretRef `json:"rpcCredential,omitempty" optional:"true"`
}

type SecretRef struct {
	FromEnv string `json:"fromEnv"`
}
type RegistrySpec struct {
	Contracts []Contract `json:"contracts"`
}

type Contract struct {
	ID                        string          `json:"id"`
	Address                   string          `json:"address"`
	Name                      string          `json:"name"`
	ABI                       json.RawMessage `json:"abi"`
	AllowVisibleToUnlock      bool            `json:"allowVisibleToUnlock"`
	EventsAllowDynamicPayload bool            `json:"eventsAllowDynamicPayload"`
	ReadGrants                []ReadGrant     `json:"readGrants"`
}

type ReadGrant struct {
	ID         string     `json:"id"`
	GroupID    string     `json:"groupId"`
	EventRules EventRules `json:"eventRules"`
}

type EventRules struct {
	Mode  string      `json:"mode"`
	Rules []EventRule `json:"rules"`
}

type EventRule struct {
	Topic0     string      `json:"topic0"`
	Name       string      `json:"name"`
	ParamRules []ParamRule `json:"paramRules"`
}

type ParamRule struct {
	Index  int    `json:"index"`
	MustBe string `json:"must_be"`
}

type ExecutionSpec struct {
	Policy *policycore.Policy `json:"policy"`
}
