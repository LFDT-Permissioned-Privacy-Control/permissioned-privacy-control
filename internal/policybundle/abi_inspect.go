package policybundle

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"sort"

	"github.com/ethereum/go-ethereum/accounts/abi"
)

type ABIFunction struct {
	Signature string `json:"signature"`
	Selector  string `json:"selector"`
}

type ABIEvent struct {
	Signature         string `json:"signature"`
	Anonymous         bool   `json:"anonymous"`
	SignatureHash     string `json:"signatureHash"`
	Topic0            string `json:"topic0,omitempty"`
	TopicRuleEligible bool   `json:"topicRuleEligible"`
}

// ABIInspection contains detached inspection data, never a mutable ABI index or
// a grant. ABIDigest is the unprefixed hex value native exact-selector rules use.
// FileByteDigest instead identifies the exact input file, before normalization.
type ABIInspection struct {
	FileByteDigest      Digest        `json:"fileByteDigest"`
	CanonicalByteDigest Digest        `json:"canonicalByteDigest"`
	ABIDigest           string        `json:"abiDigest"`
	Functions           []ABIFunction `json:"functions"`
	Events              []ABIEvent    `json:"events"`
	DeploymentVerified  bool          `json:"deploymentVerified"`
}

// InspectABI uses the registry's same bounded parser. It does not establish that
// an ABI describes deployed code or that any rule derived from it is approved.
func InspectABI(raw []byte, limits Limits) (ABIInspection, error) {
	if !limits.valid() {
		return ABIInspection{}, fail(InvalidSelection, "", "", "limits", "positive bounded limits are required")
	}
	canonical, parsed, err := parseCanonicalABI(raw, limits, "")
	if err != nil {
		return ABIInspection{}, err
	}
	digest := RawDigest(canonical)
	report := ABIInspection{FileByteDigest: RawDigest(raw), CanonicalByteDigest: digest,
		ABIDigest: string(digest[len("sha256:"):]), Functions: []ABIFunction{}, Events: []ABIEvent{}}
	for _, method := range parsed.Methods {
		report.Functions = append(report.Functions, ABIFunction{method.Sig, "0x" + hex.EncodeToString(method.ID)})
	}
	for _, event := range parsed.Events {
		entry := ABIEvent{Signature: event.Sig, Anonymous: event.Anonymous, SignatureHash: event.ID.Hex(), TopicRuleEligible: !event.Anonymous}
		if !event.Anonymous {
			entry.Topic0 = entry.SignatureHash
		}
		report.Events = append(report.Events, entry)
	}
	sort.Slice(report.Functions, func(i, j int) bool { return report.Functions[i].Signature < report.Functions[j].Signature })
	sort.Slice(report.Events, func(i, j int) bool { return report.Events[i].Signature < report.Events[j].Signature })
	return report, nil
}

// This is the single registry/inspection normalization and ABI safety boundary.
// Bounds precede abi.JSON, which constructs reflected tuple/array Go types.
func parseCanonicalABI(raw []byte, limits Limits, org string) ([]byte, abi.ABI, error) {
	var zero abi.ABI
	if int64(len(raw)) > limits.MaxDocumentBytes {
		return nil, zero, fail(LimitExceeded, ContractRegistry, org, "abi", "ABI byte budget exceeded")
	}
	value, err := strictValue(raw, limits.MaxJSONDepth)
	if err != nil {
		return nil, zero, fail(InvalidSchema, ContractRegistry, org, "abi", err.Error())
	}
	if err := checkABIBudget(value, limits); err != nil {
		return nil, zero, fail(LimitExceeded, ContractRegistry, org, "abi", err.Error())
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, zero, fail(InvalidSchema, ContractRegistry, org, "abi", "cannot normalize ABI")
	}
	parsed, err := abi.JSON(bytes.NewReader(canonical))
	if err != nil {
		return nil, zero, fail(InvalidSchema, ContractRegistry, org, "abi", "invalid contract ABI")
	}
	if err := uniqueABIIdentities(value, parsed, org); err != nil {
		return nil, zero, err
	}
	return canonical, parsed, nil
}
