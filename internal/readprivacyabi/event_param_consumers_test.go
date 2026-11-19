package readprivacyabi_test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"privacy-proxy/internal/explorerprivacy"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/readprivacy"
	"privacy-proxy/internal/readprivacyabi"

	"github.com/ethereum/go-ethereum/accounts/abi"
)

type consumerABI string

func (value consumerABI) GetContractABI(string) string { return string(value) }

// Exercise both real pure consumers with ordinary grants (no admin, sender or
// visibleTo bypass). This qualifies routing, not server/storage integration.
func TestScalarPredicatesReachRPCAndExplorerConsumers(t *testing.T) {
	contract := "0x1111111111111111111111111111111111111111"
	for _, test := range []struct {
		typ     string
		value   interface{}
		literal string
	}{
		{"uint8", uint8(7), "0x07"},
		{"bytes4", [4]byte{0xaa, 0xbb, 0xcc, 0xdd}, "0xaabbccdd"},
		{"int24", big.NewInt(-1), "0x" + strings.Repeat("ff", 32)},
	} {
		for _, indexed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/indexed=%t", test.typ, indexed), func(t *testing.T) {
				raw := fmt.Sprintf(`[{"type":"event","name":"Scalar","inputs":[{"name":"value","type":%q,"indexed":%t}]}]`, test.typ, indexed)
				parsed, err := abi.JSON(strings.NewReader(raw))
				if err != nil {
					t.Fatal(err)
				}
				event := parsed.Events["Scalar"]
				word, err := event.Inputs.Pack(test.value)
				if err != nil {
					t.Fatal(err)
				}
				topic0 := strings.ToLower(event.ID.Hex())
				topics, data := []string{topic0}, "0x"
				if indexed {
					topics = append(topics, "0x"+hex.EncodeToString(word))
				} else {
					data += hex.EncodeToString(word)
				}
				logJSON, err := json.Marshal(map[string]interface{}{"address": contract, "topics": topics, "data": data})
				if err != nil {
					t.Fatal(err)
				}
				row := explorerprivacy.Log{Address: contract, Topic0: &topic0, Data: data}
				if indexed {
					row.Topic1 = &topics[1]
				}
				for _, literal := range []string{test.literal, "0x02", "invalid"} {
					want := 0
					if literal == test.literal {
						want = 1
					}
					perms := &rbac.EffectivePermissions{ContractAccess: map[string]rbac.ContractAccess{contract: {
						Claims: []rbac.Claim{}, EventRules: &rbac.EventRulesField{Rules: []rbac.EventRule{{Topic0: topic0, ParamRules: []rbac.ParamRule{{Index: 0, MustBe: literal}}}}},
					}}}
					rpc := rbac.FilterEventLogs(rbac.ReadProfileStandard, []json.RawMessage{logJSON}, perms, nil, consumerABI(raw), nil, nil)
					explorer, err := explorerprivacy.RedactLogs(explorerprivacy.LogInput{
						Rows: []explorerprivacy.Log{row}, Profile: readprivacy.ReadProfileStandard,
						Visibility:    explorerprivacy.VisibilityMap{contract: explorerprivacy.VisibilityFull},
						RulesResolved: map[string]bool{contract: true},
						Rules:         map[string]explorerprivacy.EventRulesResolution{contract: {Rules: []explorerprivacy.EventRuleInfo{{Topic0: topic0, ParamRules: []readprivacyabi.ParamRule{{Index: 0, MustBe: literal}}}}}},
						ContractABIs:  map[string]json.RawMessage{contract: json.RawMessage(raw)}, ResolvedABIs: map[string]string{contract: raw},
					}, nil)
					if err != nil {
						t.Fatal(err)
					}
					if len(rpc) != want || len(explorer) != want {
						t.Fatalf("literal %s: RPC=%d Explorer=%d, want both %d", literal, len(rpc), len(explorer), want)
					}
				}
			})
		}
	}
}
