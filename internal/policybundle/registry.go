package policybundle

import (
	"encoding/hex"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

type eventAddressRef struct{ org, address string }

func normalizeRegistry(spec *RegistrySpec, org string, limits Limits) ([]eventAddressRef, error) {
	if len(spec.Contracts) > limits.MaxContractsPerOrg {
		return nil, fail(LimitExceeded, ContractRegistry, org, "contracts", "contract budget exceeded")
	}
	ids, addresses := map[string]bool{}, map[string]bool{}
	var refs []eventAddressRef
	for i := range spec.Contracts {
		c := &spec.Contracts[i]
		if !canonicalUUID(c.ID) || ids[c.ID] || !common.IsHexAddress(c.Address) || !boundedName(c.Name, 256) {
			return nil, fail(InvalidSchema, ContractRegistry, org, "contracts", "invalid/duplicate contract identity")
		}
		ids[c.ID] = true
		c.Address = addressKey(c.Address)
		if addresses[c.Address] {
			return nil, fail(InvalidSchema, ContractRegistry, org, "contracts", "duplicate contract address")
		}
		addresses[c.Address] = true
		canonical, parsed, err := parseCanonicalABI(c.ABI, limits, org)
		if err != nil {
			return nil, err
		}
		c.ABI = canonical
		groups := map[string]bool{}
		for j := range c.ReadGrants {
			grant := &c.ReadGrants[j]
			if !canonicalUUID(grant.ID) || ids[grant.ID] || !canonicalUUID(grant.GroupID) || groups[grant.GroupID] {
				return nil, fail(InvalidSchema, ContractRegistry, org, "readGrants", "invalid or duplicate grant/group identity")
			}
			ids[grant.ID], groups[grant.GroupID] = true, true
			switch grant.EventRules.Mode {
			case "none", "all":
				if len(grant.EventRules.Rules) != 0 {
					return nil, fail(InvalidSchema, ContractRegistry, org, "eventRules", "none/all modes require empty rules")
				}
			case "allowlist":
				if len(grant.EventRules.Rules) == 0 {
					return nil, fail(InvalidSchema, ContractRegistry, org, "eventRules", "allowlist requires explicit rules")
				}
				found, err := normalizeEvents(&grant.EventRules, parsed, org)
				if err != nil {
					return nil, err
				}
				refs = append(refs, found...)
			default:
				return nil, fail(InvalidSchema, ContractRegistry, org, "eventRules.mode", "unsupported mode")
			}
		}
		sort.Slice(c.ReadGrants, func(a, b int) bool { return c.ReadGrants[a].GroupID < c.ReadGrants[b].GroupID })
	}
	sort.Slice(spec.Contracts, func(i, j int) bool { return spec.Contracts[i].ID < spec.Contracts[j].ID })
	return refs, nil
}

// The native compiler indexes methods by selector, while event grants use
// topic IDs. Reject ambiguity before either index can choose by map traversal.
// New canonical bundles also reject equivalent duplicate entries.
func uniqueABIIdentities(value any, parsed abi.ABI, org string) error {
	methodIDs, eventIDs := map[string]bool{}, map[common.Hash]bool{}
	functions, events, constructors, fallbacks, receivers := 0, 0, 0, 0, 0
	for _, entry := range value.([]any) {
		object := entry.(map[string]any)
		switch object["type"] {
		case "function":
			functions++
		case "event":
			events++
		case "constructor":
			constructors++
		case "fallback":
			fallbacks++
		case "receive":
			receivers++
		}
	}
	if functions != len(parsed.Methods) || events != len(parsed.Events) || constructors > 1 || fallbacks > 1 || receivers > 1 {
		return fail(InvalidSchema, ContractRegistry, org, "abi", "duplicate ABI entry identity")
	}
	for _, method := range parsed.Methods {
		key := string(method.ID)
		if methodIDs[key] {
			return fail(InvalidSchema, ContractRegistry, org, "abi", "duplicate or ambiguous ABI method selector")
		}
		methodIDs[key] = true
	}
	for _, event := range parsed.Events {
		if eventIDs[event.ID] {
			return fail(InvalidSchema, ContractRegistry, org, "abi", "duplicate or ambiguous ABI event topic/layout")
		}
		eventIDs[event.ID] = true
	}
	return nil
}

func normalizeEvents(rules *EventRules, parsed abi.ABI, org string) ([]eventAddressRef, error) {
	seen := map[string]bool{}
	var refs []eventAddressRef
	bad := func(msg string) error { return fail(InvalidSchema, ContractRegistry, org, "eventRules", msg) }
	for i := range rules.Rules {
		rule := &rules.Rules[i]
		topic, err := hex.DecodeString(strings.TrimPrefix(rule.Topic0, "0x"))
		if err != nil || len(topic) != 32 || !strings.HasPrefix(rule.Topic0, "0x") {
			return nil, bad("event topic requires 32-byte hex")
		}
		rule.Topic0 = strings.ToLower(rule.Topic0)
		if seen[rule.Topic0] {
			return nil, bad("duplicate event topic")
		}
		seen[rule.Topic0] = true
		event, err := parsed.EventByID(common.BytesToHash(topic))
		if err != nil || event.Anonymous || rule.Name != event.RawName {
			return nil, bad("event topic/name must match a non-anonymous ABI event")
		}
		indexes := map[int]bool{}
		for j := range rule.ParamRules {
			param := &rule.ParamRules[j]
			if param.Index < 0 || param.Index >= len(event.Inputs) || indexes[param.Index] {
				return nil, bad("invalid or duplicate event parameter index")
			}
			indexes[param.Index] = true
			typ := event.Inputs[param.Index].Type
			if param.MustBe == "self" {
				if typ.T != abi.AddressTy {
					return nil, bad("self requires an address parameter")
				}
				continue
			}
			value, err := hex.DecodeString(strings.TrimPrefix(param.MustBe, "0x"))
			if err != nil || !strings.HasPrefix(param.MustBe, "0x") {
				return nil, bad("event predicate requires self or canonical hex")
			}
			size := 32
			switch typ.T {
			case abi.AddressTy:
				size = 20
			case abi.FixedBytesTy:
				size = typ.Size
			case abi.IntTy, abi.UintTy, abi.BoolTy:
			default:
				return nil, bad("event predicate requires static scalar ABI type")
			}
			if len(value) != size {
				return nil, bad("event predicate width does not match ABI")
			}
			param.MustBe = strings.ToLower(param.MustBe)
			if typ.T == abi.AddressTy {
				refs = append(refs, eventAddressRef{org, param.MustBe})
			}
		}
		sort.Slice(rule.ParamRules, func(i, j int) bool { return rule.ParamRules[i].Index < rule.ParamRules[j].Index })
	}
	sort.Slice(rules.Rules, func(i, j int) bool { return rules.Rules[i].Topic0 < rules.Rules[j].Topic0 })
	return refs, nil
}
