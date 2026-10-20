package rbac

import (
	"github.com/ethereum/go-ethereum/accounts/abi"
)

// EventLogInputs is the minimal log shape used by event param-rule
// evaluation. Both the JSON-RPC layer (rbac.FilterEventLogs) and the
// explorer redactor (explorer.RedactionEngine.RedactLogs) build one of
// these and call MatchesEventParamRules so the two layers reach the
// same allow/deny decision for a given (log, rule, viewer) tuple.
//
// Topics are 0x-prefixed lowercase hex strings, ordered topics[0..N].
// topics[0] is the event signature hash for non-anonymous events. Data
// is the 0x-prefixed ABI-encoded non-indexed payload (may be "0x" or
// "" for events with no non-indexed params).
type EventLogInputs struct {
	ContractAddress string
	Topics          []string
	Data            string
}

// MatchesEventParamRules returns true iff the log satisfies AT LEAST
// ONE of the supplied param-rule constraints (OR semantics, mirroring
// the RPC layer's checkEventParamRules).
//
// The caller is responsible for verifying that the rule's Topic0
// already matches the log's topics[0] — this function only evaluates
// the param-level constraints. Callers with no ParamRules attached
// should pass the log through without invoking this function (matching
// the RPC behaviour at event_filter.go where len(rule.ParamRules)==0
// is treated as "topic0 match is sufficient").
//
// abiJSON may be empty; in that case the function falls back to
// best-effort topic-position matching (same fallback as the RPC layer).
// For non-indexed params with no ABI the function returns false rather
// than guess at the encoding.
//
// viewerAddrs is the set of lowercase 0x-prefixed addresses linked to
// the viewer. Used only by the "self" constraint type.
func MatchesEventParamRules(
	log EventLogInputs,
	paramRules []ParamRule,
	viewerAddrs map[string]bool,
	abiJSON string,
) bool {
	if len(paramRules) == 0 {
		// No constraints — caller should never reach here; defensive return.
		return true
	}
	if len(log.Topics) == 0 {
		// Anonymous event — no topic0 to match an ABI event against, no
		// indexed params either. Fail closed.
		return false
	}
	entry := logEntry{
		Address: log.ContractAddress,
		Topics:  log.Topics,
		Data:    log.Data,
	}
	var parsedEvent *abi.Event
	if abiJSON != "" {
		parsedEvent = findEventByTopic0(abiJSON, log.Topics[0])
	}
	for _, pr := range paramRules {
		switch {
		case pr.MustBe == "self":
			if matchesParamSelf(entry, pr.Index, viewerAddrs, parsedEvent) {
				return true
			}
		case isHexValue(pr.MustBe):
			if matchesParamCustom(entry, pr.Index, pr.MustBe, parsedEvent) {
				return true
			}
		default:
			// Unknown constraint type — fail-closed, skip this rule.
			continue
		}
	}
	return false
}
