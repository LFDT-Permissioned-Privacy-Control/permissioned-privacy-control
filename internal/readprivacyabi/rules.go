package readprivacyabi

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ParamRule constrains a single ABI parameter of a function call or event.
type ParamRule struct {
	Index  int    `json:"index"`   // ABI parameter position (0-based)
	MustBe string `json:"must_be"` // "self" (caller's address) or "0x..." (literal hex value)
}

// EventRule describes access to a single event (identified by topic0 hash),
// with optional parameter-level constraints.
type EventRule struct {
	Topic0     string      `json:"topic0"`                // keccak256(EventName(paramTypes)) — 32-byte hex with 0x prefix
	Name       string      `json:"name"`                  // human-readable event name, from ABI
	ParamRules []ParamRule `json:"param_rules,omitempty"` // optional "self" constraints (reuse existing ParamRule)
}

// EventRulesField represents event access configuration for a contract grant.
// Three states:
//   - Wildcard ("*" in JSON) = all events visible
//   - Deny (null or [] in JSON) = no events visible (fail-closed)
//   - Allowlist ([{...}] in JSON) = only listed events visible
type EventRulesField struct {
	Wildcard bool        // true when the JSON value is the string "*"
	Rules    []EventRule // allowlist rules; only meaningful when Wildcard is false
}

// IsWildcard returns true if all events are visible (wildcard mode).
func (f EventRulesField) IsWildcard() bool { return f.Wildcard }

// IsDeny returns true if no events are visible (deny mode).
func (f EventRulesField) IsDeny() bool { return !f.Wildcard && len(f.Rules) == 0 }

// GetRules returns the allowlist rules. Returns nil for wildcard or deny states.
func (f EventRulesField) GetRules() []EventRule {
	if f.Wildcard {
		return nil
	}
	return f.Rules
}

// MarshalJSON encodes the EventRulesField to JSON:
//   - Wildcard → "*" (quoted string)
//   - Deny (nil/empty rules) → null
//   - Allowlist → JSON array of EventRule
func (f EventRulesField) MarshalJSON() ([]byte, error) {
	if f.Wildcard {
		return json.Marshal("*")
	}
	if len(f.Rules) == 0 {
		return []byte("null"), nil
	}
	return json.Marshal(f.Rules)
}

// UnmarshalJSON decodes JSON into EventRulesField:
//   - "*" string → Wildcard=true
//   - null → Wildcard=false, Rules=nil (deny)
//   - [] → Wildcard=false, Rules=nil (deny)
//   - [{...}] → Wildcard=false, Rules=parsed
func (f *EventRulesField) UnmarshalJSON(data []byte) error {
	// Handle null
	if string(data) == "null" {
		f.Wildcard = false
		f.Rules = nil
		return nil
	}

	// Try string first (for "*")
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		if s == "*" {
			f.Wildcard = true
			f.Rules = nil
			return nil
		}
		return fmt.Errorf("invalid event_rules string: %q (only \"*\" is supported)", s)
	}

	// Try array
	var rules []EventRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return fmt.Errorf("event_rules must be \"*\", null, or an array: %w", err)
	}

	f.Wildcard = false
	if len(rules) == 0 {
		f.Rules = nil // empty array = deny (same as null)
	} else {
		f.Rules = rules
	}
	return nil
}

func UnionEventRules(a, b *EventRulesField) *EventRulesField {
	// nil means deny — no contribution
	aDeny := a == nil || a.IsDeny()
	bDeny := b == nil || b.IsDeny()

	// If either is wildcard, result is wildcard
	if a != nil && a.IsWildcard() {
		return a
	}
	if b != nil && b.IsWildcard() {
		return b
	}

	// Both deny → deny
	if aDeny && bDeny {
		return nil
	}
	// One deny → return the other
	if aDeny {
		return b
	}
	if bDeny {
		return a
	}

	// Both have rules — union them by topic0
	aRules := a.GetRules()
	bRules := b.GetRules()

	seen := make(map[string]EventRule, len(aRules))
	for _, rule := range aRules {
		seen[strings.ToLower(rule.Topic0)] = rule
	}
	for _, rule := range bRules {
		key := strings.ToLower(rule.Topic0)
		if existing, ok := seen[key]; ok {
			// Both sides allow this event. If either side has no param rules,
			// the union is the less restrictive one (no param rules).
			if len(existing.ParamRules) == 0 || len(rule.ParamRules) == 0 {
				seen[key] = EventRule{Topic0: rule.Topic0, Name: rule.Name}
			}
			// else: both have param rules, keep existing (arbitrary but consistent)
		} else {
			seen[key] = rule
		}
	}

	rules := make([]EventRule, 0, len(seen))
	for _, rule := range seen {
		rules = append(rules, rule)
	}
	return &EventRulesField{Rules: rules}
}
