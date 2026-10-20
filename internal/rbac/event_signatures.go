package rbac

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/crypto"
)

// EventSignature represents a parsed event definition from a contract ABI.
type EventSignature struct {
	Name              string      `json:"name"`                // e.g. "Transfer"
	Signature         string      `json:"signature"`           // e.g. "Transfer(address,address,uint256)"
	Topic0            string      `json:"topic0"`              // keccak256 of signature, hex-encoded with 0x prefix
	Inputs            []EventInput `json:"inputs"`
	DefaultParamRules []ParamRule `json:"default_param_rules"` // suggested "self" constraint for each address-typed input
}

// EventInput describes one parameter of an event.
type EventInput struct {
	Name    string `json:"name"`
	Type    string `json:"type"`    // ABI type string (e.g. "address", "uint256")
	Indexed bool   `json:"indexed"`
}

// ExtractEventSignatures parses a contract ABI JSON string and returns event
// definitions with computed topic0 hashes. Returns an error if the ABI cannot
// be parsed.
func ExtractEventSignatures(abiJSON string) ([]EventSignature, error) {
	if abiJSON == "" {
		return nil, fmt.Errorf("empty ABI")
	}

	parsedABI, err := abi.JSON(strings.NewReader(abiJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to parse ABI: %w", err)
	}

	var sigs []EventSignature
	for _, event := range parsedABI.Events {
		inputs := make([]EventInput, len(event.Inputs))
		for i, inp := range event.Inputs {
			inputs[i] = EventInput{
				Name:    inp.Name,
				Type:    inp.Type.String(),
				Indexed: inp.Indexed,
			}
		}

		topic0 := "0x" + hex.EncodeToString(crypto.Keccak256([]byte(event.Sig)))

		// Build default param rules: "self" for every address-typed input.
		var defaultRules []ParamRule
		for i, inp := range event.Inputs {
			if inp.Type.String() == "address" {
				defaultRules = append(defaultRules, ParamRule{
					Index:  i,
					MustBe: "self",
				})
			}
		}

		sigs = append(sigs, EventSignature{
			Name:              event.Name,
			Signature:         event.Sig,
			Topic0:            topic0,
			Inputs:            inputs,
			DefaultParamRules: defaultRules,
		})
	}

	return sigs, nil
}

// IsValidTopic0 checks if a string is a valid 32-byte hex topic0 hash.
// Must be "0x" followed by exactly 64 hex characters (32 bytes).
func IsValidTopic0(topic0 string) bool {
	if len(topic0) != 66 || !strings.HasPrefix(topic0, "0x") {
		return false
	}
	_, err := hex.DecodeString(topic0[2:])
	return err == nil
}

// ValidateParamRuleMustBe validates a ParamRule.MustBe value.
// Valid values are:
//   - "self" — matches the caller's linked addresses
//   - "0x..." — a valid hex string (at least 1 byte, at most 32 bytes)
//
// Returns an error message suitable for API responses, or "" if valid.
func ValidateParamRuleMustBe(mustBe string) string {
	if mustBe == "self" {
		return ""
	}
	if !strings.HasPrefix(mustBe, "0x") {
		return "must_be must be \"self\" or a 0x-prefixed hex value"
	}
	hexPart := mustBe[2:]
	if len(hexPart) == 0 {
		return "must_be hex value cannot be empty (just \"0x\")"
	}
	if len(hexPart)%2 != 0 {
		return "must_be hex value must have even number of hex characters"
	}
	if len(hexPart) > 64 {
		return "must_be hex value too long (max 32 bytes / 64 hex chars)"
	}
	if _, err := hex.DecodeString(hexPart); err != nil {
		return "must_be contains invalid hex characters"
	}
	return ""
}
