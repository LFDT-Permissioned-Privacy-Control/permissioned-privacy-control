package rpcexecution

import (
	"bytes"
	"encoding/hex"
	"encoding/json"

	"github.com/ethereum/go-ethereum/common"
)

type BlockSelector struct {
	selector   string
	hash       bool
	canonical  bool
	historical bool
}

func (b BlockSelector) Historical() bool { return b.historical }

// ParseBlockSelector preserves an explicit anchor request. Pending is a named
// unsupported operation, never a request to silently trace latest instead.
func ParseBlockSelector(raw []byte) (BlockSelector, error) {
	if len(raw) == 0 {
		return BlockSelector{selector: "latest"}, nil
	}
	v, err := readValue(raw, 4)
	if err != nil {
		return BlockSelector{}, failure(InvalidCall)
	}
	if object, ok := v.(map[string]any); ok {
		var b BlockSelector
		if value, ok := object["blockHash"]; ok {
			s, valid := value.(string)
			if !valid {
				return b, failure(InvalidCall)
			}
			b, err = ParseBlockSelector(rawString(s))
			if err != nil || !b.hash {
				return BlockSelector{}, failure(InvalidCall)
			}
			if value, present := object["requireCanonical"]; present {
				flag, valid := value.(bool)
				if !valid {
					return BlockSelector{}, failure(InvalidCall)
				}
				b.canonical = flag
			}
			if len(object) != 1 && !(len(object) == 2 && object["requireCanonical"] != nil) {
				return BlockSelector{}, failure(InvalidCall)
			}
			return b, nil
		}
		if len(object) != 1 {
			return b, failure(InvalidCall)
		}
		s, ok := object["blockNumber"].(string)
		if !ok {
			return b, failure(InvalidCall)
		}
		b, err = ParseBlockSelector(rawString(s))
		if err != nil || b.hash || !b.historical {
			return BlockSelector{}, failure(InvalidCall)
		}
		return b, nil
	}
	s, ok := v.(string)
	if !ok {
		return BlockSelector{}, failure(InvalidCall)
	}
	switch s {
	case "latest", "safe", "finalized":
		return BlockSelector{selector: s}, nil
	case "pending":
		return BlockSelector{}, failure(UnsupportedEvidence)
	}
	if len(s) == 66 {
		b, valid := data(s)
		if valid && len(b) == 32 {
			return BlockSelector{selector: "0x" + hex.EncodeToString(b), hash: true, historical: true}, nil
		}
	}
	if _, valid := quantity(s, 64); valid {
		return BlockSelector{selector: s, historical: true}, nil
	}
	return BlockSelector{}, failure(InvalidCall)
}

type Anchor struct {
	ChainID        string
	Hash           common.Hash
	Number         uint64
	Timestamp      uint64
	Profile        string
	OrganizationID string
}

func decodeHeader(raw []byte) (Anchor, error) {
	v, err := readValue(raw, 32)
	if err != nil {
		return Anchor{}, failure(InvalidEvidence)
	}
	m, ok := v.(map[string]any)
	if !ok {
		return Anchor{}, failure(InvalidEvidence)
	}
	var a Anchor
	s, ok := m["hash"].(string)
	if !ok {
		return a, failure(InvalidEvidence)
	}
	b, valid := data(s)
	if !valid || len(b) != 32 || bytes.Equal(b, make([]byte, 32)) {
		return a, failure(InvalidEvidence)
	}
	a.Hash = common.BytesToHash(b)
	for _, field := range []string{"number", "timestamp"} {
		s, ok := m[field].(string)
		if !ok {
			return a, failure(InvalidEvidence)
		}
		n, valid := quantity(s, 64)
		if !valid {
			return a, failure(InvalidEvidence)
		}
		if field == "number" {
			a.Number = n.Uint64()
		} else {
			a.Timestamp = n.Uint64()
		}
	}
	return a, nil
}

// rawString safely wraps selector strings without permitting injected JSON.
func rawString(s string) json.RawMessage { b, _ := json.Marshal(s); return b }
