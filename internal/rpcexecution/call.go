package rpcexecution

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	"privacy-proxy/internal/strictjson"
)

// Call is an owned normalized simulation. Its From is never a verified signer.
type Call struct {
	from, to       common.Address
	fromSupplied   bool
	input          []byte
	value, chainID *big.Int
	wire           map[string]any
}

func (c Call) From() common.Address { return c.from }
func (c Call) To() common.Address   { return c.to }
func (c Call) FromSupplied() bool   { return c.fromSupplied }
func (c Call) Input() []byte        { return bytes.Clone(c.input) }
func (c Call) Value() *big.Int {
	if c.value == nil {
		return nil
	}
	return new(big.Int).Set(c.value)
}
func (c Call) Object() map[string]any {
	if c.wire == nil {
		return nil
	}
	out := make(map[string]any, len(c.wire))
	for k, v := range c.wire {
		if k == "accessList" {
			entries := v.([]any)
			copyEntries := make([]any, len(entries))
			for i, entry := range entries {
				tuple := entry.(map[string]any)
				copyEntries[i] = map[string]any{"address": tuple["address"], "storageKeys": append([]any{}, tuple["storageKeys"].([]any)...)}
			}
			out[k] = copyEntries
		} else {
			out[k] = v
		}
	}
	return out
}

func readValue(raw []byte, depth int) (any, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, err := strictjson.ReadValue(d, 0, depth)
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, failure(InvalidCall)
	}
	return v, nil
}

func address(s string) (common.Address, bool) {
	if len(s) != 42 || !strings.HasPrefix(s, "0x") {
		return common.Address{}, false
	}
	b, e := hex.DecodeString(s[2:])
	if e != nil {
		return common.Address{}, false
	}
	return common.BytesToAddress(b), true
}

func data(s string) ([]byte, bool) {
	if !strings.HasPrefix(s, "0x") || len(s)%2 != 0 {
		return nil, false
	}
	b, e := hex.DecodeString(s[2:])
	return b, e == nil
}

func quantity(s string, bits int) (*big.Int, bool) {
	if !strings.HasPrefix(s, "0x") || len(s) < 3 || len(s)-2 > (bits+3)/4 || (len(s) > 3 && s[2] == '0') {
		return nil, false
	}
	for _, c := range s[2:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return nil, false
		}
	}
	v, ok := new(big.Int).SetString(s[2:], 16)
	return v, ok && v.BitLen() <= bits
}

// NormalizeCall rejects ambiguous aliases, overrides and unsupported envelopes.
// The complete supported call object is retained for the node's execution.
func NormalizeCall(raw []byte) (Call, error) {
	bad := func() (Call, error) { return Call{}, failure(InvalidCall) }
	if len(raw) > MaxCallBytes {
		return bad()
	}
	v, e := readValue(raw, 24)
	if e != nil {
		return bad()
	}
	m, ok := v.(map[string]any)
	if !ok {
		return bad()
	}
	c := Call{value: new(big.Int), wire: map[string]any{}}
	for name, value := range m {
		s, isString := value.(string)
		switch name {
		case "from", "to":
			if !isString {
				return bad()
			}
			a, valid := address(s)
			if !valid {
				return bad()
			}
			if name == "from" {
				c.from = a
				c.fromSupplied = true
			} else {
				c.to = a
			}
			c.wire[name] = strings.ToLower(a.Hex())
		case "data", "input":
			if !isString {
				return bad()
			}
			b, valid := data(s)
			if !valid {
				return bad()
			}
			c.wire[name] = "0x" + hex.EncodeToString(b)
		case "gas", "nonce", "value", "gasPrice", "maxFeePerGas", "maxPriorityFeePerGas", "chainId", "type":
			bits := 256
			if name == "gas" || name == "nonce" {
				bits = 64
			}
			if name == "type" {
				bits = 8
			}
			if !isString {
				return bad()
			}
			n, valid := quantity(s, bits)
			if !valid {
				return bad()
			}
			c.wire[name] = s
			if name == "value" {
				c.value = n
			}
			if name == "chainId" {
				c.chainID = n
			}
		case "accessList":
			entries, valid := value.([]any)
			if !valid {
				return bad()
			}
			for _, entry := range entries {
				tuple, valid := entry.(map[string]any)
				if !valid || len(tuple) != 2 {
					return bad()
				}
				s, valid := tuple["address"].(string)
				if !valid {
					return bad()
				}
				a, valid := address(s)
				if !valid {
					return bad()
				}
				keys, valid := tuple["storageKeys"].([]any)
				if !valid {
					return bad()
				}
				for _, key := range keys {
					s, valid := key.(string)
					if !valid {
						return bad()
					}
					b, valid := data(s)
					if !valid || len(b) != 32 {
						return bad()
					}
				}
				tuple["address"] = strings.ToLower(a.Hex())
			}
			c.wire[name] = entries
		default:
			return bad()
		}
	}
	if c.to == (common.Address{}) {
		return bad()
	}
	input, hasInput := c.wire["input"].(string)
	legacy, hasData := c.wire["data"].(string)
	if hasInput && hasData && input != legacy {
		return bad()
	}
	if !hasInput {
		input = legacy
	}
	if input == "" {
		input = "0x"
		c.wire["input"] = input
	}
	c.input, _ = data(input)
	if !c.fromSupplied {
		c.wire["from"] = strings.ToLower(c.from.Hex())
	}
	if _, ok := c.wire["value"]; !ok {
		c.wire["value"] = "0x0"
	}
	_, gasPrice := c.wire["gasPrice"]
	_, fee := c.wire["maxFeePerGas"]
	_, tip := c.wire["maxPriorityFeePerGas"]
	if gasPrice && (fee || tip) {
		return bad()
	}
	if fee && tip {
		maximum, _ := quantity(c.wire["maxFeePerGas"].(string), 256)
		priority, _ := quantity(c.wire["maxPriorityFeePerGas"].(string), 256)
		if priority.Cmp(maximum) > 0 {
			return bad()
		}
	}
	if typ, ok := c.wire["type"].(string); ok {
		n, _ := quantity(typ, 8)
		kind := n.Uint64()
		if kind > 2 || (kind < 2 && (fee || tip)) || (kind == 2 && gasPrice) {
			return bad()
		}
		if kind == 0 {
			if _, ok := c.wire["accessList"]; ok {
				return bad()
			}
		}
	}
	return c, nil
}
