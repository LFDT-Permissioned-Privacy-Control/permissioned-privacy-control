package rpcengine

import (
	"bytes"
	"encoding/json"
	"io"

	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/strictjson"
	"privacy-proxy/internal/walletadapter"
	"privacy-proxy/internal/walletops"
)

const MaxRawRequestBytes = 2 << 20

type rawRequest struct {
	id       json.RawMessage
	rawHex   string
	metadata []any
	present  bool
}

func parseRawRequest(raw []byte) (rawRequest, *RPCError) {
	bad := func(id json.RawMessage, code int) (rawRequest, *RPCError) {
		message := "invalid request"
		if code == -32602 {
			message = "invalid params"
		}
		if code == -32601 {
			message = "method not found"
		}
		return rawRequest{id: id}, &RPCError{Code: code, Message: message}
	}
	if len(raw) > MaxRawRequestBytes {
		return bad(nil, -32600)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, err := strictjson.ReadValue(d, 0, 32)
	if err != nil {
		return bad(nil, -32600)
	}
	if _, err := d.Token(); err != io.EOF {
		return bad(nil, -32600)
	}
	m, ok := v.(map[string]any)
	if !ok || len(m) < 4 || len(m) > 6 {
		return bad(nil, -32600)
	}
	for key := range m {
		if key != "jsonrpc" && key != "id" && key != "method" && key != "params" && key != "visibleTo" && key != "privateFor" {
			return bad(nil, -32600)
		}
	}
	if m["jsonrpc"] != "2.0" {
		return bad(nil, -32600)
	}
	idValue, hasID := m["id"]
	if !hasID {
		return bad(nil, -32600)
	}
	switch idValue.(type) {
	case nil, string, json.Number:
	default:
		return bad(nil, -32600)
	}
	id, _ := json.Marshal(idValue)
	method, ok := m["method"].(string)
	if !ok {
		return bad(nil, -32600)
	}
	if method != "eth_sendRawTransaction" {
		return bad(id, -32601)
	}
	params, ok := m["params"].([]any)
	if !ok || len(params) < 1 || len(params) > 2 {
		return bad(id, -32602)
	}
	rawHex, ok := params[0].(string)
	if !ok {
		return bad(id, -32602)
	}
	r := rawRequest{id: id, rawHex: rawHex}
	for _, key := range []string{"visibleTo", "privateFor"} {
		if value, present := m[key]; present {
			r.present = true
			r.metadata = append(r.metadata, value)
		}
	}
	if len(params) == 2 {
		opts, ok := params[1].(map[string]any)
		if !ok || len(opts) != 1 {
			return bad(id, -32602)
		}
		value, present := opts["visibleTo"]
		if !present {
			return bad(id, -32602)
		}
		r.present = true
		r.metadata = append(r.metadata, value)
	}
	return r, nil
}

// entries checks the combined raw count before any lookup or deduplication.
func (r rawRequest) entries() ([]string, bool) {
	out := []string{}
	for _, field := range r.metadata {
		values, ok := field.([]any)
		if !ok || len(values) > walletadapter.MaxRecipients-len(out) {
			return nil, false
		}
		for _, value := range values {
			s, ok := value.(string)
			if !ok || s == "" {
				return nil, false
			}
			if !identity.ValidActorID(s) {
				if _, err := walletops.ParseAddress(s); err != nil {
					return nil, false
				}
			}
			out = append(out, s)
		}
	}
	return out, true
}
