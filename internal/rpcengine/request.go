package rpcengine

import (
	"bytes"
	"encoding/json"
	"io"

	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/strictjson"
)

const MaxRequestBytes = 1 << 20

type request struct {
	id    json.RawMessage
	call  rpcexecution.Call
	block rpcexecution.BlockSelector
}

func parseRequest(raw []byte) (request, *RPCError) {
	bad := func(code int, message string) (request, *RPCError) {
		return request{}, &RPCError{Code: code, Message: message}
	}
	if len(raw) > MaxRequestBytes {
		return bad(-32600, "invalid request")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, err := strictjson.ReadValue(d, 0, 32)
	if err != nil {
		return bad(-32600, "invalid request")
	}
	if _, err = d.Token(); err != io.EOF {
		return bad(-32600, "invalid request")
	}
	m, ok := v.(map[string]any)
	if !ok || len(m) != 4 {
		return bad(-32600, "invalid request")
	}
	for key := range m {
		if key != "jsonrpc" && key != "id" && key != "method" && key != "params" {
			return bad(-32600, "invalid request")
		}
	}
	if m["jsonrpc"] != "2.0" {
		return bad(-32600, "invalid request")
	}
	if _, ok := m["id"]; !ok {
		return bad(-32600, "invalid request")
	}
	switch m["id"].(type) {
	case nil, string, json.Number:
	default:
		return bad(-32600, "invalid request")
	}
	id, _ := json.Marshal(m["id"])
	method, ok := m["method"].(string)
	if !ok {
		return bad(-32600, "invalid request")
	}
	if method != "eth_call" {
		return request{id: id}, &RPCError{Code: -32601, Message: "method not found"}
	}
	params, ok := m["params"].([]any)
	if !ok || len(params) < 1 || len(params) > 2 {
		return request{id: id}, &RPCError{Code: -32602, Message: "invalid params"}
	}
	callRaw, _ := json.Marshal(params[0])
	call, err := rpcexecution.NormalizeCall(callRaw)
	if err != nil {
		return request{id: id}, &RPCError{Code: -32602, Message: "invalid params"}
	}
	var blockRaw []byte
	if len(params) == 2 {
		blockRaw, _ = json.Marshal(params[1])
	}
	block, err := rpcexecution.ParseBlockSelector(blockRaw)
	if err != nil {
		return request{id: id}, &RPCError{Code: -32602, Message: "unsupported or invalid block selector"}
	}
	return request{id: id, call: call, block: block}, nil
}
