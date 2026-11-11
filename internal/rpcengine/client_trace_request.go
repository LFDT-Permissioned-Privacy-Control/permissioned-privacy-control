package rpcengine

import (
	"bytes"
	"encoding/json"
	"github.com/ethereum/go-ethereum/common"
	"io"
	"math/big"
	"privacy-proxy/internal/rpcenvelope"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/rpcmethoddata"
	"privacy-proxy/internal/strictjson"
	"strings"
)

type clientTraceRequest struct {
	id           json.RawMessage
	notification bool
	method       string
	call         rpcexecution.Call
	block        rpcexecution.BlockSelector
}

func traceFold(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	out := map[string]any{}
	for k, v := range m {
		k = strings.ToLower(k)
		if _, dup := out[k]; dup {
			return nil, false
		}
		out[k] = v
	}
	return out, true
}
func traceHex(s string, bytes bool) bool {
	if len(s) < 2 || !strings.EqualFold(s[:2], "0x") || bytes && len(s)%2 != 0 {
		return false
	}
	if !bytes && (len(s) < 3 || len(s) > 66) {
		return false
	}
	for _, c := range s[2:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}
func canonicalClientTraceCall(v any) ([]byte, error) {
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, errOperation
	}
	if _, ok := traceFold(obj); !ok {
		return nil, errOperation
	}
	out := map[string]any{}
	for _, key := range []string{"from", "to"} {
		raw, has := obj[key]
		if !has || key == "to" && raw == nil {
			continue
		}
		s, ok := raw.(string)
		if !ok {
			return nil, errOperation
		}
		if s == "" || key == "to" && strings.EqualFold(s, "0x") {
			continue
		}
		if len(s) != 42 || !common.IsHexAddress(s) {
			return nil, errOperation
		}
		out[key] = strings.ToLower(common.HexToAddress(s).Hex())
	}
	data, hd := obj["data"]
	input, hi := obj["input"]
	ds, is := "", ""
	if hd {
		var ok bool
		ds, ok = data.(string)
		if !ok {
			return nil, errOperation
		}
	}
	if hi {
		var ok bool
		is, ok = input.(string)
		if !ok {
			return nil, errOperation
		}
	}
	if hd && hi && !strings.EqualFold(ds, is) {
		return nil, errOperation
	}
	if !hd {
		ds = is
	}
	if ds != "" {
		if !traceHex(ds, true) {
			return nil, errOperation
		}
		out["data"] = "0x" + strings.ToLower(ds[2:])
	}
	if raw, has := obj["value"]; has {
		s, ok := raw.(string)
		if !ok {
			return nil, errOperation
		}
		if s != "" {
			if !traceHex(s, false) {
				return nil, errOperation
			}
			n, ok := new(big.Int).SetString(s[2:], 16)
			if !ok {
				return nil, errOperation
			}
			out["value"] = "0x" + n.Text(16)
		}
	}
	return json.Marshal(out)
}
func vetClientTraceConfig(v any) bool {
	if v == nil {
		return true
	}
	m, ok := traceFold(v)
	if !ok {
		return false
	}
	for _, k := range []string{"stateoverrides", "stateoverride", "blockoverrides", "blockoverride", "txindex"} {
		if _, has := m[k]; has {
			return false
		}
	}
	if tr, has := m["tracer"]; has {
		if tr != "callTracer" {
			return false
		}
	} else {
		for _, k := range []string{"enablememory", "disablestorage", "disablestack", "enablereturndata", "debug", "limit"} {
			if _, has := m[k]; has {
				return false
			}
		}
	}
	if tc, has := m["tracerconfig"]; has {
		c, ok := traceFold(tc)
		if !ok {
			return false
		}
		if wl, has := c["withlog"]; has {
			b, ok := wl.(bool)
			if !ok || b {
				return false
			}
		}
	}
	return true
}
func (e *Engine) parseClientTrace(raw []byte) (clientTraceRequest, int) {
	q := clientTraceRequest{id: json.RawMessage("null")}
	env, err := rpcenvelope.ParseRaw(raw, rpcenvelope.DefaultLimits())
	if err != nil {
		return q, -32600
	}
	if v := env.VersionJSON(); len(v) > 0 {
		var s string
		if json.Unmarshal(v, &s) != nil || s != "2.0" {
			return q, -32600
		}
	}
	q.id, q.notification = env.IDJSON()
	q.notification = !q.notification
	if q.notification {
		q.id = json.RawMessage("null")
	}
	name := env.Method()
	if c, builtin := rpcmethoddata.CanonicalBuiltin(name); builtin {
		name = c
	}
	if e == nil || !e.traceMethods[name] {
		return q, -32601
	}
	q.method = name
	v, err := readClientTraceParams(env.ParamsJSON())
	if err != nil {
		return q, -32602
	}
	params, ok := v.([]any)
	if !ok || len(params) < 1 || len(params) > 3 {
		return q, -32602
	}
	if len(params) == 3 && !vetClientTraceConfig(params[2]) {
		return q, -32602
	}
	call, err := canonicalClientTraceCall(params[0])
	if err != nil {
		return q, -32602
	}
	q.call, err = rpcexecution.NormalizeSimulationCall(call)
	if err != nil {
		return q, -32602
	}
	var block []byte
	if len(params) > 1 && params[1] != nil {
		block, _ = json.Marshal(params[1])
	}
	q.block, err = rpcexecution.ParseBlockSelector(block)
	if err != nil {
		return q, -32602
	}
	return q, 0
}

func readClientTraceParams(raw []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, err := strictjson.ReadValue(d, 0, 32)
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errOperation
	}
	return v, nil
}
