package rpcengine

import (
	"encoding/json"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/rpcenvelope"
	"privacy-proxy/internal/rpcmethoddata"
)

type minedTraceRequest struct {
	id           json.RawMessage
	notification bool
	method       string
	hash         common.Hash
}

func strictMinedConfig(v any) bool {
	if v == nil {
		return true
	}
	m, ok := v.(map[string]any)
	if !ok || m["tracer"] != "callTracer" {
		return false
	}
	if _, ok := traceFold(m); !ok {
		return false
	}
	for name, value := range m {
		switch name {
		case "tracer":
		case "tracerConfig":
			c, ok := value.(map[string]any)
			if !ok {
				return false
			} // Nested null is rejected by V1's composed gate.
			if _, ok := traceFold(c); !ok {
				return false
			}
			for k, v := range c {
				if k == "onlyTopCall" && v == true || k == "withLog" && v == false {
					continue
				}
				return false
			}
		default:
			return false
		}
	}
	return true
}
func (e *Engine) parseMinedTrace(raw []byte) (minedTraceRequest, int) {
	q := minedTraceRequest{id: json.RawMessage("null")}
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
	var hasID bool
	q.id, hasID = env.IDJSON()
	q.notification = !hasID
	if q.notification {
		q.id = json.RawMessage("null")
	}
	name := env.Method()
	if canonical, builtin := rpcmethoddata.CanonicalBuiltin(name); builtin {
		name = canonical
	}
	if e == nil || e.mined == nil || !e.mined.methods[name] {
		return q, -32601
	}
	q.method = name
	v, err := readClientTraceParams(env.ParamsJSON())
	if err != nil {
		return q, -32602
	}
	params, ok := v.([]any)
	if !ok || len(params) < 1 || len(params) > 2 {
		return q, -32602
	}
	h, ok := params[0].(string)
	if !ok || len(h) != 66 || !traceHex(h, true) {
		return q, -32602
	}
	q.hash = common.HexToHash(strings.ToLower(h))
	if q.hash == (common.Hash{}) {
		return q, -32602
	}
	if len(params) == 2 {
		if !vetClientTraceConfig(params[1]) || e.mined.profile.Strict() && !strictMinedConfig(params[1]) {
			return q, -32602
		}
	}
	return q, 0
}
