package privado

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/iden3/go-circuits/v2"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/iden3comm/v2/packers"
	"github.com/iden3/iden3comm/v2/protocol"
)

type stateKey struct{ network, id, state string }
type parsed struct {
	response            protocol.AuthorizationResponseMessage
	holderID            core.ID
	holderNetwork, gist string
	roles               map[stateKey]bool // true means a required nonrevocation lookup
	claimsAsOf          int64
}

// Structural parsing limits apply before SDK/base-field/bigint work. Inputs
// remain untrusted: only real FullVerify can turn any of them into evidence.
func parseCompact(compact string, req protocol.AuthorizationRequestMessage, profile selectedProfile, now int64) (parsed, error) {
	var result parsed
	if len(compact) == 0 || len(compact) > MaxCompactBytes || strings.Count(compact, ".") != 2 {
		return result, ErrEvidence
	}
	parts := strings.Split(compact, ".")
	nodes := 0
	header, err := decodeObjectSegment(parts[0], 2<<10, &nodes)
	if err != nil {
		return result, err
	}
	if !keys(header, []string{"alg", "circuitId", "typ", "crit"}, nil) || header["alg"] != "groth16" || header["circuitId"] != "authV2" || header["typ"] != string(packers.MediaTypeZKPMessage) {
		return result, ErrEvidence
	}
	crit, ok := header["crit"].([]any)
	if !ok || len(crit) != 1 || crit[0] != "circuitId" {
		return result, ErrEvidence
	}
	payload, err := decodeObjectSegment(parts[1], 512<<10, &nodes)
	if err != nil {
		return result, err
	}
	outer, err := decodeObjectSegment(parts[2], 16<<10, &nodes)
	if err != nil {
		return result, err
	}
	outerSignals, err := zkProof(outer, 3)
	if err != nil {
		return result, err
	}
	var auth circuits.AuthV2PubSignals
	signalsJSON, _ := json.Marshal(outerSignals)
	if auth.PubSignalsUnmarshal(signalsJSON) != nil || auth.UserID == nil || auth.GISTRoot == nil {
		return result, ErrEvidence
	}
	if !keys(payload, []string{"id", "type", "thid", "body", "from", "to"}, []string{"typ", "created_time", "expires_time", "attachments"}) {
		return result, ErrEvidence
	}
	id, idOK := payload["id"].(string)
	thread, threadOK := payload["thid"].(string)
	from, fromOK := payload["from"].(string)
	if !idOK || !threadOK || !fromOK || !canonicalUUID(id) || !canonicalUUID(thread) || thread != req.ID || payload["type"] != string(protocol.AuthorizationResponseMessageType) || payload["to"] != req.From {
		return result, ErrEvidence
	}
	if typ, present := payload["typ"]; present && typ != string(packers.MediaTypeZKPMessage) && typ != string(packers.MediaTypePlainMessage) {
		return result, ErrEvidence
	}
	if v, present := payload["created_time"]; present {
		n, valid := integer(v, 253402300799)
		if !valid || n > now+30 {
			return result, ErrEvidence
		}
	}
	if v, present := payload["expires_time"]; present {
		n, valid := integer(v, 253402300799)
		if !valid || n <= now {
			return result, ErrEvidence
		}
	}
	if v, present := payload["attachments"]; present {
		list, ok := v.([]any)
		if !ok || len(list) > 4 {
			return result, ErrEvidence
		}
		for _, entry := range list {
			if _, ok := entry.(map[string]any); !ok || jsonSize(entry) > 8<<10 {
				return result, ErrEvidence
			}
		}
	}
	body, ok := payload["body"].(map[string]any)
	if !ok || !keys(body, []string{"message", "scope"}, []string{"did_doc"}) || body["message"] != req.Body.Message {
		return result, ErrEvidence
	}
	if v, present := body["did_doc"]; present {
		if _, ok := v.(map[string]any); !ok || jsonSize(v) > 8<<10 {
			return result, ErrEvidence
		}
	}
	holderID, holderNetwork, err := parseIdentityDID(from)
	if err != nil || holderNetwork != profile.source.Network || holderID != *auth.UserID {
		return result, ErrEvidence
	}
	result = parsed{holderID: holderID, holderNetwork: holderNetwork, gist: auth.GISTRoot.BigInt().String(), roles: map[stateKey]bool{}, claimsAsOf: min(*req.CreatedTime, now)}
	scope, ok := body["scope"].([]any)
	if !ok || len(scope) != len(req.Body.Scope) || len(scope) > MaxPredicates {
		return parsed{}, ErrEvidence
	}
	seen := map[uint32]bool{}
	for _, value := range scope {
		proof, ok := value.(map[string]any)
		if !ok || !keys(proof, []string{"id", "circuitId", "proof", "pub_signals"}, []string{"vp"}) || proof["circuitId"] != "credentialAtomicQuerySigV2" {
			return parsed{}, ErrEvidence
		}
		proofID, ok := integer(proof["id"], 1<<32-1)
		if !ok || proofID < 1 || proofID > int64(len(scope)) || seen[uint32(proofID)] {
			return parsed{}, ErrEvidence
		}
		seen[uint32(proofID)] = true
		if v, present := proof["vp"]; present && v != nil {
			if _, ok := v.(map[string]any); !ok || jsonSize(v) > 16<<10 {
				return parsed{}, ErrEvidence
			}
		}
		signals, err := proofSignals(proof, 77)
		if err != nil {
			return parsed{}, err
		}
		var sig circuits.AtomicQuerySigV2PubSignals
		raw, _ := json.Marshal(signals)
		if sig.PubSignalsUnmarshal(raw) != nil || sig.UserID == nil || sig.IssuerID == nil || sig.IssuerAuthState == nil || sig.IssuerClaimNonRevState == nil || sig.RequestID == nil || sig.RequestID.Cmp(big.NewInt(proofID)) != 0 || *sig.UserID != holderID || sig.IsRevocationChecked != 1 || !roleTimeCurrent(sig.Timestamp, *req.CreatedTime, now) {
			return parsed{}, ErrEvidence
		}
		issuerDID, err := core.ParseDIDFromID(*sig.IssuerID)
		if err != nil || !contains(profile.source.AllowedCredentialIssuers, issuerDID.String()) {
			return parsed{}, ErrEvidence
		}
		network := networkOf(*sig.IssuerID)
		if network == "" {
			return parsed{}, ErrEvidence
		}
		authKey := stateKey{network, sig.IssuerID.BigInt().String(), sig.IssuerAuthState.BigInt().String()}
		if _, exists := result.roles[authKey]; !exists {
			result.roles[authKey] = false
		}
		result.roles[stateKey{network, sig.IssuerID.BigInt().String(), sig.IssuerClaimNonRevState.BigInt().String()}] = true
		result.claimsAsOf = min(result.claimsAsOf, sig.Timestamp)
	}
	raw, _ := json.Marshal(payload)
	if json.Unmarshal(raw, &result.response) != nil {
		return parsed{}, ErrEvidence
	}
	return result, nil
}

func roleTimeCurrent(at, created, now int64) bool {
	return at >= 0 && at >= created-30 && at <= now+30 && at+300 > now
}

func proofSignals(v map[string]any, count int) ([]string, error) {
	p, ok := v["proof"].(map[string]any)
	if !ok || !keys(p, []string{"pi_a", "pi_b", "pi_c", "protocol"}, []string{"curve"}) || p["protocol"] != "groth16" {
		return nil, ErrEvidence
	}
	if curve, present := p["curve"]; present && curve != "bn128" {
		return nil, ErrEvidence
	}
	field := fp.Modulus()
	for _, key := range []string{"pi_a", "pi_c"} {
		values, ok := p[key].([]any)
		if !ok || len(values) != 3 {
			return nil, ErrEvidence
		}
		for _, value := range values {
			if !fieldNumber(value, field) {
				return nil, ErrEvidence
			}
		}
	}
	b, ok := p["pi_b"].([]any)
	if !ok || len(b) != 3 {
		return nil, ErrEvidence
	}
	for _, row := range b {
		values, ok := row.([]any)
		if !ok || len(values) != 2 {
			return nil, ErrEvidence
		}
		for _, v := range values {
			if !fieldNumber(v, field) {
				return nil, ErrEvidence
			}
		}
	}
	values, ok := v["pub_signals"].([]any)
	if !ok || len(values) != count {
		return nil, ErrEvidence
	}
	out := make([]string, count)
	scalar := fr.Modulus()
	for i, v := range values {
		if !fieldNumber(v, scalar) {
			return nil, ErrEvidence
		}
		out[i] = v.(string)
	}
	return out, nil
}
func zkProof(v map[string]any, count int) ([]string, error) {
	if !keys(v, []string{"proof", "pub_signals"}, nil) {
		return nil, ErrEvidence
	}
	return proofSignals(v, count)
}
func fieldNumber(v any, modulus *big.Int) bool {
	s, ok := v.(string)
	if !ok || !decimal(s, 78) {
		return false
	}
	n, ok := new(big.Int).SetString(s, 10)
	return ok && n.Sign() >= 0 && n.Cmp(modulus) < 0
}
func keys(v map[string]any, required, optional []string) bool {
	if len(v) < len(required) || len(v) > len(required)+len(optional) {
		return false
	}
	allowed := map[string]bool{}
	for _, k := range required {
		if _, ok := v[k]; !ok {
			return false
		}
		allowed[k] = true
	}
	for _, k := range optional {
		allowed[k] = true
	}
	for k := range v {
		if !allowed[k] {
			return false
		}
	}
	return true
}
func contains(values []string, s string) bool {
	for _, v := range values {
		if v == s {
			return true
		}
	}
	return false
}
func integer(v any, max int64) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok || !decimal(n.String(), 20) {
		return 0, false
	}
	i, e := strconv.ParseInt(n.String(), 10, 64)
	return i, e == nil && i >= 0 && i <= max
}
func jsonSize(v any) int {
	b, e := json.Marshal(v)
	if e != nil {
		return MaxCompactBytes + 1
	}
	return len(b)
}
func decodeObjectSegment(s string, max int, nodes *int) (map[string]any, error) {
	if len(s) == 0 || len(s) > base64.RawURLEncoding.EncodedLen(max) {
		return nil, ErrEvidence
	}
	raw, e := base64.RawURLEncoding.Strict().DecodeString(s)
	if e != nil || len(raw) > max || base64.RawURLEncoding.EncodeToString(raw) != s {
		return nil, ErrEvidence
	}
	v, e := readJSON(raw, max, nodes)
	if e != nil {
		return nil, e
	}
	o, ok := v.(map[string]any)
	if !ok {
		return nil, ErrEvidence
	}
	return o, nil
}
func readJSON(raw []byte, max int, nodes *int) (any, error) {
	if len(raw) > max || !utf8.Valid(raw) {
		return nil, ErrEvidence
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, e := readValue(d, 0, nodes)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, ErrEvidence
	}
	return v, nil
}
func readValue(d *json.Decoder, depth int, nodes *int) (any, error) {
	*nodes++
	if depth > 16 || *nodes > 8192 {
		return nil, ErrEvidence
	}
	token, e := d.Token()
	if e != nil {
		return nil, ErrEvidence
	}
	switch token := token.(type) {
	case json.Delim:
		switch token {
		case '{':
			out := map[string]any{}
			for d.More() {
				if len(out) >= 64 {
					return nil, ErrEvidence
				}
				key, e := d.Token()
				if e != nil {
					return nil, ErrEvidence
				}
				s, ok := key.(string)
				if !ok || len(s) > 128 {
					return nil, ErrEvidence
				}
				if _, dup := out[s]; dup {
					return nil, ErrEvidence
				}
				value, e := readValue(d, depth+1, nodes)
				if e != nil {
					return nil, e
				}
				out[s] = value
			}
			if _, e := d.Token(); e != nil {
				return nil, ErrEvidence
			}
			return out, nil
		case '[':
			out := []any{}
			for d.More() {
				if len(out) >= 128 {
					return nil, ErrEvidence
				}
				value, e := readValue(d, depth+1, nodes)
				if e != nil {
					return nil, e
				}
				out = append(out, value)
			}
			if _, e := d.Token(); e != nil {
				return nil, ErrEvidence
			}
			return out, nil
		default:
			return nil, ErrEvidence
		}
	case string:
		if len(token) > 8192 {
			return nil, ErrEvidence
		}
	case json.Number:
		if len(token) > 78 {
			return nil, ErrEvidence
		}
	}
	return token, nil
}
