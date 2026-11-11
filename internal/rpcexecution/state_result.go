package rpcexecution

// stateResult validates structure and request pairing, retaining the wire-owned
// bytes. A Merkle proof's opaque nodes can contain unrequested inlined leaves;
// this validator supplies no proof-node confidentiality or permission verdict.
func stateResult(q StateQuery, raw []byte, l StateLimits) ([]byte, error) {
	if !q.validFor(l) || int64(len(raw)) > l.MaxResultBytes {
		return nil, failure(EvidenceLimit)
	}
	remainingNodes := l.MaxTotalProofNodes
	v, err := readJSONFieldArrays(raw, func(depth int, field string) int {
		if q.method != StateProof {
			return 0
		}
		if depth == 1 && field == "accountProof" || depth == 3 && field == "proof" {
			if remainingNodes <= 0 {
				return 0
			}
			remainingNodes-- // The callback is evaluated before each append.
			return l.MaxProofNodesPerProof
		}
		if depth == 1 && field == "storageProof" {
			return l.MaxStorageKeys
		}
		return 0
	})
	if err != nil {
		return nil, err
	}
	ok := false
	switch q.method {
	case StateBalance:
		ok = metadataQuantity(v, 256)
	case StateNonce:
		ok = metadataQuantity(v, 64)
	case StateStorage:
		ok = stateData(v, 32, 32)
	case StateCode:
		ok = stateData(v, 0, l.MaxCodeBytes)
	case StateProof:
		ok = stateProofResult(q, v, l)
	}
	if !ok {
		return nil, failure(InvalidEvidence)
	}
	return raw, nil
}

func stateData(v any, min, max int) bool {
	s, ok := v.(string)
	if !ok || len(s) < 2 || len(s)%2 != 0 {
		return false
	}
	n := (len(s) - 2) / 2
	if n < min || n > max {
		return false
	}
	_, ok = data(s)
	return ok
}

func stateProofResult(q StateQuery, v any, l StateLimits) bool {
	object, ok := v.(map[string]any)
	if !ok || len(object) != 7 {
		return false
	}
	for _, key := range []string{"address", "accountProof", "balance", "codeHash", "nonce", "storageHash", "storageProof"} {
		if _, exists := object[key]; !exists {
			return false
		}
	}
	text, ok := object["address"].(string)
	target, valid := address(text)
	if !ok || !valid || target != q.target || !metadataQuantity(object["balance"], 256) ||
		!metadataQuantity(object["nonce"], 64) || !stateData(object["codeHash"], 32, 32) ||
		!stateData(object["storageHash"], 32, 32) {
		return false
	}
	usage := stateProofUsage{}
	if !usage.nodes(object["accountProof"], true, l) {
		return false
	}
	rows, ok := object["storageProof"].([]any)
	if !ok || len(rows) != len(q.keys) {
		return false
	}
	for i, row := range rows {
		entry, ok := row.(map[string]any)
		if !ok || len(entry) != 3 || entry["key"] == nil || entry["value"] == nil {
			return false
		}
		proof, exists := entry["proof"]
		if !exists || !stateProofKey(entry["key"], q.keys[i]) || !metadataQuantity(entry["value"], 256) || !usage.nodes(proof, false, l) {
			return false
		}
	}
	return true
}

func stateProofKey(v any, expected StateStorageKey) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	if expected.InputBytes == 32 {
		if !stateData(s, 32, 32) {
			return false
		}
		key, _, valid := stateStorageKey(s)
		return valid && key.Value == expected.Value
	}
	if !metadataQuantity(v, 256) {
		return false
	}
	key, _, valid := stateStorageKey(s)
	return valid && key.Value == expected.Value
}

type stateProofUsage struct{ count, bytes int }

func (u *stateProofUsage) nodes(v any, allowNull bool, l StateLimits) bool {
	if v == nil {
		return allowNull
	}
	items, ok := v.([]any)
	if !ok || len(items) > l.MaxProofNodesPerProof || len(items) > l.MaxTotalProofNodes-u.count {
		return false
	}
	u.count += len(items)
	for _, item := range items {
		s, ok := item.(string)
		if !ok || len(s) < 2 || len(s)%2 != 0 {
			return false
		}
		n := (len(s) - 2) / 2
		if n > l.MaxProofNodeBytes || n > l.MaxTotalProofBytes-u.bytes || !stateData(s, 0, l.MaxProofNodeBytes) {
			return false
		}
		u.bytes += n
	}
	return true
}
