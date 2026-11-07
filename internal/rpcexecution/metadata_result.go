package rpcexecution

import (
	"encoding/json"
	"strings"
	"unicode/utf8"
)

// raw is already exclusively owned by rpcBounded. Keep that ownership after
// validation, avoiding another large copy. The public getter copies separately.
func metadataResult(q MetadataQuery, raw []byte, l MetadataLimits) ([]byte, error) {
	if int64(len(raw)) > l.MaxResultBytes {
		return nil, failure(EvidenceLimit)
	}
	v, err := metadataJSONArrays(raw, func(depth int) int {
		if q.method == MetadataAccounts && depth == 0 {
			return l.MaxAccounts
		}
		if q.method == MetadataFeeHistory {
			if depth == 1 {
				return q.blocks + 1 // fee arrays include the next block
			}
			if depth == 2 {
				return q.percentiles
			}
		}
		return 0
	})
	if err != nil {
		return nil, err
	}
	ok := false
	switch q.method {
	case MetadataBlockNumber:
		ok = metadataQuantity(v, 63)
	case MetadataChainID:
		ok = metadataQuantity(v, 64) && v != "0x0"
	case MetadataPeerCount:
		ok = metadataQuantity(v, 64)
	case MetadataGasPrice, MetadataMaxPriorityFee:
		ok = metadataQuantity(v, 256)
	case MetadataListening:
		_, ok = v.(bool)
	case MetadataNetworkVersion:
		s, valid := v.(string)
		ok = valid && len(s) > 0 && len(s) <= 78
		for _, c := range s {
			ok = ok && c >= '0' && c <= '9'
		}
	case MetadataClientVersion:
		s, valid := v.(string)
		ok = valid && len(s) <= 1024 && utf8.ValidString(s)
		for _, c := range s {
			ok = ok && c >= 0x20 && c != 0x7f
		}
	case MetadataAccounts:
		items, valid := v.([]any)
		ok = valid && len(items) <= l.MaxAccounts
		if !ok {
			break
		}
		for i, item := range items {
			s, valid := item.(string)
			_, validAddress := address(s)
			if !valid || !validAddress {
				ok = false
				break
			}
			items[i] = strings.ToLower(s)
		}
		if ok {
			raw, err = json.Marshal(items)
			if err != nil || int64(len(raw)) > l.MaxResultBytes {
				return nil, failure(EvidenceLimit)
			}
		}
	case MetadataSyncing:
		if b, valid := v.(bool); valid {
			ok = !b
			break
		}
		object, valid := v.(map[string]any)
		ok = valid
		for _, name := range []string{"startingBlock", "currentBlock", "highestBlock"} {
			ok = ok && object[name] != nil
		}
		for name, value := range object {
			ok = ok && metadataIdentifier(name) && metadataQuantity(value, 256)
		}
	case MetadataFeeHistory:
		ok = metadataFees(v, q)
	}
	if !ok {
		return nil, failure(InvalidEvidence)
	}
	return raw, nil
}

func metadataQuantity(v any, bits int) bool {
	s, ok := v.(string)
	if !ok || s != strings.ToLower(s) {
		return false
	}
	_, ok = quantity(s, bits)
	return ok
}

func metadataIdentifier(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || (i > 0 && c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

func metadataFees(v any, q MetadataQuery) bool {
	m, ok := v.(map[string]any)
	if !ok || !metadataQuantity(m["oldestBlock"], 63) {
		return false
	}
	for k := range m {
		if k != "oldestBlock" && k != "gasUsedRatio" && k != "reward" && k != "baseFeePerGas" && k != "baseFeePerBlobGas" && k != "blobGasUsedRatio" {
			return false
		}
	}
	gas, present := m["gasUsedRatio"]
	if !present {
		return false
	}
	ratios, ok := gas.([]any)
	if gas == nil {
		ratios, ok = []any{}, true
	}
	if !ok || len(ratios) > q.blocks || !metadataRatios(ratios) {
		return false
	}
	n := len(ratios)
	for _, name := range []string{"baseFeePerGas", "baseFeePerBlobGas"} {
		if value, exists := m[name]; exists {
			values, valid := value.([]any)
			if !valid || (len(values) != n+1 && !(n == 0 && len(values) == 0)) {
				return false
			}
			for _, fee := range values {
				if !metadataQuantity(fee, 256) {
					return false
				}
			}
		}
	}
	if value, exists := m["blobGasUsedRatio"]; exists {
		values, valid := value.([]any)
		if !valid || len(values) != n || !metadataRatios(values) {
			return false
		}
	}
	if value, exists := m["reward"]; exists {
		rows, valid := value.([]any)
		if q.percentiles == 0 {
			return valid && len(rows) == 0
		}
		if !valid || len(rows) != n {
			return false
		}
		for _, row := range rows {
			fees, valid := row.([]any)
			if !valid || len(fees) != q.percentiles {
				return false
			}
			for _, fee := range fees {
				if !metadataQuantity(fee, 256) {
					return false
				}
			}
		}
	} else if q.percentiles > 0 && n > 0 {
		return false
	}
	return true
}

func metadataRatios(values []any) bool {
	for _, v := range values {
		f, ok := metadataFloat(v)
		if !ok || f < 0 || f > 1 {
			return false
		}
	}
	return true
}
