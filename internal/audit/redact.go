package audit

import "encoding/json"

// RedactParams returns a JSON representation of request parameters with sensitive data redacted.
// Redaction strategy by method:
//   - eth_sendRawTransaction: truncate raw tx hex to 20 chars
//   - eth_sendTransaction: keep from/to/value/gas, truncate data to 10 chars
//   - eth_call, eth_estimateGas: keep from/to/value, truncate data to 10 chars
//   - eth_getLogs: redact filter — keep blocks, redact addresses & topics
//   - eth_getStorageAt: keep address, redact slot
//   - All other methods: params replaced with a placeholder sentinel.
//
// M22 (security audit): pre-fix, unknown methods were passed through
// verbatim. AUDIT_LOG_PARAMS defaults to off so the risk only existed
// when opted in, but the silent verbatim pass-through made the toggle
// dangerous (any new method exposing sensitive arguments would land in
// the audit log without a code-review heads-up). Now the default for
// unknown methods is a `{"_redacted":"unknown method"}` sentinel, so
// adding a method to the allowlist is a deliberate code change rather
// than a silent default.
func RedactParams(method string, params []any) []byte {
	if len(params) == 0 {
		return nil
	}

	switch method {
	case "eth_sendRawTransaction":
		return redactSendRawTransaction(params)
	case "eth_sendTransaction":
		return redactSendTransaction(params)
	case "eth_call", "eth_estimateGas":
		return redactCallLike(params)
	case "eth_getLogs":
		return redactGetLogs(params)
	case "eth_getStorageAt":
		return redactGetStorageAt(params)
	case "eth_getBalance",
		"eth_getCode",
		"eth_getTransactionCount",
		"eth_getTransactionByHash",
		"eth_getTransactionReceipt",
		"eth_getBlockByHash",
		"eth_getBlockByNumber",
		"eth_getBlockReceipts",
		"eth_blockNumber",
		"eth_chainId",
		"eth_gasPrice",
		"net_version":
		// Safe to log verbatim — params are public chain identifiers
		// (block numbers, tx hashes, public addresses for balance
		// queries). Documented allowlist.
		out, err := json.Marshal(params)
		if err != nil {
			return nil
		}
		return out
	default:
		// M22: fail-closed default. Unknown methods are NOT echoed —
		// adding a method to the allowlist above is a deliberate code
		// change. The slog entry still records the method name.
		out, _ := json.Marshal(map[string]any{"_redacted": "unsupported method"})
		return out
	}
}

// redactGetLogs strips addresses and topics from the eth_getLogs filter.
// Block-range fields and the raw topic-position structure are kept so
// the audit row still indicates the rough shape of the query.
func redactGetLogs(params []any) []byte {
	if len(params) == 0 {
		return nil
	}
	obj, ok := params[0].(map[string]any)
	if !ok {
		out, _ := json.Marshal(params)
		return out
	}
	safe := map[string]any{}
	for _, key := range []string{"fromBlock", "toBlock", "blockHash"} {
		if v, exists := obj[key]; exists {
			safe[key] = v
		}
	}
	if _, exists := obj["address"]; exists {
		safe["address"] = "[REDACTED]"
	}
	if v, exists := obj["topics"]; exists {
		if arr, ok := v.([]any); ok {
			redactedTopics := make([]any, len(arr))
			for i := range arr {
				redactedTopics[i] = "[REDACTED]"
			}
			safe["topics"] = redactedTopics
		} else {
			safe["topics"] = "[REDACTED]"
		}
	}
	redacted := make([]any, len(params))
	copy(redacted, params)
	redacted[0] = safe
	out, err := json.Marshal(redacted)
	if err != nil {
		return nil
	}
	return out
}

// redactGetStorageAt keeps the address (already public if the caller
// has access — the proxy enforces address-level access elsewhere) and
// redacts the storage slot, which can encode sensitive offsets.
func redactGetStorageAt(params []any) []byte {
	if len(params) == 0 {
		return nil
	}
	redacted := make([]any, len(params))
	copy(redacted, params)
	if len(redacted) > 1 {
		redacted[1] = "[REDACTED]"
	}
	out, err := json.Marshal(redacted)
	if err != nil {
		return nil
	}
	return out
}

// redactSendRawTransaction truncates the raw transaction hex to 20 characters.
func redactSendRawTransaction(params []any) []byte {
	if len(params) == 0 {
		return nil
	}

	redacted := make([]any, len(params))
	copy(redacted, params)

	if raw, ok := redacted[0].(string); ok {
		redacted[0] = truncate(raw, 20)
	}

	out, err := json.Marshal(redacted)
	if err != nil {
		return nil
	}
	return out
}

// redactSendTransaction keeps from/to/value/gas and truncates data/input.
func redactSendTransaction(params []any) []byte {
	if len(params) == 0 {
		return nil
	}

	obj, ok := params[0].(map[string]any)
	if !ok {
		out, _ := json.Marshal(params)
		return out
	}

	safe := map[string]any{}
	for _, key := range []string{"from", "to", "value", "gas", "gasPrice"} {
		if v, exists := obj[key]; exists {
			safe[key] = v
		}
	}
	truncateDataField(obj, safe)

	redacted := make([]any, len(params))
	copy(redacted, params)
	redacted[0] = safe

	out, err := json.Marshal(redacted)
	if err != nil {
		return nil
	}
	return out
}

// redactCallLike handles eth_call and eth_estimateGas: keep from/to/value, truncate data/input.
func redactCallLike(params []any) []byte {
	if len(params) == 0 {
		return nil
	}

	obj, ok := params[0].(map[string]any)
	if !ok {
		out, _ := json.Marshal(params)
		return out
	}

	safe := map[string]any{}
	for _, key := range []string{"from", "to", "value", "gas", "gasPrice"} {
		if v, exists := obj[key]; exists {
			safe[key] = v
		}
	}
	truncateDataField(obj, safe)

	// Preserve additional positional params (e.g., block number for eth_call).
	redacted := make([]any, len(params))
	copy(redacted, params)
	redacted[0] = safe

	out, err := json.Marshal(redacted)
	if err != nil {
		return nil
	}
	return out
}

// truncateDataField copies the "data" or "input" field from src to dst, truncated to 10 chars.
func truncateDataField(src, dst map[string]any) {
	for _, key := range []string{"data", "input"} {
		if v, exists := src[key]; exists {
			if s, ok := v.(string); ok {
				dst[key] = truncate(s, 10)
			}
		}
	}
}

// truncate shortens s to maxLen characters and appends "..." if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
