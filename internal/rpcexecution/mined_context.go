package rpcexecution

import (
	"encoding/json"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
)

// The fixed flat child comes from the SAME MUX inspector as call/prestate.
// Its explicit replay context binds those two views to the selected envelope;
// flat actions/results never grant permission or enter the public projection.
func validateMinedTraceContext(raw []byte, p *MinedEnvelope) error {
	if p == nil || len(raw) == 0 || len(raw) > 8<<20 {
		return failure(EvidenceLimit)
	}
	value, err := readJSONFieldArrays(raw, func(depth int, field string) int {
		if depth == 0 {
			return 4096
		}
		if field == "traceAddress" {
			return 256
		}
		return 0
	})
	if err != nil {
		return err
	}
	entries, ok := value.([]any)
	if !ok || len(entries) == 0 {
		return failure(InvalidEvidence)
	}
	for i, entry := range entries {
		fields, ok := entry.(map[string]any)
		if !ok || len(fields) > 12 {
			return failure(InvalidEvidence)
		}
		for key := range fields {
			switch key {
			case "action", "result", "error", "subtraces", "traceAddress", "type", "blockHash", "blockNumber", "transactionHash", "transactionPosition":
			default:
				return failure(InvalidEvidence)
			}
		}
		path, ok := fields["traceAddress"].([]any)
		if !ok || (i == 0) != (len(path) == 0) {
			return failure(InvalidEvidence)
		}
		for _, component := range path {
			n, err := minedDecimal(component)
			if err != nil || n >= 4096 {
				return failure(InvalidEvidence)
			}
		}
		if !minedContextHash(fields["blockHash"], p.header.Hash) || !minedContextHash(fields["transactionHash"], p.transaction.Hash()) {
			return failure(InvalidEvidence)
		}
		number, err := minedDecimal(fields["blockNumber"])
		if err != nil || number != p.header.Number {
			return failure(InvalidEvidence)
		}
		index, err := minedDecimal(fields["transactionPosition"])
		if err != nil || index != uint64(p.index) {
			return failure(InvalidEvidence)
		}
	}
	return nil
}

func minedContextHash(value any, wanted common.Hash) bool {
	s, ok := value.(string)
	if !ok || len(s) != 66 {
		return false
	}
	b, ok := data(s)
	return ok && len(b) == 32 && common.BytesToHash(b) == wanted
}
func minedDecimal(value any) (uint64, error) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, failure(InvalidEvidence)
	}
	s := string(number)
	if len(s) == 0 || len(s) > 20 || len(s) > 1 && s[0] == '0' {
		return 0, failure(InvalidEvidence)
	}
	for _, digit := range s {
		if digit < '0' || digit > '9' {
			return 0, failure(InvalidEvidence)
		}
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, failure(InvalidEvidence)
	}
	return n, nil
}
