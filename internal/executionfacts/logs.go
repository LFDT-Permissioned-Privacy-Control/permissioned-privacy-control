package executionfacts

import (
	"encoding/hex"
	"encoding/json"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
)

func (p *decoder) logs(record int) ([]Log, error) {
	token, err := p.json.Token()
	if err != nil || token != json.Delim('[') {
		return nil, fail(InvalidTrace, record, "logs", "logs must be a nonnull array")
	}
	logs := []Log{}
	for p.json.More() {
		if p.logsUsed >= p.limits.MaxLogs {
			return nil, fail(LimitExceeded, record, "logs", "log count exceeds budget")
		}
		p.logsUsed++
		log, err := p.log(record)
		if err != nil {
			return nil, err
		}
		logs = append(logs, log)
	}
	if token, err := p.json.Token(); err != nil || token != json.Delim(']') {
		return nil, fail(InvalidTrace, record, "logs", "unterminated log array")
	}
	return logs, nil
}

func (p *decoder) log(record int) (Log, error) {
	var result Log
	token, err := p.json.Token()
	if err != nil || token != json.Delim('{') {
		return result, fail(InvalidTrace, record, "logs", "log must be an object")
	}
	seen := map[string]bool{}
	for p.json.More() {
		token, err := p.json.Token()
		field, ok := token.(string)
		if err != nil || !ok {
			return result, fail(InvalidTrace, record, "logs", "invalid log field")
		}
		switch field {
		case "address", "topics", "data", "position", "index":
		default:
			return result, fail(InvalidTrace, record, "logs", "unsupported log field")
		}
		if seen[field] {
			return result, fail(InvalidTrace, record, "logs", "duplicate log field")
		}
		seen[field] = true
		if field == "topics" {
			topics, err := p.topics(record)
			if err != nil {
				return result, err
			}
			result.Topics = topics
			continue
		}
		token, err = p.json.Token()
		value, ok := token.(string)
		if err != nil || !ok {
			return result, fail(InvalidTrace, record, "logs", "log field must be a nonnull string")
		}
		switch field {
		case "address":
			address, ok := parseAddress(value)
			if !ok {
				return result, fail(InvalidTrace, record, "logs.address", "invalid log address")
			}
			result.Address = address
		case "data":
			if len(value) < 2 || value[:2] != "0x" || len(value)%2 != 0 {
				return result, fail(InvalidTrace, record, "logs.data", "invalid log data")
			}
			size := (len(value) - 2) / 2
			if size > p.limits.MaxAggregateLogBytes-p.logBytes {
				return result, fail(LimitExceeded, record, "logs.data", "log bytes exceed budget")
			}
			data, err := hex.DecodeString(value[2:])
			if err != nil {
				return result, fail(InvalidTrace, record, "logs.data", "invalid log data")
			}
			result.Data = data
			p.logBytes += size
		case "position", "index":
			if !quantity(value, 64) {
				return result, fail(InvalidTrace, record, "logs", "log position/index must be uint64 hex")
			}
			number, _ := strconv.ParseUint(value[2:], 16, 64)
			if field == "position" {
				result.Position = number
			} else {
				result.Index = &number
			}
		}
	}
	if token, err := p.json.Token(); err != nil || token != json.Delim('}') {
		return result, fail(InvalidTrace, record, "logs", "unterminated log")
	}
	for _, required := range []string{"address", "topics", "data", "position"} {
		if !seen[required] {
			return result, fail(InvalidTrace, record, "logs", "required log field missing")
		}
	}
	return result, nil
}

func (p *decoder) topics(record int) ([]common.Hash, error) {
	token, err := p.json.Token()
	if err != nil || token != json.Delim('[') {
		return nil, fail(InvalidTrace, record, "logs.topics", "topics must be a nonnull array")
	}
	result := []common.Hash{}
	for p.json.More() {
		if len(result) >= 4 {
			return nil, fail(InvalidTrace, record, "logs.topics", "more than four log topics")
		}
		token, err := p.json.Token()
		value, ok := token.(string)
		if err != nil || !ok || len(value) != 66 || value[:2] != "0x" {
			return nil, fail(InvalidTrace, record, "logs.topics", "topic must contain 32 hex bytes")
		}
		data, err := hex.DecodeString(value[2:])
		if err != nil {
			return nil, fail(InvalidTrace, record, "logs.topics", "invalid topic")
		}
		result = append(result, common.BytesToHash(data))
	}
	if token, err := p.json.Token(); err != nil || token != json.Delim(']') {
		return nil, fail(InvalidTrace, record, "logs.topics", "unterminated topic array")
	}
	return result, nil
}
