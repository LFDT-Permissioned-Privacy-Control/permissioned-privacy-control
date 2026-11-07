package rpcexecution

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// CodeInfo is presence-aware owned code. Its byte accessor copies; cheap
// classification/hash accessors avoid repeated code-sized allocations per frame.
type CodeInfo struct {
	code       []byte
	hash       common.Hash
	precompile bool
}

func (c CodeInfo) Bytes() []byte     { return bytes.Clone(c.code) }
func (c CodeInfo) Hash() common.Hash { return c.hash }
func (c CodeInfo) HasCode() bool     { return len(c.code) > 0 }
func (c CodeInfo) Precompile() bool  { return c.precompile }
func (c CodeInfo) Delegated() bool   { return delegation(c.code) }

func closedRawObject(raw []byte, maxFields int) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	opening, err := d.Token()
	if err != nil || opening != json.Delim('{') {
		return nil, failure(InvalidEvidence)
	}
	m := make(map[string]json.RawMessage)
	for d.More() {
		if len(m) >= maxFields {
			return nil, failure(EvidenceLimit)
		}
		key, err := d.Token()
		if err != nil {
			return nil, failure(InvalidEvidence)
		}
		name, ok := key.(string)
		if !ok {
			return nil, failure(InvalidEvidence)
		}
		if _, ok := m[name]; ok {
			return nil, failure(InvalidEvidence)
		}
		var value json.RawMessage
		if err = d.Decode(&value); err != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, failure(InvalidEvidence)
		}
		m[name] = value
	}
	if _, err = d.Token(); err != nil {
		return nil, failure(InvalidEvidence)
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, failure(InvalidEvidence)
	}
	return m, nil
}

func decodeCode(raw json.RawMessage, limit int) ([]byte, error) {
	// Reject oversized hex before the decoder or hex parser allocates code.
	if int64(len(raw)) > 2*int64(limit)+4 {
		return nil, failure(EvidenceLimit)
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return nil, failure(InvalidEvidence)
	}
	if len(s) < 2 || (len(s)-2)/2 > limit {
		return nil, failure(EvidenceLimit)
	}
	b, ok := data(s)
	if !ok {
		return nil, failure(InvalidEvidence)
	}
	return b, nil
}

func decodePrestate(raw []byte, l Limits) (map[common.Address]CodeInfo, int, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	opening, err := d.Token()
	if err != nil || opening != json.Delim('{') {
		return nil, 0, failure(InvalidEvidence)
	}
	accounts := map[common.Address]CodeInfo{}
	total := 0
	for d.More() {
		if len(accounts) >= l.MaxPrestateAccounts {
			return nil, 0, failure(EvidenceLimit)
		}
		key, e := d.Token()
		if e != nil {
			return nil, 0, failure(InvalidEvidence)
		}
		s, ok := key.(string)
		if !ok {
			return nil, 0, failure(InvalidEvidence)
		}
		a, ok := address(s)
		if !ok {
			return nil, 0, failure(InvalidEvidence)
		}
		if _, duplicate := accounts[a]; duplicate {
			return nil, 0, failure(InvalidEvidence)
		}
		var accountRaw json.RawMessage
		if d.Decode(&accountRaw) != nil {
			return nil, 0, failure(InvalidEvidence)
		}
		fields, e := closedRawObject(accountRaw, 4)
		if e != nil {
			return nil, 0, e
		}
		var code []byte
		var declaredHash *common.Hash
		for name, value := range fields {
			switch name {
			case "code":
				code, e = decodeCode(value, min(l.MaxCodeBytesPerAccount, l.MaxTotalCodeBytes-total))
				if e != nil {
					return nil, 0, e
				}
			case "codeHash":
				var s string
				if json.Unmarshal(value, &s) != nil {
					return nil, 0, failure(InvalidEvidence)
				}
				b, ok := data(s)
				if !ok || len(b) != 32 {
					return nil, 0, failure(InvalidEvidence)
				}
				h := common.BytesToHash(b)
				declaredHash = &h
			case "balance":
				var s string
				if json.Unmarshal(value, &s) != nil {
					return nil, 0, failure(InvalidEvidence)
				}
				if _, ok := quantity(s, 256); !ok {
					return nil, 0, failure(InvalidEvidence)
				}
			case "nonce":
				s := string(value)
				if s == "" || len(s) > 20 || (len(s) > 1 && s[0] == '0') {
					return nil, 0, failure(InvalidEvidence)
				}
				for _, r := range s {
					if r < '0' || r > '9' {
						return nil, 0, failure(InvalidEvidence)
					}
				}
				if _, err := strconv.ParseUint(s, 10, 64); err != nil {
					return nil, 0, failure(InvalidEvidence)
				}
			default:
				return nil, 0, failure(InvalidEvidence)
			}
		}
		h := crypto.Keccak256Hash(code)
		if declaredHash != nil && *declaredHash != h {
			return nil, 0, failure(InvalidEvidence)
		}
		if len(code) > l.MaxTotalCodeBytes-total {
			return nil, 0, failure(EvidenceLimit)
		}
		total += len(code)
		accounts[a] = CodeInfo{code: code, hash: h, precompile: precompile(a)}
	}
	if _, err = d.Token(); err != nil {
		return nil, 0, failure(InvalidEvidence)
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, 0, failure(InvalidEvidence)
	}
	return accounts, total, nil
}

func precompile(a common.Address) bool {
	for _, b := range a[:19] {
		if b != 0 {
			return false
		}
	}
	return a[19] >= 1 && a[19] <= 17
}

func delegation(code []byte) bool {
	return len(code) >= 3 && bytes.Equal(code[:3], []byte{0xef, 0x01, 0x00})
}

func headerName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", r)) {
			return false
		}
	}
	switch strings.ToLower(s) {
	case "host", "connection", "content-length", "transfer-encoding", "content-type", "trailer", "upgrade", "proxy-authorization":
		return false
	}
	return true
}
