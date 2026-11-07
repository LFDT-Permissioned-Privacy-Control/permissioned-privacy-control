package rpcexecution

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/transactioninput"
)

type includedPosition struct {
	Hash           common.Hash
	Number         uint64
	Index          uint32
	Timestamp      uint64
	TimestampKnown bool
}

func includedString(raw json.RawMessage, max int) (string, error) {
	// Check the raw envelope before allowing JSON escape expansion/hex work.
	if len(raw) == 0 || len(raw) > 6*max+2 {
		return "", failure(EvidenceLimit)
	}
	var s string
	if json.Unmarshal(raw, &s) != nil || len(s) > max {
		return "", failure(InvalidEvidence)
	}
	return s, nil
}
func includedQuantity(raw json.RawMessage, bits int) (uint64, error) {
	s, err := includedString(raw, 2+(bits+3)/4)
	if err != nil {
		return 0, err
	}
	n, ok := quantity(s, bits)
	if !ok {
		return 0, failure(InvalidEvidence)
	}
	if bits > 64 {
		return 0, nil
	}
	return n.Uint64(), nil
}
func includedData(raw json.RawMessage, size int) ([]byte, error) {
	s, err := includedString(raw, 2+2*size)
	if err != nil {
		return nil, err
	}
	b, ok := data(s)
	if !ok || len(b) != size {
		return nil, failure(InvalidEvidence)
	}
	return b, nil
}
func includedArray(raw json.RawMessage, max int, visit func(json.RawMessage) error) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	t, err := d.Token()
	if err != nil || t != json.Delim('[') {
		return failure(InvalidEvidence)
	}
	count := 0
	for d.More() {
		if count >= max {
			return failure(EvidenceLimit)
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return failure(InvalidEvidence)
		}
		if err := visit(value); err != nil {
			return err
		}
		count++
	}
	if _, err := d.Token(); err != nil {
		return failure(InvalidEvidence)
	}
	if _, err := d.Token(); err != io.EOF {
		return failure(InvalidEvidence)
	}
	return nil
}
func includedAccessList(raw json.RawMessage) error {
	keys := 0
	return includedArray(raw, transactioninput.MaxRawBytes/20, func(entry json.RawMessage) error {
		fields, err := closedRawObject(entry, 2)
		if err != nil || len(fields) != 2 {
			return failure(InvalidEvidence)
		}
		if _, err := includedData(fields["address"], 20); err != nil {
			return err
		}
		return includedArray(fields["storageKeys"], transactioninput.MaxRawBytes/32, func(key json.RawMessage) error {
			keys++
			if keys > transactioninput.MaxRawBytes/32 {
				return failure(EvidenceLimit)
			}
			_, err := includedData(key, 32)
			return err
		})
	})
}
func decodeIncludedPosition(fields map[string]json.RawMessage) (includedPosition, error) {
	var p includedPosition
	nulls := 0
	for _, key := range []string{"blockHash", "blockNumber", "transactionIndex"} {
		raw, ok := fields[key]
		if !ok {
			return p, failure(InvalidEvidence)
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			nulls++
		}
	}
	if nulls == 3 {
		return p, ErrNotIncluded
	}
	if nulls != 0 {
		return p, failure(InvalidEvidence)
	}
	h, err := includedData(fields["blockHash"], 32)
	if err != nil {
		return p, err
	}
	p.Hash = common.BytesToHash(h)
	if p.Hash == (common.Hash{}) {
		return p, failure(InvalidEvidence)
	}
	p.Number, err = includedQuantity(fields["blockNumber"], 63)
	if err != nil {
		return p, err
	}
	index, err := includedQuantity(fields["transactionIndex"], 31)
	if err != nil {
		return p, err
	}
	p.Index = uint32(index)
	if value, ok := fields["blockTimestamp"]; ok {
		p.Timestamp, err = includedQuantity(value, 64)
		if err != nil {
			return p, err
		}
		p.TimestampKnown = true
	}
	return p, nil
}
func decodeIncludedTransaction(raw []byte, wanted common.Hash, chain string) (transactioninput.VerifiedTransaction, includedPosition, error) {
	var zero transactioninput.VerifiedTransaction
	var pos includedPosition
	if len(raw) > 2<<20 {
		return zero, pos, failure(EvidenceLimit)
	}
	fields, err := nullableRawObject(raw, 32, map[string]bool{"to": true, "blockHash": true, "blockNumber": true, "transactionIndex": true, "gasPrice": true, "maxFeePerGas": true, "maxPriorityFeePerGas": true})
	if err != nil {
		return zero, pos, err
	}
	pos, err = decodeIncludedPosition(fields)
	if err != nil {
		return zero, pos, err
	}
	typeID, err := includedQuantity(fields["type"], 8)
	if err != nil {
		return zero, pos, err
	}
	if typeID > 2 {
		return zero, pos, failure(UnsupportedEvidence)
	}
	// Geth's standard JSON encoding emits inapplicable fee variants as null;
	// these do not replace any required field of the selected signed type.
	for _, name := range []string{"gasPrice", "maxFeePerGas", "maxPriorityFeePerGas"} {
		if value, ok := fields[name]; ok && bytes.Equal(bytes.TrimSpace(value), []byte("null")) && ((typeID == 2 && name == "gasPrice") || (typeID < 2 && name != "gasPrice")) {
			delete(fields, name)
		}
	}
	for _, key := range []string{"nonce", "to", "value", "gas", "input", "v", "r", "s", "hash", "from"} {
		if fields[key] == nil {
			return zero, pos, failure(InvalidEvidence)
		}
	}
	allowed := map[string]bool{"type": true, "nonce": true, "to": true, "value": true, "gas": true, "input": true, "v": true, "r": true, "s": true, "hash": true, "from": true, "blockHash": true, "blockNumber": true, "transactionIndex": true, "blockTimestamp": true, "chainId": true, "gasPrice": true, "yParity": true}
	if typeID > 0 {
		allowed["accessList"] = true
		if fields["chainId"] == nil || fields["accessList"] == nil {
			return zero, pos, failure(InvalidEvidence)
		}
	}
	if typeID == 2 {
		allowed["maxFeePerGas"] = true
		allowed["maxPriorityFeePerGas"] = true
		if fields["maxFeePerGas"] == nil || fields["maxPriorityFeePerGas"] == nil {
			return zero, pos, failure(InvalidEvidence)
		}
	} else if fields["gasPrice"] == nil {
		return zero, pos, failure(InvalidEvidence)
	}
	for key, value := range fields {
		if !allowed[key] {
			return zero, pos, failure(InvalidEvidence)
		}
		switch key {
		case "blockHash", "blockNumber", "transactionIndex", "blockTimestamp":
		case "type", "nonce", "gas", "chainId", "yParity":
			bits := 64
			if key == "type" {
				bits = 8
			}
			n, err := includedQuantity(value, bits)
			if err != nil || key == "yParity" && n > 1 {
				return zero, pos, failure(InvalidEvidence)
			}
		case "value", "v", "r", "s", "gasPrice", "maxFeePerGas", "maxPriorityFeePerGas":
			if _, err := includedQuantity(value, 256); err != nil {
				return zero, pos, err
			}
		case "hash":
			b, err := includedData(value, 32)
			if err != nil || common.BytesToHash(b) != wanted {
				return zero, pos, failure(InvalidEvidence)
			}
		case "from":
			if _, err := includedData(value, 20); err != nil {
				return zero, pos, err
			}
		case "to":
			if !bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				if _, err := includedData(value, 20); err != nil {
					return zero, pos, err
				}
			}
		case "input":
			s, err := includedString(value, 2+2*transactioninput.MaxRawBytes)
			if err != nil {
				return zero, pos, err
			}
			if _, ok := data(s); !ok {
				return zero, pos, failure(InvalidEvidence)
			}
		case "accessList":
			if err := includedAccessList(value); err != nil {
				return zero, pos, err
			}
		}
	}
	var tx types.Transaction
	if json.Unmarshal(raw, &tx) != nil {
		return zero, pos, failure(InvalidEvidence)
	}
	binary, err := tx.MarshalBinary()
	if err != nil || len(binary) > transactioninput.MaxRawBytes {
		return zero, pos, failure(EvidenceLimit)
	}
	verified, err := transactioninput.DecodeRaw("0x"+common.Bytes2Hex(binary), chain, transactioninput.ProtectedEVMProfile(), transactioninput.DefaultLimits())
	if err != nil || verified.Hash() != wanted {
		return zero, pos, failure(InvalidEvidence)
	}
	from, _ := includedData(fields["from"], 20)
	if verified.Signer() != common.BytesToAddress(from) {
		return zero, pos, failure(InvalidEvidence)
	}
	if rawChain, ok := fields["chainId"]; ok {
		var text string
		_ = json.Unmarshal(rawChain, &text)
		n, valid := quantity(text, 64)
		if !valid || n.String() != chain {
			return zero, pos, failure(InvalidEvidence)
		}
	}
	return verified, pos, nil
}

func decodeIncludedBlock(raw []byte, wanted includedPosition, txHash common.Hash) (creationfacts.Header, error) {
	if len(raw) > 8<<20 {
		return creationfacts.Header{}, failure(EvidenceLimit)
	}
	fields, err := nullableRawObject(raw, 40, map[string]bool{"baseFeePerGas": true, "withdrawalsRoot": true, "blobGasUsed": true, "excessBlobGas": true, "parentBeaconBlockRoot": true, "requestsHash": true, "totalDifficulty": true, "size": true, "blockAccessListHash": true, "slotNumber": true})
	if err != nil {
		return creationfacts.Header{}, err
	}
	list, ok := fields["transactions"]
	if !ok {
		return creationfacts.Header{}, failure(InvalidEvidence)
	}
	delete(fields, "transactions")
	index := uint32(0)
	found := false
	if err := includedArray(list, (8<<20)/68, func(value json.RawMessage) error {
		b, err := includedData(value, 32)
		if err != nil {
			return err
		}
		if index == wanted.Index {
			if common.BytesToHash(b) != txHash {
				return failure(InvalidEvidence)
			}
			found = true
		}
		index++
		return nil
	}); err != nil || !found {
		if err != nil {
			return creationfacts.Header{}, err
		}
		return creationfacts.Header{}, failure(InvalidEvidence)
	}
	for _, name := range []string{"uncles", "withdrawals"} {
		if value, ok := fields[name]; ok {
			if err := includedArray(value, 8192, func(json.RawMessage) error { return nil }); err != nil {
				return creationfacts.Header{}, err
			}
			delete(fields, name)
		}
	}
	headerRaw, err := json.Marshal(fields)
	if err != nil {
		return creationfacts.Header{}, failure(InvalidEvidence)
	}
	header, err := decodeQualifiedHeader(headerRaw)
	if err != nil || header.Hash != wanted.Hash || header.Number != wanted.Number || wanted.TimestampKnown && header.Timestamp != wanted.Timestamp {
		return creationfacts.Header{}, failure(InvalidEvidence)
	}
	return header, nil
}
func decodeIncludedReceipt(raw []byte, tx transactioninput.VerifiedTransaction, pos includedPosition) (bool, error) {
	if len(raw) > 2<<20 {
		return false, failure(EvidenceLimit)
	}
	fields, err := nullableRawObject(raw, 32, map[string]bool{"to": true, "contractAddress": true})
	if err != nil {
		return false, err
	}
	for _, key := range []string{"transactionHash", "blockHash", "blockNumber", "transactionIndex", "status", "contractAddress", "from", "to"} {
		if fields[key] == nil {
			return false, failure(InvalidEvidence)
		}
	}
	allowed := map[string]bool{"transactionHash": true, "blockHash": true, "blockNumber": true, "transactionIndex": true, "status": true, "contractAddress": true, "from": true, "to": true, "gasUsed": true, "cumulativeGasUsed": true, "effectiveGasPrice": true, "logsBloom": true, "logs": true, "type": true}
	for key, value := range fields {
		if !allowed[key] {
			return false, failure(InvalidEvidence)
		}
		switch key {
		case "transactionHash", "blockHash":
			b, err := includedData(value, 32)
			want := pos.Hash
			if key == "transactionHash" {
				want = tx.Hash()
			}
			if err != nil || common.BytesToHash(b) != want {
				return false, failure(InvalidEvidence)
			}
		case "blockNumber", "transactionIndex", "status", "gasUsed", "cumulativeGasUsed", "type":
			n, err := includedQuantity(value, 64)
			if err != nil {
				return false, err
			}
			if key == "blockNumber" && n != pos.Number || key == "transactionIndex" && n != uint64(pos.Index) || key == "status" && n > 1 || key == "type" && n != uint64(tx.Type()) || key == "gasUsed" && n > tx.Gas() {
				return false, failure(InvalidEvidence)
			}
		case "effectiveGasPrice":
			if _, err := includedQuantity(value, 256); err != nil {
				return false, err
			}
		case "from":
			b, err := includedData(value, 20)
			if err != nil || common.BytesToAddress(b) != tx.Signer() {
				return false, failure(InvalidEvidence)
			}
		case "to":
			to, call := tx.Destination()
			if !call {
				if !bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
					return false, failure(InvalidEvidence)
				}
			} else {
				b, err := includedData(value, 20)
				if err != nil || common.BytesToAddress(b) != to {
					return false, failure(InvalidEvidence)
				}
			}
		case "logsBloom":
			if _, err := includedData(value, 256); err != nil {
				return false, err
			}
		case "logs":
			if err := includedArray(value, 4096, func(json.RawMessage) error { return nil }); err != nil {
				return false, err
			}
		case "contractAddress":
			if !bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				if _, err := includedData(value, 20); err != nil {
					return false, err
				}
			}
		}
	}
	status, err := includedQuantity(fields["status"], 1)
	if err != nil {
		return false, err
	}
	if tx.Creation() && status == 1 {
		b, err := includedData(fields["contractAddress"], 20)
		if err != nil || common.BytesToAddress(b) != crypto.CreateAddress(tx.Signer(), tx.Nonce()) {
			return false, failure(InvalidEvidence)
		}
	} else if !bytes.Equal(bytes.TrimSpace(fields["contractAddress"]), []byte("null")) {
		return false, failure(InvalidEvidence)
	}
	return status == 1, nil
}
