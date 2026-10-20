package compliance

import (
	"encoding/hex"
	"math/big"
	"strings"
)

// ERC-20 function selectors.
const (
	SelectorTransfer     = "0xa9059cbb" // transfer(address,uint256)
	SelectorTransferFrom = "0x23b872dd" // transferFrom(address,address,uint256)
)

// TransferInfo describes a detected value transfer.
type TransferInfo struct {
	Type         TransferType
	TokenAddress *string  // nil for native ETH
	FromAddress  string   // sender
	ToAddress    string   // recipient
	AmountWei    *big.Int // transfer amount in smallest unit
}

// DetectTransfer analyzes decoded transaction fields and returns transfer info.
// Returns nil if the transaction is not a value transfer.
// Parameters are hex strings as decoded from the transaction (from/to are 0x-prefixed addresses,
// data is 0x-prefixed calldata hex, value is 0x-prefixed hex amount or empty).
func DetectTransfer(from, to, data, value string) *TransferInfo {
	parsedValue := parseHexValue(value)

	// Check for ERC-20 selectors first (need at least "0x" + 8 hex chars = 10 chars).
	// ERC-20 transfers take priority because the token amount is in calldata, not value.
	if len(data) >= 10 {
		selector := strings.ToLower(data[:10])
		dataBytes, err := hexToBytes(data)
		if err == nil {
			if info := detectERC20(selector, dataBytes, from, to); info != nil {
				return info
			}
		}
	}

	// Native ETH transfer: value > 0 (regardless of calldata).
	// Checked after ERC-20 selectors so that ERC-20 transfer amounts take priority.
	// This catches: plain transfers, calls to payable functions, and any tx with ETH value.
	if parsedValue != nil && parsedValue.Sign() > 0 {
		return &TransferInfo{
			Type:        TransferTypeETH,
			FromAddress: from,
			ToAddress:   to,
			AmountWei:   parsedValue,
		}
	}

	return nil
}

// detectERC20 checks if calldata matches a known ERC-20 transfer selector.
func detectERC20(selector string, dataBytes []byte, from, to string) *TransferInfo {
	switch selector {
	case SelectorTransfer:
		// transfer(address,uint256)
		// ABI: 4-byte selector + 32-byte address + 32-byte uint256 = 68 bytes minimum
		if len(dataBytes) < 68 {
			return nil
		}
		recipientBytes := dataBytes[16:36]
		recipient := "0x" + hex.EncodeToString(recipientBytes)
		amount := new(big.Int).SetBytes(dataBytes[36:68])

		tokenAddr := strings.ToLower(to)
		return &TransferInfo{
			Type:         TransferTypeERC20,
			TokenAddress: &tokenAddr,
			FromAddress:  from,
			ToAddress:    recipient,
			AmountWei:    amount,
		}

	case SelectorTransferFrom:
		// transferFrom(address,address,uint256)
		// ABI: 4-byte selector + 32-byte from + 32-byte to + 32-byte uint256 = 100 bytes minimum
		if len(dataBytes) < 100 {
			return nil
		}
		senderBytes := dataBytes[16:36]
		sender := "0x" + hex.EncodeToString(senderBytes)
		recipientBytes := dataBytes[48:68]
		recipient := "0x" + hex.EncodeToString(recipientBytes)
		amount := new(big.Int).SetBytes(dataBytes[68:100])

		tokenAddr := strings.ToLower(to)
		return &TransferInfo{
			Type:         TransferTypeERC20,
			TokenAddress: &tokenAddr,
			FromAddress:  sender,
			ToAddress:    recipient,
			AmountWei:    amount,
		}
	}

	return nil
}

// hexToBytes decodes a hex string (with optional "0x" prefix) to bytes.
func hexToBytes(hexStr string) ([]byte, error) {
	hexStr = strings.TrimPrefix(hexStr, "0x")
	hexStr = strings.TrimPrefix(hexStr, "0X")
	return hex.DecodeString(hexStr)
}

// parseHexValue parses a hex-encoded value string to a *big.Int.
// Returns nil if the input is empty, "0x", or "0x0".
func parseHexValue(hexValue string) *big.Int {
	if hexValue == "" || hexValue == "0x" || hexValue == "0X" || hexValue == "0x0" || hexValue == "0X0" {
		return nil
	}

	cleaned := strings.TrimPrefix(hexValue, "0x")
	cleaned = strings.TrimPrefix(cleaned, "0X")

	val, ok := new(big.Int).SetString(cleaned, 16)
	if !ok {
		return nil
	}
	return val
}
