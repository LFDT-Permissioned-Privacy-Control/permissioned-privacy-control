package readprivacyabi

import (
	"encoding/hex"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"strings"
)

func IsViewerInCalldataABI(inputData, abiJSON string, viewerAddrs map[string]bool) bool {
	parsedABI, err := abi.JSON(strings.NewReader(abiJSON))
	if err != nil {
		return false
	}
	data := strings.TrimPrefix(strings.ToLower(inputData), "0x")
	if len(data) < 8 {
		return false
	}
	raw, err := hex.DecodeString(data)
	if err != nil {
		return false
	}
	method, err := parsedABI.MethodById(raw[:4])
	if err != nil {
		return false // Selector unknown to ABI (proxy/upgrade mismatch) — fail-closed.
	}
	args, err := method.Inputs.Unpack(raw[4:])
	if err != nil {
		return false
	}
	for _, arg := range args {
		if AnyAddressMatches(arg, viewerAddrs) {
			return true
		}
	}
	return false
}
