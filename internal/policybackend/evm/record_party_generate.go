package evm

import (
	"fmt"
	"slices"
	"strings"

	"privacy-proxy/internal/policycore"
)

func writeRecordPartyCheck(b *strings.Builder, rule int, arg policycore.CodegenArgument, headLen int) {
	r := arg.Record
	fmt.Fprintf(b, "\n    function _record%d_%d(address[] calldata linked, bytes calldata payload, address target) internal view returns (uint16) {\n", rule, arg.Index)
	b.WriteString("        bytes memory input;\n        {\n")
	fmt.Fprintf(b, "            uint256 word = uint256(bytes32(payload[%d:%d]));\n", arg.Offset, arg.Offset+32)
	if r.InputKind == policycore.CodegenRecordString || r.InputKind == policycore.CodegenRecordBytes {
		fmt.Fprintf(b, "            if (word %% 32 != 0 || word < %d || word > payload.length - 36) return MALFORMED_CALLDATA;\n", headLen-4)
		b.WriteString("            uint256 start = 4 + word;\n")
		b.WriteString("            uint256 length = uint256(bytes32(payload[start:start + 32]));\n")
		fmt.Fprintf(b, "            if (length > %d) return MALFORMED_CALLDATA;\n", policycore.MaxRecordIDBytes)
		b.WriteString("            uint256 padded = (length + 31) / 32 * 32;\n")
		b.WriteString("            if (padded > payload.length - start - 32) return MALFORMED_CALLDATA;\n")
		b.WriteString("            for (uint256 p = start + 32 + length; p < start + 32 + padded; p++) { if (payload[p] != 0) return MALFORMED_CALLDATA; }\n")
		fmt.Fprintf(b, "            input = abi.encodeWithSelector(%s, payload[start + 32:start + 32 + length]);\n", solidityBytes4(r.Selector))
	} else {
		if r.InputKind == policycore.CodegenRecordUint && r.InputBits < 256 {
			fmt.Fprintf(b, "            if (word >> %d != 0) return MALFORMED_CALLDATA;\n", r.InputBits)
		}
		fmt.Fprintf(b, "            input = abi.encodePacked(%s, bytes32(word));\n", solidityBytes4(r.Selector))
	}
	b.WriteString("        }\n")
	outputLen := 32 * len(r.OutputBits)
	fmt.Fprintf(b, "        bytes memory output = new bytes(%d);\n", outputLen)
	b.WriteString("        bool success;\n        uint256 returned;\n")
	b.WriteString("        // Bound both the nested execution and copied return data.\n")
	b.WriteString("        assembly {\n")
	fmt.Fprintf(b, "            success := staticcall(%d, target, add(input, 32), mload(input), add(output, 32), %d)\n", policycore.RecordReadGas, outputLen)
	b.WriteString("            returned := returndatasize()\n        }\n")
	fmt.Fprintf(b, "        if (!success || returned != %d) return ARGUMENT_CONSTRAINT;\n", outputLen)
	b.WriteString("        bool found;\n")
	for i, bits := range r.OutputBits {
		isParty := slices.Contains(r.PartyOutputs, i)
		if bits == 256 && !isParty {
			continue
		}
		b.WriteString("        {\n            uint256 word;\n")
		fmt.Fprintf(b, "            assembly { word := mload(add(output, %d)) }\n", 32+32*i)
		if bits < 256 {
			fmt.Fprintf(b, "            if (word >> %d != 0) return ARGUMENT_CONSTRAINT;\n", bits)
		}
		if isParty {
			b.WriteString("            if (word != 0) {\n                for (uint256 k = 0; k < linked.length; k++) {\n                    if (linked[k] == address(uint160(word))) { found = true; break; }\n                }\n            }\n")
		}
		b.WriteString("        }\n")
	}
	b.WriteString("        return found ? OK : ARGUMENT_CONSTRAINT;\n    }\n")
}
