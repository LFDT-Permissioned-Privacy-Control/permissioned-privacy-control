package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Unit tests for extractEthCallBlockParam (RD-915 F2).
//
// The function gates the second positional arg of eth_call before it
// reaches the tracer. Goal: trace and forwarded call must run against
// the same chain state, so the parser must accept the shapes geth's
// debug_traceCall accepts and reject anything else with a clean 400.

func TestExtractEthCallBlockParam_MissingReturnsNil(t *testing.T) {
	got, err := extractEthCallBlockParam([]any{map[string]any{"to": "0xaa"}})
	require.NoError(t, err)
	assert.Nil(t, got, "no params[1] → nil → tracer defaults to 'latest'")
}

func TestExtractEthCallBlockParam_NilSecondParamReturnsNil(t *testing.T) {
	got, err := extractEthCallBlockParam([]any{map[string]any{"to": "0xaa"}, nil})
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestExtractEthCallBlockParam_StringTags(t *testing.T) {
	for _, tag := range []string{"latest", "earliest", "pending", "safe", "finalized"} {
		t.Run(tag, func(t *testing.T) {
			got, err := extractEthCallBlockParam([]any{map[string]any{"to": "0xaa"}, tag})
			require.NoError(t, err)
			assert.Equal(t, tag, got)
		})
	}
}

func TestExtractEthCallBlockParam_StringHexBlockNumber(t *testing.T) {
	got, err := extractEthCallBlockParam([]any{map[string]any{"to": "0xaa"}, "0x1234abcd"})
	require.NoError(t, err)
	assert.Equal(t, "0x1234abcd", got)
}

func TestExtractEthCallBlockParam_StringUppercaseNormalized(t *testing.T) {
	got, err := extractEthCallBlockParam([]any{map[string]any{"to": "0xaa"}, "LATEST"})
	require.NoError(t, err)
	assert.Equal(t, "latest", got, "tag is normalized to lowercase before dispatch")
}

func TestExtractEthCallBlockParam_RejectsBareDecimalNumber(t *testing.T) {
	// "1234" (no 0x prefix) — geth would reject this; we reject pre-trace
	// so the tracer never sees a shape it might silently coerce to latest.
	_, err := extractEthCallBlockParam([]any{map[string]any{"to": "0xaa"}, "1234"})
	require.Error(t, err)
}

func TestExtractEthCallBlockParam_RejectsBareHexNoPrefix(t *testing.T) {
	_, err := extractEthCallBlockParam([]any{map[string]any{"to": "0xaa"}, "deadbeef"})
	require.Error(t, err)
}

func TestExtractEthCallBlockParam_RejectsZeroXOnly(t *testing.T) {
	// "0x" with no digits isn't a valid block number.
	_, err := extractEthCallBlockParam([]any{map[string]any{"to": "0xaa"}, "0x"})
	require.Error(t, err)
}

func TestExtractEthCallBlockParam_RejectsNonHexAfterPrefix(t *testing.T) {
	_, err := extractEthCallBlockParam([]any{map[string]any{"to": "0xaa"}, "0xZZZ"})
	require.Error(t, err)
}

func TestExtractEthCallBlockParam_EIP1898BlockNumber(t *testing.T) {
	obj := map[string]any{"blockNumber": "0x1234"}
	got, err := extractEthCallBlockParam([]any{map[string]any{"to": "0xaa"}, obj})
	require.NoError(t, err)
	assert.Equal(t, obj, got, "EIP-1898 object passed through verbatim")
}

func TestExtractEthCallBlockParam_EIP1898BlockHash(t *testing.T) {
	obj := map[string]any{
		"blockHash":         "0xabc123",
		"requireCanonical": true,
	}
	got, err := extractEthCallBlockParam([]any{map[string]any{"to": "0xaa"}, obj})
	require.NoError(t, err)
	assert.Equal(t, obj, got)
}

func TestExtractEthCallBlockParam_EIP1898RejectsBothFields(t *testing.T) {
	// Setting both blockNumber and blockHash is ambiguous — geth would
	// likely error too, but we reject early so the trace path doesn't
	// run with a different interpretation than the forwarded call.
	obj := map[string]any{
		"blockNumber": "0x1234",
		"blockHash":   "0xabcd",
	}
	_, err := extractEthCallBlockParam([]any{map[string]any{"to": "0xaa"}, obj})
	require.Error(t, err)
}

func TestExtractEthCallBlockParam_EIP1898RejectsEmptyObject(t *testing.T) {
	_, err := extractEthCallBlockParam([]any{map[string]any{"to": "0xaa"}, map[string]any{}})
	require.Error(t, err)
}

func TestExtractEthCallBlockParam_EIP1898RejectsNonHexValues(t *testing.T) {
	obj := map[string]any{"blockNumber": "latest"} // strings are valid only at top level, not inside the object
	_, err := extractEthCallBlockParam([]any{map[string]any{"to": "0xaa"}, obj})
	require.Error(t, err)
}

func TestExtractEthCallBlockParam_RejectsUnsupportedTypes(t *testing.T) {
	for name, val := range map[string]any{
		"number": float64(1234),
		"array":  []any{"latest"},
		"bool":   true,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := extractEthCallBlockParam([]any{map[string]any{"to": "0xaa"}, val})
			require.Error(t, err)
		})
	}
}
