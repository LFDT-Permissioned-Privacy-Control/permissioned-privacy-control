package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Unit tests for the input-validation helpers in admin_shared_infra.go.
// The full HTTP / DB integration coverage lives in
// admin_shared_infra_integration_test.go (Postgres testcontainer) —
// kept separate so non-container CI shards still catch regressions
// on the pure-validation paths.

func TestIsValidHash32(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"valid lowercase", "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", true},
		{"valid uppercase prefix", "0Xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", true},
		{"valid mixed-case body", "0xC5D2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", true},
		{"missing 0x prefix", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", false},
		{"too short", "0xabc", false},
		{"too long", "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a47000", false},
		{"non-hex char", "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a47z", false},
		{"empty", "", false},
		{"just 0x", "0x", false},
		// One nibble off from valid length — common typo class.
		{"63 nibbles", "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a47", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isValidHash32(tt.in))
		})
	}
}

func TestValidateSharedInfraInput(t *testing.T) {
	const validAddr = "0xe592427a0aece92de3edee1f18e0157c05861564"
	const validHash = "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"

	tests := []struct {
		name        string
		addr        string
		codehash    string
		wantErr     bool
		wantAddr    string
		wantHash    string
	}{
		{
			name: "valid address, no codehash",
			addr: validAddr, codehash: "",
			wantAddr: validAddr, wantHash: "",
		},
		{
			name: "valid address + valid codehash",
			addr: validAddr, codehash: validHash,
			wantAddr: validAddr, wantHash: validHash,
		},
		{
			name: "checksummed address normalises to lowercase",
			addr: "0xE592427A0Aece92De3Edee1f18E0157C05861564", codehash: "",
			wantAddr: validAddr, wantHash: "",
		},
		{
			name: "uppercase codehash normalises to lowercase",
			addr: validAddr, codehash: "0xC5D2460186F7233C927E7DB2DCC703C0E500B653CA82273B7BFAD8045D85A470",
			wantAddr: validAddr, wantHash: validHash,
		},
		{
			name: "invalid address rejected",
			addr: "not-an-address", codehash: "",
			wantErr: true,
		},
		{
			name: "valid address, malformed codehash rejected",
			addr: validAddr, codehash: "0xabc",
			wantErr: true,
		},
		{
			name: "whitespace trimmed",
			addr: "  " + validAddr + "  ", codehash: "  " + validHash + "  ",
			wantAddr: validAddr, wantHash: validHash,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAddr, gotHash, err := validateSharedInfraInput(tt.addr, tt.codehash)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.wantAddr, gotAddr)
			assert.Equal(t, tt.wantHash, gotHash)
		})
	}
}

func TestCodehashForLog(t *testing.T) {
	s := "0xabc"
	assert.Equal(t, "0xabc", codehashForLog(&s))
	assert.Equal(t, "", codehashForLog(nil))
}
