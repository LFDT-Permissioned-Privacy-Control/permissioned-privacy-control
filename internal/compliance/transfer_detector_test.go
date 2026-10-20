package compliance

import (
	"math/big"
	"testing"
)

func TestDetectTransfer(t *testing.T) {
	tests := []struct {
		name           string
		from           string
		to             string
		data           string
		value          string
		wantNil        bool
		wantType       TransferType
		wantFrom       string
		wantTo         string
		wantAmount     *big.Int
		wantTokenAddr  *string
	}{
		{
			name:       "native ETH transfer with empty data",
			from:       "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
			to:         "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
			data:       "",
			value:      "0xde0b6b3a7640000",
			wantNil:    false,
			wantType:   TransferTypeETH,
			wantFrom:   "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
			wantTo:     "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
			wantAmount: new(big.Int).SetUint64(1000000000000000000),
		},
		{
			name:       "native ETH transfer with 0x data",
			from:       "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
			to:         "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
			data:       "0x",
			value:      "0xde0b6b3a7640000",
			wantNil:    false,
			wantType:   TransferTypeETH,
			wantFrom:   "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
			wantTo:     "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
			wantAmount: new(big.Int).SetUint64(1000000000000000000),
		},
		{
			name:    "not a transfer - unknown selector with no value",
			from:    "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
			to:      "0x5fbdb2315678afecb367f032d93f642f64180aa3",
			data:    "0xdeadbeef00000000000000000000000000000000000000000000000000000000",
			value:   "0x0",
			wantNil: true,
		},
		{
			name: "ERC-20 transfer",
			from: "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
			to:   "0x5FbDB2315678afecb367f032d93F642f64180aa3",
			// transfer(address,uint256)
			// recipient: 0x70997970C51812dc3A010C7d01b50e0d17dc79C8
			// amount: 1000000000000000000 (1e18)
			data:          "0xa9059cbb00000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c80000000000000000000000000000000000000000000000000de0b6b3a7640000",
			value:         "0x0",
			wantNil:       false,
			wantType:      TransferTypeERC20,
			wantFrom:      "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
			wantTo:        "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
			wantAmount:    new(big.Int).SetUint64(1000000000000000000),
			wantTokenAddr: strPtr("0x5fbdb2315678afecb367f032d93f642f64180aa3"),
		},
		{
			name: "ERC-20 transferFrom",
			from: "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc", // msg.sender (approved spender)
			to:   "0x5FbDB2315678afecb367f032d93F642f64180aa3", // token contract
			// transferFrom(address,address,uint256)
			// from:   0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
			// to:     0x70997970C51812dc3A010C7d01b50e0d17dc79C8
			// amount: 5000000000000000000 (5e18)
			data:          "0x23b872dd000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb9226600000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c80000000000000000000000000000000000000000000000004563918244f40000",
			value:         "0x0",
			wantNil:       false,
			wantType:      TransferTypeERC20,
			wantFrom:      "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
			wantTo:        "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
			wantAmount:    new(big.Int).Mul(big.NewInt(5), new(big.Int).SetUint64(1000000000000000000)),
			wantTokenAddr: strPtr("0x5fbdb2315678afecb367f032d93f642f64180aa3"),
		},
		{
			name:       "native ETH transfer with calldata (payable function)",
			from:       "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
			to:         "0x5fbdb2315678afecb367f032d93f642f64180aa3",
			data:       "0xdeadbeef00000000000000000000000000000000000000000000000000000000",
			value:      "0xde0b6b3a7640000",
			wantNil:    false,
			wantType:   TransferTypeETH,
			wantFrom:   "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
			wantTo:     "0x5fbdb2315678afecb367f032d93f642f64180aa3",
			wantAmount: new(big.Int).SetUint64(1000000000000000000),
		},
		{
			name:    "zero value with no data",
			from:    "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
			to:      "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
			data:    "",
			value:   "0x0",
			wantNil: true,
		},
		{
			name:    "data too short for selector",
			from:    "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
			to:      "0x5fbdb2315678afecb367f032d93f642f64180aa3",
			data:    "0xa9059c",
			value:   "0x0",
			wantNil: true,
		},
		{
			name:    "malformed transfer calldata - correct selector but truncated data",
			from:    "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
			to:      "0x5fbdb2315678afecb367f032d93f642f64180aa3",
			data:    "0xa9059cbb00000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c8",
			value:   "0x0",
			wantNil: true, // only 36 bytes of data, needs 68
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectTransfer(tt.from, tt.to, tt.data, tt.value)

			if tt.wantNil {
				if result != nil {
					t.Fatalf("expected nil, got %+v", result)
				}
				return
			}

			if result == nil {
				t.Fatal("expected non-nil result, got nil")
			}

			if result.Type != tt.wantType {
				t.Errorf("Type: want %q, got %q", tt.wantType, result.Type)
			}

			if result.FromAddress != tt.wantFrom {
				t.Errorf("FromAddress: want %q, got %q", tt.wantFrom, result.FromAddress)
			}

			if result.ToAddress != tt.wantTo {
				t.Errorf("ToAddress: want %q, got %q", tt.wantTo, result.ToAddress)
			}

			if result.AmountWei.Cmp(tt.wantAmount) != 0 {
				t.Errorf("AmountWei: want %s, got %s", tt.wantAmount.String(), result.AmountWei.String())
			}

			if tt.wantTokenAddr == nil {
				if result.TokenAddress != nil {
					t.Errorf("TokenAddress: want nil, got %q", *result.TokenAddress)
				}
			} else {
				if result.TokenAddress == nil {
					t.Errorf("TokenAddress: want %q, got nil", *tt.wantTokenAddr)
				} else if *result.TokenAddress != *tt.wantTokenAddr {
					t.Errorf("TokenAddress: want %q, got %q", *tt.wantTokenAddr, *result.TokenAddress)
				}
			}
		})
	}
}

func TestParseHexValue(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		want   *big.Int
	}{
		{
			name:  "empty string",
			input: "",
			want:  nil,
		},
		{
			name:  "bare 0x prefix",
			input: "0x",
			want:  nil,
		},
		{
			name:  "0x0 returns nil",
			input: "0x0",
			want:  nil,
		},
		{
			name:  "1 ETH in wei",
			input: "0xde0b6b3a7640000",
			want:  new(big.Int).SetUint64(1000000000000000000),
		},
		{
			name:  "0x1",
			input: "0x1",
			want:  big.NewInt(1),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseHexValue(tt.input)

			if tt.want == nil {
				if got != nil {
					t.Fatalf("want nil, got %s", got.String())
				}
				return
			}

			if got == nil {
				t.Fatalf("want %s, got nil", tt.want.String())
			}

			if got.Cmp(tt.want) != 0 {
				t.Errorf("want %s, got %s", tt.want.String(), got.String())
			}
		})
	}
}

func TestHexToBytes(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []byte
		wantErr bool
	}{
		{
			name:  "valid selector with 0x prefix",
			input: "0xa9059cbb",
			want:  []byte{0xa9, 0x05, 0x9c, 0xbb},
		},
		{
			name:  "empty string",
			input: "",
			want:  []byte{},
		},
		{
			name:    "invalid hex characters",
			input:   "0xZZZZ",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := hexToBytes(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(got) != len(tt.want) {
				t.Fatalf("length mismatch: want %d bytes, got %d bytes", len(tt.want), len(got))
			}

			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("byte %d: want 0x%02x, got 0x%02x", i, tt.want[i], got[i])
				}
			}
		})
	}
}

// strPtr is a helper that returns a pointer to the given string.
func strPtr(s string) *string {
	return &s
}
