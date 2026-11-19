package readprivacyabi

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// Logs use the real ABI encoder, not hand-shaped decoded Go values. This
// exercises native integer widths, *big.Int widths and every fixed-byte array.
func scalarLog(t *testing.T, typ string, indexed bool, value interface{}) (EventLogInputs, string, []byte) {
	t.Helper()
	raw := fmt.Sprintf(`[{"type":"event","name":"Scalar","anonymous":false,"inputs":[{"name":"value","type":%q,"indexed":%t}]}]`, typ, indexed)
	parsed, err := abi.JSON(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	event := parsed.Events["Scalar"]
	word, err := event.Inputs.Pack(value)
	if err != nil {
		t.Fatal(err)
	}
	log := EventLogInputs{Topics: []string{event.ID.Hex()}, Data: "0x"}
	if indexed {
		log.Topics = append(log.Topics, "0x"+hex.EncodeToString(word))
	} else {
		log.Data += hex.EncodeToString(word)
	}
	return log, raw, word
}

func integerValue(t *testing.T, typ string, value *big.Int) interface{} {
	t.Helper()
	kind, err := abi.NewType(typ, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	result := reflect.New(kind.GetType()).Elem()
	switch result.Kind() {
	case reflect.Ptr:
		return new(big.Int).Set(value)
	case reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		result.SetInt(value.Int64())
	case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		result.SetUint(value.Uint64())
	default:
		t.Fatal("unexpected ABI integer representation", result.Kind())
	}
	return result.Interface()
}

func TestEventScalarIntegerWidthsMatchActualABI(t *testing.T) {
	for bits := 8; bits <= 256; bits += 8 {
		for _, signed := range []bool{false, true} {
			name := fmt.Sprintf("uint%d", bits)
			max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(bits)), big.NewInt(1))
			values := []*big.Int{big.NewInt(0), big.NewInt(7), max}
			if signed {
				name = fmt.Sprintf("int%d", bits)
				half := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
				values = []*big.Int{big.NewInt(0), big.NewInt(7), big.NewInt(-1), new(big.Int).Neg(half), new(big.Int).Sub(half, big.NewInt(1))}
			}
			for _, indexed := range []bool{false, true} {
				for _, value := range values {
					t.Run(fmt.Sprintf("%s/indexed=%t/value=%s", name, indexed, value), func(t *testing.T) {
						log, raw, word := scalarLog(t, name, indexed, integerValue(t, name, value))
						literal := "0x" + hex.EncodeToString(word)
						if !MatchesEventParamRules(log, []ParamRule{{Index: 0, MustBe: literal}}, nil, raw) {
							t.Fatal("actual ABI value did not match its full literal", literal)
						}
						if value.Sign() >= 0 && value.BitLen() <= 8 {
							short := fmt.Sprintf("0x%02x", value.Uint64())
							if !MatchesEventParamRules(log, []ParamRule{{Index: 0, MustBe: short}}, nil, raw) {
								t.Fatal("short positive legacy literal did not match", short)
							}
						}
						wrong := append([]byte(nil), word...)
						wrong[31] ^= 1
						if MatchesEventParamRules(log, []ParamRule{{Index: 0, MustBe: "0x" + hex.EncodeToString(wrong)}}, nil, raw) {
							t.Fatal("different integer literal matched")
						}
					})
				}
			}
		}
	}
}

func TestEventScalarFixedBytesWidthsMatchActualABI(t *testing.T) {
	for size := 1; size <= 32; size++ {
		for _, indexed := range []bool{false, true} {
			t.Run(fmt.Sprintf("bytes%d/indexed=%t", size, indexed), func(t *testing.T) {
				kind, err := abi.NewType(fmt.Sprintf("bytes%d", size), "", nil)
				if err != nil {
					t.Fatal(err)
				}
				value := reflect.New(kind.GetType()).Elem()
				literal := make([]byte, size)
				for i := range literal {
					literal[i] = byte(0x80 + i)
					value.Index(i).SetUint(uint64(literal[i]))
				}
				log, raw, word := scalarLog(t, kind.String(), indexed, value.Interface())
				for _, candidate := range [][]byte{literal, word} {
					if !MatchesEventParamRules(log, []ParamRule{{Index: 0, MustBe: "0x" + hex.EncodeToString(candidate)}}, nil, raw) {
						t.Fatal("fixed bytes did not match exact declared-width or canonical legacy word")
					}
				}
				literal[0] ^= 1
				if MatchesEventParamRules(log, []ParamRule{{Index: 0, MustBe: "0x" + hex.EncodeToString(literal)}}, nil, raw) {
					t.Fatal("different fixed bytes matched")
				}
				if size < 32 {
					word[31] = 1
					if indexed {
						log.Topics[1] = "0x" + hex.EncodeToString(word)
					} else {
						log.Data = "0x" + hex.EncodeToString(word)
					}
					if MatchesEventParamRules(log, []ParamRule{{Index: 0, MustBe: "0x" + hex.EncodeToString(word)}}, nil, raw) {
						t.Fatal("noncanonical fixed-bytes padding matched")
					}
				}
			})
		}
	}
}

func TestEventScalarAddressBoolSelfAndOR(t *testing.T) {
	address := common.HexToAddress("0x1122334455667788990011223344556677889900")
	linked := map[string]bool{strings.ToLower(address.Hex()): true}
	for _, indexed := range []bool{false, true} {
		log, raw, word := scalarLog(t, "address", indexed, address)
		for _, literal := range []string{strings.ToLower(address.Hex()), "0x" + hex.EncodeToString(word), "self"} {
			if !MatchesEventParamRules(log, []ParamRule{{Index: 0, MustBe: literal}}, linked, raw) {
				t.Fatal("valid address/self failed", indexed, literal)
			}
		}
		if MatchesEventParamRules(log, []ParamRule{{Index: 0, MustBe: "self"}}, nil, raw) {
			t.Fatal("self matched without linked address")
		}
		if !MatchesEventParamRules(log, []ParamRule{{Index: -1, MustBe: "0x01"}, {Index: 0, MustBe: "self"}}, linked, raw) {
			t.Fatal("OR stopped at nonmatching rule")
		}
		word[0] = 1
		if MatchesEventParamRules(log, []ParamRule{{Index: 0, MustBe: "0x" + hex.EncodeToString(word)}}, linked, raw) {
			t.Fatal("nonzero literal address padding matched")
		}
		if indexed {
			log.Topics[1] = "0x" + hex.EncodeToString(word)
		} else {
			log.Data = "0x" + hex.EncodeToString(word)
		}
		if MatchesEventParamRules(log, []ParamRule{{Index: 0, MustBe: "self"}}, linked, raw) {
			t.Fatal("malformed address word matched self")
		}
		for _, value := range []bool{false, true} {
			log, raw, word := scalarLog(t, "bool", indexed, value)
			short := "0x00"
			if value {
				short = "0x01"
			}
			for _, literal := range []string{short, "0x" + hex.EncodeToString(word)} {
				if !MatchesEventParamRules(log, []ParamRule{{Index: 0, MustBe: literal}}, nil, raw) {
					t.Fatal("valid bool failed", indexed, value)
				}
			}
			if MatchesEventParamRules(log, []ParamRule{{Index: 0, MustBe: "0x02"}}, nil, raw) {
				t.Fatal("invalid bool matched")
			}
		}
	}
}

func TestEventScalarInvalidInputsAndUnsupportedTypesNeverMatch(t *testing.T) {
	for _, indexed := range []bool{false, true} {
		log, raw, _ := scalarLog(t, "uint8", indexed, uint8(7))
		for _, literal := range []string{"", "0x", "07", "0x7", "0xgg", "0x0107", "0x" + strings.Repeat("01", 33)} {
			if MatchesEventParamRules(log, []ParamRule{{Index: 0, MustBe: literal}}, nil, raw) {
				t.Fatal("invalid literal matched", indexed, literal)
			}
		}
		for _, index := range []int{-1, 1, int(^uint(0) >> 1)} {
			if MatchesEventParamRules(log, []ParamRule{{Index: index, MustBe: "0x07"}}, nil, raw) {
				t.Fatal("invalid parameter index matched", index)
			}
		}
		for _, badABI := range []string{"not-json", "[]", `[{"type":"event","name":"Other","inputs":[]}]`} {
			if MatchesEventParamRules(log, []ParamRule{{Index: 0, MustBe: "0x07"}}, nil, badABI) {
				t.Fatal("supplied invalid/unmatched ABI used no-ABI fallback")
			}
		}
		log, raw, _ = scalarLog(t, "int8", indexed, int8(-1))
		if MatchesEventParamRules(log, []ParamRule{{Index: 0, MustBe: "0xff"}}, nil, raw) {
			t.Fatal("short unsigned literal was silently reinterpreted as signed negative")
		}
		log, raw, _ = scalarLog(t, "uint256", indexed, new(big.Int).SetBytes(common.HexToAddress("0x1122").Bytes()))
		if MatchesEventParamRules(log, []ParamRule{{Index: 0, MustBe: "self"}}, map[string]bool{strings.ToLower(common.HexToAddress("0x1122").Hex()): true}, raw) {
			t.Fatal("a known non-address scalar matched self")
		}
	}
	for _, typ := range []string{"bytes", "string", "uint256[]", "uint256[1]", "function"} {
		raw := fmt.Sprintf(`[{"type":"event","name":"Scalar","inputs":[{"name":"value","type":%q,"indexed":true}]}]`, typ)
		parsed, err := abi.JSON(strings.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		word := "0x" + strings.Repeat("1", 64)
		log := EventLogInputs{Topics: []string{parsed.Events["Scalar"].ID.Hex(), word}, Data: "0x"}
		if MatchesEventParamRules(log, []ParamRule{{Index: 0, MustBe: word}}, nil, raw) {
			t.Fatal("unsupported typed hash/function matched a scalar rule", typ)
		}
	}
	log, raw, _ := scalarLog(t, "uint8", false, uint8(7))
	log.Data += "00"
	if MatchesEventParamRules(log, []ParamRule{{Index: 0, MustBe: "0x07"}}, nil, raw) {
		t.Fatal("noncanonical trailing event data matched")
	}
	log, raw, _ = scalarLog(t, "address", true, common.Address{})
	invalidAddress := "0x" + strings.Repeat("z", 40)
	log.Topics[1] = "0x" + strings.Repeat("0", 24) + invalidAddress[2:]
	if MatchesEventParamRules(log, []ParamRule{{Index: 0, MustBe: "self"}}, map[string]bool{invalidAddress: true}, raw) {
		t.Fatal("malformed topic address matched a supplied self entry")
	}
}

func TestEventScalarNoABILegacyFallbackRemainsExplicitAndBounded(t *testing.T) {
	log, _, _ := scalarLog(t, "uint8", true, uint8(7))
	if !MatchesEventParamRules(log, []ParamRule{{Index: 0, MustBe: "0x07"}}, nil, "") {
		t.Fatal("empty-ABI exact topic fallback regressed")
	}
	for _, topic := range []string{"07", "0xgg" + strings.Repeat("0", 62), "0x07"} {
		log.Topics[1] = topic
		if MatchesEventParamRules(log, []ParamRule{{Index: 0, MustBe: "0x07"}}, nil, "") {
			t.Fatal("malformed fallback topic matched")
		}
	}
	log.Topics = []string{"0x" + strings.Repeat("0", 64)}
	if MatchesEventParamRules(log, []ParamRule{{Index: -1, MustBe: "0x00"}}, nil, "") {
		t.Fatal("negative fallback index matched topic0")
	}
}

func TestEventScalarEveryIntegerWidthRejectsImpossibleEncodings(t *testing.T) {
	for bits := 8; bits < 256; bits += 8 {
		for _, signed := range []bool{false, true} {
			name := fmt.Sprintf("uint%d", bits)
			if signed {
				name = fmt.Sprintf("int%d", bits)
			}
			for _, indexed := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/indexed=%t", name, indexed), func(t *testing.T) {
					log, raw, _ := scalarLog(t, name, indexed, integerValue(t, name, big.NewInt(0)))
					bad := make([]byte, 32)
					if signed {
						bad[32-bits/8] = 0x80 // sign bit without the required sign extension
					} else {
						bad[31-bits/8] = 1 // one bit above the declared unsigned range
					}
					encoded := "0x" + hex.EncodeToString(bad)
					if indexed {
						log.Topics[1] = encoded
					} else {
						log.Data = encoded
					}
					if MatchesEventParamRules(log, []ParamRule{{Index: 0, MustBe: encoded}}, nil, raw) {
						t.Fatal("out-of-range ABI word matched itself")
					}
				})
			}
		}
	}
}

func TestEventScalarMixedIndexedAndDataPositions(t *testing.T) {
	raw := `[{"type":"event","name":"Mixed","inputs":[{"name":"number","type":"uint8","indexed":false},{"name":"account","type":"address","indexed":true},{"name":"tag","type":"bytes4","indexed":false},{"name":"delta","type":"int24","indexed":true}]}]`
	parsed, err := abi.JSON(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	event := parsed.Events["Mixed"]
	address := common.HexToAddress("0x112233")
	data, err := event.Inputs.NonIndexed().Pack(uint8(7), [4]byte{0xaa, 0xbb, 0xcc, 0xdd})
	if err != nil {
		t.Fatal(err)
	}
	account, err := (abi.Arguments{event.Inputs[1]}).Pack(address)
	if err != nil {
		t.Fatal(err)
	}
	delta, err := (abi.Arguments{event.Inputs[3]}).Pack(big.NewInt(-7))
	if err != nil {
		t.Fatal(err)
	}
	log := EventLogInputs{Topics: []string{event.ID.Hex(), "0x" + hex.EncodeToString(account), "0x" + hex.EncodeToString(delta)}, Data: "0x" + hex.EncodeToString(data)}
	for _, rule := range []ParamRule{{Index: 0, MustBe: "0x07"}, {Index: 1, MustBe: "self"}, {Index: 2, MustBe: "0xaabbccdd"}, {Index: 3, MustBe: "0x" + hex.EncodeToString(delta)}} {
		if !MatchesEventParamRules(log, []ParamRule{rule}, map[string]bool{strings.ToLower(address.Hex()): true}, raw) {
			t.Fatal("mixed ABI position did not match", rule.Index)
		}
	}
}
