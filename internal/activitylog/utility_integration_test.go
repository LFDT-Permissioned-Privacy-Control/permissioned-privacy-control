package activitylog_test

import (
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"privacy-proxy/internal/networkidentity"
	"privacy-proxy/internal/operational/rpcactivity"
	"privacy-proxy/internal/rpcengine"
)

type utilityActivityNode struct {
	t                *testing.T
	traceGas         []uint64
	lists            []any
	signs            int
	wrongSigner      bool
	denyIntermediate bool
	signedCalls      []map[string]any
	changeSigned     func(map[string]any)
}

func (m *utilityActivityNode) respond(n *node, w http.ResponseWriter, id json.RawMessage, method string, params []json.RawMessage) bool {
	var result any
	switch method {
	case "eth_getHeaderByHash":
		result = n.anchorHeader
	case "eth_getBalance":
		result = "0x" + strings.Repeat("f", 64)
	case "eth_gasPrice":
		result = "0x1"
	case "debug_traceCall":
		var call, config map[string]any
		_ = json.Unmarshal(params[0], &call)
		_ = json.Unmarshal(params[2], &config)
		if config["tracer"] != "muxTracer" {
			return false
		}
		cfg := config["tracerConfig"].(map[string]any)
		preCfg := cfg["prestateTracer"].(map[string]any)
		gas := uint64(100000)
		if s, ok := call["gas"].(string); ok {
			gas, _ = strconv.ParseUint(s[2:], 16, 64)
		}
		m.traceGas = append(m.traceGas, gas)
		m.lists = append(m.lists, call["accessList"])
		used := uint64(40000)
		if call["accessList"] != nil {
			used = 30000
		}
		root := map[string]any{"type": "CALL", "from": call["from"], "to": call["to"], "input": call["input"], "value": call["value"], "gas": "0x" + strconv.FormatUint(gas, 16), "gasUsed": "0x" + strconv.FormatUint(used, 16), "output": "0xfeed"}
		if m.denyIntermediate && gas > 50000 && gas < 80000 {
			root["calls"] = []any{map[string]any{"type": "CALL", "from": addressA, "to": addressB, "input": "0x", "value": "0x0", "gas": "0x1000", "gasUsed": "0x1", "output": "0xprivate"}}
		}
		if gas < 50000 {
			root["error"] = "out of gas"
			root["gasUsed"] = "0x" + strconv.FormatUint(gas, 16)
			root["output"] = "0x"
		}
		account := map[string]any{"code": "0x6000"}
		if preCfg["disableStorage"] == false {
			account["storage"] = map[string]any{common.Hash{42}.Hex(): common.Hash{9}.Hex()}
		}
		result = map[string]any{"callTracer": root, "prestateTracer": map[string]any{addressA: account, addressB: map[string]any{"code": "0x6000"}, call["from"].(string): map[string]any{}}}
	case "eth_signTransaction":
		m.signs++
		var c map[string]any
		_ = json.Unmarshal(params[0], &c)
		m.signedCalls = append(m.signedCalls, c)
		if m.changeSigned != nil {
			m.changeSigned(c)
		}
		parse := func(name string) *big.Int {
			s, _ := c[name].(string)
			if s == "" {
				return new(big.Int)
			}
			n, _ := new(big.Int).SetString(s[2:], 16)
			return n
		}
		to := common.HexToAddress(c["to"].(string))
		data := common.FromHex(c["input"].(string))
		key, _ := crypto.HexToECDSA(strings.Repeat("0", 63) + "1")
		if m.wrongSigner {
			key, _ = crypto.HexToECDSA(strings.Repeat("0", 63) + "2")
		}
		var access types.AccessList
		encodedAccess, _ := json.Marshal(c["accessList"])
		_ = json.Unmarshal(encodedAccess, &access)
		unsigned := types.NewTransaction(parse("nonce").Uint64(), to, parse("value"), parse("gas").Uint64(), parse("gasPrice"), data)
		if c["type"] == "0x1" {
			unsigned = types.NewTx(&types.AccessListTx{ChainID: big.NewInt(1), Nonce: parse("nonce").Uint64(), To: &to, Value: parse("value"), Gas: parse("gas").Uint64(), GasPrice: parse("gasPrice"), Data: data, AccessList: access})
		}
		if c["type"] == "0x2" {
			unsigned = types.NewTx(&types.DynamicFeeTx{ChainID: big.NewInt(1), Nonce: parse("nonce").Uint64(), To: &to, Value: parse("value"), Gas: parse("gas").Uint64(), GasFeeCap: parse("maxFeePerGas"), GasTipCap: parse("maxPriorityFeePerGas"), Data: data, AccessList: access})
		}
		tx, err := types.SignTx(unsigned, types.LatestSignerForChainID(big.NewInt(1)), key)
		if err != nil {
			m.t.Fatal(err)
		}
		raw, _ := tx.MarshalBinary()
		result = "0x" + common.Bytes2Hex(raw)
	default:
		return false
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
	return true
}
func utilityFixture() fixture {
	f := traceFixture()
	f.linkSigner = true
	m := *f.methodCatalog
	m.Assignable = append(m.Assignable, "eth_estimateGas", "eth_createAccessList")
	f.methodCatalog = &m
	f.groups[0].AllowedMethods = []string{"eth_estimateGas", "eth_createAccessList", "eth_sendTransaction", "eth_getStorageAt"}
	return f
}
func TestUtilityActualCheckedEstimateAccessListAndSignedRawPipeline(t *testing.T) {
	d := rawPostgres(t)
	if _, err := d.owner.Exec(t.Context(), `CREATE ROLE raw_observer LOGIN PASSWORD 'raw-test-only';CREATE ROLE raw_facts LOGIN PASSWORD 'raw-test-only'`); err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"eth_estimateGas", "eth_createAccessList", "eth_sendTransaction", "wrong-signer", "gas-dependent-denial"} {
		t.Run(method, func(t *testing.T) {
			f := utilityFixture()
			u := &utilityActivityNode{t: t, wrongSigner: method == "wrong-signer", denyIntermediate: method == "gas-dependent-denial"}
			n := &node{utility: u}
			engine, tok, financial, _ := mountedRawEngine(t, f, n, d, false, creationMountOptions{configure: func(o *rpcengine.RawOptions) { o.Utilities = &rpcengine.ExecutionUtilityOptions{NodeSigning: true} }})
			defer engine.Close()
			net := financial.Metadata().Network
			network := networkidentity.Binding{Environment: net.Environment, ChainID: net.ChainID, GenesisHash: net.GenesisHash, DeploymentID: net.DeploymentID}
			x := setupActivityDatabase(t, network)
			rec := rpcRecorder(t, x, func() time.Time { return time.Unix(now, 0) }, nil, "eth_estimateGas", "eth_createAccessList", "eth_sendTransaction")
			service, err := rpcactivity.New(rpcactivity.Config{Engine: engine, Recorder: rec, Network: network})
			if err != nil {
				t.Fatal(err)
			}
			handler, _ := service.Handler(orgA)
			front := httptest.NewTLSServer(handler)
			defer front.Close()
			wireMethod := method
			if method == "gas-dependent-denial" {
				wireMethod = "eth_estimateGas"
			}
			if method == "wrong-signer" {
				wireMethod = "eth_sendTransaction"
			}
			body := `{"jsonrpc":"2.0","id":1.2500e+03,"method":"` + wireMethod + `","params":[{"from":"` + signedValue(t, 9).Signer().Hex() + `","to":"` + addressA + `","input":"0x0102","value":"0x0","gas":"0x186a0"}]}`
			raw := bodyResult(t, requestAsync(t, front.Client(), front.URL, tok, body, context.Background()))
			var response struct {
				Result json.RawMessage
				Error  *rpcengine.RPCError
			}
			if json.Unmarshal(raw, &response) != nil {
				t.Fatal(string(raw))
			}
			if method == "gas-dependent-denial" {
				if response.Error == nil || len(u.traceGas) < 2 {
					t.Fatal("intermediate unapproved probe allowed", string(raw), u.traceGas)
				}
				return
			}
			if method == "wrong-signer" {
				if response.Error == nil {
					t.Fatal("node substituted signer", string(raw))
				}
				methods, _ := n.counts()
				for _, m := range methods {
					if m == "eth_sendRawTransaction" {
						t.Fatal("substituted signed transaction broadcast")
					}
				}
				return
			}
			if response.Error != nil {
				methods, _ := n.counts()
				t.Fatal("utility unavailable", method, string(raw), "traceGas", u.traceGas, "lists", u.lists, "methods", methods)
			}
			if !strings.Contains(string(raw), `"id":1.2500e+03`) {
				t.Fatal("raw ID lost", string(raw))
			}
			switch method {
			case "eth_estimateGas":
				var text string
				_ = json.Unmarshal(response.Result, &text)
				gas, _ := strconv.ParseUint(text[2:], 16, 64)
				if gas < 50000 || gas > 51000 || len(u.traceGas) < 2 {
					t.Fatal("not checked gas search", text, u.traceGas)
				}
			case "eth_createAccessList":
				var out struct {
					AccessList types.AccessList
					GasUsed    string
				}
				if json.Unmarshal(response.Result, &out) != nil || out.GasUsed != "0x7530" || len(u.traceGas) != 2 || len(out.AccessList) != 1 || out.AccessList[0].Address != common.HexToAddress(addressA) || len(out.AccessList[0].StorageKeys) != 0 || u.lists[1] == nil {
					t.Fatal("unfiltered list/wrong second replay gas", string(raw), u.lists)
				}
			case "eth_sendTransaction":
				var hash string
				_ = json.Unmarshal(response.Result, &hash)
				if len(hash) != 66 || u.signs != 1 {
					t.Fatal("sign/raw result", string(raw), u.signs)
				}
				methods, _ := n.counts()
				send := 0
				for _, name := range methods {
					if name == "eth_sendTransaction" {
						t.Fatal("unchecked node send fallback")
					}
					if name == "eth_sendRawTransaction" {
						send++
					}
				}
				if send != 1 {
					t.Fatal("raw pipeline did not broadcast exactly once", methods)
				}
			}
		})
	}
}
