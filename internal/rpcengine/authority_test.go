package rpcengine_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"privacy-proxy/internal/nativeadmission"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
)

func child(kind, from, to, input string) map[string]any {
	return map[string]any{"type": kind, "from": from, "to": to, "input": input, "value": "0x0", "gas": "0x100", "gasUsed": "0x10"}
}

func TestHTTPNativeOwnForeignAndSharedStorageFences(t *testing.T) {
	for name, implementation := range map[string]string{"own implementation": addressC, "foreign implementation": addressB} {
		t.Run(name, func(t *testing.T) {
			f := newFixture()
			f.bindings[0].Allow = []policycore.FrameRule{{TargetClass: "org", Selector: "*", CallTypes: []policycore.CallType{policycore.CallTypeCall, policycore.CallTypeStaticCall, policycore.CallTypeDelegateCall, policycore.CallTypeCallCode}}}
			n := &node{mutate: func(root map[string]any) {
				root["calls"] = []any{child("DELEGATECALL", addressA, implementation, "0x")}
			}}
			var clock atomic.Int64
			e, tok, _ := engine(t, f, n, nil, &clock)
			response, _ := request(t, e, tok, orgA, map[string]any{"to": addressA}, nil)
			if (response.Error == nil) != (implementation == addressC) {
				t.Fatalf("%s %+v", name, response)
			}
		})
	}
	minimum := 1
	f := newFixture()
	f.groups[0].Claims = []string{"upgrade"}
	f.runtime.SharedInfrastructure = []policybundle.SharedInfrastructure{{Address: addressB}}
	f.capability(policybundle.CapabilitySharedCode)
	f.capability(policybundle.CapabilityDepth)
	f.capability(policybundle.CapabilityUpgradeFacts)
	f.bindings[0].Allow = append(f.bindings[0].Allow, policycore.FrameRule{TargetClass: "shared", Selector: "*", MinDepth: &minimum, AllowUpgrade: true})
	upgrade := "0x3659cfe6" + common.Bytes2Hex(common.LeftPadBytes(common.HexToAddress(addressC).Bytes(), 32))
	n := &node{mutate: func(root map[string]any) { root["calls"] = []any{child("CALL", addressA, addressB, upgrade)} }}
	var clock atomic.Int64
	e, tok, _ := engine(t, f, n, nil, &clock)
	if response, _ := request(t, e, tok, orgA, map[string]any{"to": addressA}, nil); response.Error == nil {
		t.Fatal("own upgrade target lent claims to foreign shared STORAGE")
	}
	// Reach own code through foreign shared storage: the ordinary shared parent
	// is permitted, but the delegated frame still needs its own rule/ownership.
	f.bindings[0].Allow = append(f.bindings[0].Allow, policycore.FrameRule{TargetClass: "org", Selector: "*", CallTypes: []policycore.CallType{policycore.CallTypeDelegateCall}})
	n = &node{mutate: func(root map[string]any) {
		parent := child("CALL", addressA, addressB, "0x")
		parent["calls"] = []any{child("DELEGATECALL", addressB, addressC, "0x")}
		root["calls"] = []any{parent}
	}}
	var clock2 atomic.Int64
	e, tok, _ = engine(t, f, n, nil, &clock2)
	if response, _ := request(t, e, tok, orgA, map[string]any{"to": addressA}, nil); response.Error == nil {
		t.Fatal("own code relabeled foreign storage")
	}
}

func TestHTTPSharedMinimumAndCodeHashPinHaveNoFallback(t *testing.T) {
	const unregistered = "0x5555555555555555555555555555555555555555"
	minimum := 1
	f := newFixture()
	f.runtime.SharedInfrastructure = []policybundle.SharedInfrastructure{{Address: unregistered}}
	f.bindings[0].Allow = []policycore.FrameRule{{TargetClass: "shared", Selector: "*", MinDepth: &minimum}}
	f.capability(policybundle.CapabilitySharedCode)
	f.capability(policybundle.CapabilityDepth)
	n := &node{}
	var clock atomic.Int64
	e, tok, _ := engine(t, f, n, nil, &clock)
	if response, _ := request(t, e, tok, orgA, map[string]any{"to": unregistered}, nil); response.Error == nil {
		t.Fatal("nested shared default allowed root")
	}
	f = newFixture()
	pin := crypto.Keccak256Hash(common.FromHex("0x6000")).Hex()
	f.runtime.SharedInfrastructure = []policybundle.SharedInfrastructure{{Address: addressA, CodeHash: &pin}}
	f.capability(policybundle.CapabilitySharedCode)
	n = &node{code: "0x6001"}
	var clock2 atomic.Int64
	e, tok, _ = engine(t, f, n, nil, &clock2)
	if response, _ := request(t, e, tok, orgA, map[string]any{"to": addressA}, nil); response.Error == nil {
		t.Fatal("shared pin mismatch fell back to literal rule")
	}
	f = newFixture()
	f.runtime.SharedInfrastructure = []policybundle.SharedInfrastructure{{Address: unregistered, CodeHash: &pin}}
	f.bindings[0].Allow = []policycore.FrameRule{{TargetClass: "eoa", Selector: "0x"}}
	f.capability(policybundle.CapabilitySharedCode)
	f.capability(policybundle.CapabilityCalldata)
	n = &node{codes: map[string]string{unregistered: ""}}
	var clock3 atomic.Int64
	e, tok, _ = engine(t, f, n, nil, &clock3)
	if response, _ := request(t, e, tok, orgA, map[string]any{"to": unregistered}, nil); response.Error == nil {
		t.Fatal("empty code bypassed shared pin through EOA fallback")
	}
}

func TestHTTPGroupClaimsCannotBeBorrowedForUpgrade(t *testing.T) {
	for _, readerHasClaim := range []bool{false, true} {
		f := newFixture()
		f.groups = append(f.groups, policybundle.Group{ID: second, Slug: "operator", Name: "Operator", AllowedMethods: []string{}, Claims: []string{"upgrade"}})
		f.roles = append(f.roles, second)
		if readerHasClaim {
			f.groups[0].Claims = []string{"upgrade"}
		}
		f.bindings[0].Allow[0].AllowUpgrade = true
		f.capability(policybundle.CapabilityUpgradeFacts)
		data := "0x3659cfe6" + common.Bytes2Hex(common.LeftPadBytes(common.HexToAddress(addressC).Bytes(), 32))
		n := &node{}
		var clock atomic.Int64
		e, tok, _ := engine(t, f, n, nil, &clock)
		response, _ := request(t, e, tok, orgA, map[string]any{"to": addressA, "input": data}, nil)
		if (response.Error == nil) != readerHasClaim {
			t.Fatalf("own claim=%v: %+v", readerHasClaim, response)
		}
	}
	f := newFixture()
	f.groups[0].Claims = []string{"upgrade"}
	f.bindings[0].Allow[0].AllowUpgrade = true
	f.capability(policybundle.CapabilityUpgradeFacts)
	n := &node{codes: map[string]string{addressC: "0xef01000000000000000000000000000000000000000001"}}
	var clock atomic.Int64
	e, tok, _ := engine(t, f, n, nil, &clock)
	data := "0x3659cfe6" + common.Bytes2Hex(common.LeftPadBytes(common.HexToAddress(addressC).Bytes(), 32))
	if response, _ := request(t, e, tok, orgA, map[string]any{"to": addressA, "input": data}, nil); response.Error == nil {
		t.Fatal("delegated upgrade destination accepted")
	}
}

func TestHTTPNoReadAdminMethodOrOrgFallback(t *testing.T) {
	for _, admin := range []bool{false, true} {
		f := newFixture()
		f.groups[0].IsOrgAdmin = admin
		f.bindings = []policycore.Binding{}
		f.contracts[0].ReadGrants = []policybundle.ReadGrant{{ID: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", GroupID: reader, EventRules: policybundle.EventRules{Mode: "all", Rules: []policybundle.EventRule{}}}}
		n := &node{}
		var clock atomic.Int64
		e, tok, _ := engine(t, f, n, nil, &clock)
		if response, _ := request(t, e, tok, orgA, map[string]any{"to": addressA}, nil); response.Error == nil {
			t.Fatal("read/admin authority bypassed empty native bindings")
		}
	}
	for name, change := range map[string]func(*fixture){"method absent": func(f *fixture) { f.groups[0].AllowedMethods = []string{"eth_getCode"} }, "ambiguous org": func(f *fixture) { f.roles = append(f.roles, foreign) }} {
		t.Run(name, func(t *testing.T) {
			f := newFixture()
			change(&f)
			n := &node{}
			var clock atomic.Int64
			e, tok, _ := engine(t, f, n, nil, &clock)
			target := addressA
			if name == "ambiguous org" {
				target = "0x5555555555555555555555555555555555555555"
			}
			response, _ := request(t, e, tok, "", map[string]any{"to": target}, nil)
			methods, _ := n.counts()
			if response.Error == nil || len(methods) > 0 {
				t.Fatalf("%s %+v %v", name, response, methods)
			}
		})
	}
	n := &node{}
	var clock atomic.Int64
	e, tok, _ := engine(t, newFixture(), n, nil, &clock)
	if response, _ := request(t, e, tok, orgA, map[string]any{"to": addressB}, nil); response.Error == nil {
		t.Fatal("foreign registered root relabeled")
	}
	if methods, _ := n.counts(); len(methods) != 0 {
		t.Fatal("foreign root reached node")
	}
}

func TestHTTPSignerIsAbsentEvenForAnAuthenticatedSimulationFrom(t *testing.T) {
	for _, alternative := range []bool{false, true} {
		f := newFixture()
		abiRaw := []byte(`[{"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"name":"who","type":"address"}],"outputs":[{"type":"uint256"}]}]`)
		var abiValue any
		json.Unmarshal(abiRaw, &abiValue)
		canonical := encoded(t, abiValue)
		f.contracts[0].ABI = canonical
		f.bindings[0].Allow = []policycore.FrameRule{{StorageAddress: addressA, Selector: "0x70a08231", ABIDigest: policycore.ABIDigest(string(canonical)), Args: []policycore.ArgConstraint{{Index: 0, AddressEquals: &policycore.AddressMatch{Source: policycore.AddressSourceSigner}}}}}
		f.capability(policybundle.CapabilitySigner)
		f.capability(policybundle.CapabilityCalldata)
		if alternative {
			f.groups = append(f.groups, policybundle.Group{ID: second, Slug: "alternative", Name: "Alternative", AllowedMethods: []string{"eth_call"}, Claims: []string{}})
			f.roles = append(f.roles, second)
			f.bindings = append(f.bindings, policycore.Binding{Group: second, Allow: []policycore.FrameRule{{StorageAddress: addressA, Selector: "*"}}})
		}
		n := &node{}
		var clock atomic.Int64
		e, tok, _ := engine(t, f, n, linkedWallets(), &clock)
		data := "0x70a08231" + common.Bytes2Hex(common.LeftPadBytes(common.HexToAddress(walletAddress).Bytes(), 32))
		response, _ := request(t, e, tok, orgA, map[string]any{"to": addressA, "from": walletAddress, "input": data}, nil)
		if (response.Error == nil) != alternative {
			t.Fatalf("alternative=%v: %+v", alternative, response)
		}
	}
}

func TestHTTPShapeFloorsAndProviderFailuresMakeNoNodeCalls(t *testing.T) {
	n := &node{}
	var clock atomic.Int64
	e, tok, _ := engine(t, newFixture(), n, nil, &clock)
	for _, body := range []string{`[]`, `{"jsonrpc":"2.0","method":"eth_call","params":[]}`, `{"jsonrpc":"2.0","id":"x","method":"alias_call","params":[]}`, `{"jsonrpc":"2.0","id":null,"method":"custom_method","params":[]}`, `{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"` + addressA + `"},"latest",{}]}`, `{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"` + addressA + `","stateOverrides":{}}]}`} {
		r := httptest.NewRequest(http.MethodPost, "/rpc", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		e.Handler(orgA).ServeHTTP(w, r)
		var response map[string]any
		json.Unmarshal(w.Body.Bytes(), &response)
		if response["error"] == nil {
			t.Fatal("shape/method accepted", body)
		}
	}
	if methods, _ := n.counts(); len(methods) != 0 {
		t.Fatal("shape floor reached node", methods)
	}
	provider := walletResolver(func(context.Context, string) (nativeadmission.WalletSnapshot, error) {
		return nativeadmission.WalletSnapshot{}, errors.New("private wallet-store detail")
	})
	n = &node{}
	var clock2 atomic.Int64
	e, tok, _ = engine(t, newFixture(), n, provider, &clock2)
	response, body := request(t, e, tok, orgA, map[string]any{"to": addressA, "from": walletAddress}, nil)
	if response.Error == nil || bytes.Contains(body, []byte("private")) {
		t.Fatal("wallet error leaked or permitted")
	}
	if methods, _ := n.counts(); len(methods) != 0 {
		t.Fatal("wallet failure reached node")
	}
}
