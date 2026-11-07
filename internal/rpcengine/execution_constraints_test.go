package rpcengine_test

import (
	"sync/atomic"
	"testing"

	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
)

func TestHTTPNativeValueCallerAndDepthApplyToActualFrames(t *testing.T) {
	for _, value := range []string{"0x1", "0x2"} {
		f := newFixture()
		maximum := "1"
		f.bindings[0].Allow[0].MaxValue = &maximum
		f.capability(policybundle.CapabilityValue)
		n := &node{}
		var clock atomic.Int64
		e, tok, _ := engine(t, f, n, nil, &clock)
		response, _ := request(t, e, tok, orgA, map[string]any{"to": addressA, "value": value}, nil)
		if (response.Error == nil) != (value == "0x1") {
			t.Fatalf("native value=%s: %+v", value, response)
		}
	}
	for _, kind := range []string{"DELEGATECALL", "CALLCODE"} {
		f := newFixture()
		rootDepth, nestedDepth := int64(0), int64(1)
		f.bindings[0].Allow[0].MaxDepth = &rootDepth
		f.bindings[0].Allow = append(f.bindings[0].Allow, policycore.FrameRule{StorageAddress: addressA, CodeAddress: addressC, Selector: "*", CallTypes: []policycore.CallType{policycore.CallTypeDelegateCall, policycore.CallTypeCallCode}, CallerAddress: walletAddress, MaxDepth: &nestedDepth})
		f.capability(policybundle.CapabilityDepth)
		f.capability(policybundle.CapabilityCaller)
		n := &node{mutate: func(root map[string]any) { root["calls"] = []any{child(kind, addressA, addressC, "0x")} }}
		var clock atomic.Int64
		e, tok, _ := engine(t, f, n, linkedWallets(), &clock)
		response, _ := request(t, e, tok, orgA, map[string]any{"to": addressA, "from": walletAddress}, nil)
		if (response.Error == nil) != (kind == "DELEGATECALL") {
			t.Fatalf("effective caller for %s: %+v", kind, response)
		}
	}
	for _, extraDepth := range []bool{false, true} {
		f := newFixture()
		maximum := int64(1)
		f.bindings[0].Allow = append(f.bindings[0].Allow, policycore.FrameRule{StorageAddress: addressC, Selector: "*", MaxDepth: &maximum})
		f.capability(policybundle.CapabilityDepth)
		n := &node{mutate: func(root map[string]any) {
			first := child("CALL", addressA, addressC, "0x")
			if extraDepth {
				first["calls"] = []any{child("CALL", addressC, addressC, "0x")}
			}
			root["calls"] = []any{first}
		}}
		var clock atomic.Int64
		e, tok, _ := engine(t, f, n, nil, &clock)
		response, _ := request(t, e, tok, orgA, map[string]any{"to": addressA}, nil)
		if (response.Error == nil) == extraDepth {
			t.Fatalf("actual depth extra=%v: %+v", extraDepth, response)
		}
	}
}

func TestHTTPRepeatedCaughtFramesStillNeedTheirOwnInputRule(t *testing.T) {
	for _, invalidCaught := range []bool{false, true} {
		f := newFixture()
		f.bindings[0].Allow = append(f.bindings[0].Allow, policycore.FrameRule{StorageAddress: addressC, Selector: "0x"})
		f.capability(policybundle.CapabilityCalldata)
		n := &node{mutate: func(root map[string]any) {
			first := child("CALL", addressA, addressC, "0x")
			first["error"] = "execution reverted"
			if invalidCaught {
				first["input"] = "0x01"
			}
			root["calls"] = []any{first, child("CALL", addressA, addressC, "0x")}
		}}
		var clock atomic.Int64
		e, tok, _ := engine(t, f, n, nil, &clock)
		response, _ := request(t, e, tok, orgA, map[string]any{"to": addressA}, nil)
		if (response.Error == nil) == invalidCaught {
			t.Fatalf("caught input invalid=%v: %+v", invalidCaught, response)
		}
	}
}

func TestHTTPStaticOmissionAndOpcodeRemainDistinct(t *testing.T) {
	for _, kind := range []string{"STATICCALL", "CALL"} {
		f := newFixture()
		f.bindings[0].Allow = append(f.bindings[0].Allow, policycore.FrameRule{StorageAddress: addressC, Selector: "*", CallTypes: []policycore.CallType{policycore.CallTypeStaticCall}})
		n := &node{mutate: func(root map[string]any) {
			frame := child(kind, addressA, addressC, "0x")
			if kind == "STATICCALL" {
				delete(frame, "value")
			}
			root["calls"] = []any{frame}
		}}
		var clock atomic.Int64
		e, tok, _ := engine(t, f, n, nil, &clock)
		response, _ := request(t, e, tok, orgA, map[string]any{"to": addressA}, nil)
		if (response.Error == nil) != (kind == "STATICCALL") {
			t.Fatalf("opcode %s: %+v", kind, response)
		}
	}
	// Approved scope metadata cannot label an empty EOA as an owned contract.
	f := newFixture()
	f.runtime.AddressScopes = []policybundle.AddressScope{{Address: addressA, OrganizationID: orgA}}
	f.capability(policybundle.CapabilityAddressScopes)
	n := &node{codes: map[string]string{addressA: ""}}
	var clock atomic.Int64
	e, tok, _ := engine(t, f, n, nil, &clock)
	response, _ := request(t, e, tok, orgA, map[string]any{"to": addressA}, nil)
	if response.Error == nil {
		t.Fatal("empty scoped address gained registered contract authority")
	}
}
