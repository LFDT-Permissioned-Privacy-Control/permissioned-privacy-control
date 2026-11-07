package rpcengine_test

import (
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
	"privacy-proxy/internal/rpcengine"
)

// Ports the independently reproduced committed-handler regression and extends
// it to both existing raw profiles and the new multi-org constructor.
func TestRegisteredEmptyCodeKeepsIsolationAcrossNativeConstructors(t *testing.T) {
	database := rawPostgres(t)
	for _, mode := range []string{"legacy-call", "legacy-raw", "legacy-guard", "multi-raw", "multi-guard"} {
		mount := func(t *testing.T, f fixture, n *node) (*rpcengine.Engine, string) {
			t.Helper()
			if mode == "legacy-call" {
				var clock atomic.Int64
				e, jwt, _ := engine(t, f, n, nil, &clock)
				return e, jwt
			}
			f.rawMode = policybundle.RawSubmissionOPSPreflight
			if mode == "legacy-guard" || mode == "multi-guard" {
				f.rawMode = policybundle.RawSubmissionGuardV1
			}
			e, jwt, _, _ := mountedRawEngine(t, f, n, database, mode == "multi-raw" || mode == "multi-guard")
			return e, jwt
		}
		for _, row := range []struct {
			name, address, code string
			allowed             bool
		}{
			{"registered-B-empty", addressB, "", false},
			{"registered-B-coded", addressB, "0x6000", false},
			{"registered-A-empty-is-not-unregistered-EOA", addressC, "", false},
			{"unregistered-empty", "0x5555555555555555555555555555555555555555", "", true},
		} {
			t.Run(mode+"/"+row.name, func(t *testing.T) {
				f := newFixture()
				f.capability(policybundle.CapabilityCalldata)
				f.bindings[0].Allow = append(f.bindings[0].Allow, policycore.FrameRule{TargetClass: "eoa", Selector: "0x"})
				n := &node{codes: map[string]string{row.address: row.code}, mutate: func(root map[string]any) { root["calls"] = []any{child("CALL", addressA, row.address, "0x")} }}
				e, jwt := mount(t, f, n)
				out, _ := request(t, e, jwt, orgA, map[string]any{"to": addressA}, nil)
				if (out.Error == nil) != row.allowed {
					t.Fatalf("registered isolation: expected allow=%v, %+v", row.allowed, out)
				}
			})
		}
		for _, emptyStorage := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/operational-mask/empty=%v", mode, emptyStorage), func(t *testing.T) {
				f := newFixture()
				f.groups[0].IsOrgAdmin = true
				f.capability(policybundle.CapabilityUpgradeFacts)
				f.bindings[0].Allow = append(f.bindings[0].Allow, policycore.FrameRule{StorageAddress: addressC, Selector: "*", AllowUpgrade: true})
				code := "0x6000"
				if emptyStorage {
					code = ""
				}
				input := "0x3659cfe6" + common.Bytes2Hex(common.LeftPadBytes(common.HexToAddress(addressA).Bytes(), 32))
				n := &node{codes: map[string]string{addressC: code}, mutate: func(root map[string]any) { root["calls"] = []any{child("CALL", addressA, addressC, input)} }}
				e, jwt := mount(t, f, n)
				out, _ := request(t, e, jwt, orgA, map[string]any{"to": addressA}, nil)
				if (out.Error == nil) == emptyStorage {
					t.Fatal("registry-only storage minted operational mask", out)
				}
			})
			t.Run(fmt.Sprintf("%s/upgrade-target/empty=%v", mode, emptyStorage), func(t *testing.T) {
				f := newFixture()
				f.groups[0].IsOrgAdmin = true
				f.capability(policybundle.CapabilityUpgradeFacts)
				f.bindings[0].Allow[0].AllowUpgrade = true
				code := "0x6000"
				if emptyStorage {
					code = ""
				}
				input := "0x3659cfe6" + common.Bytes2Hex(common.LeftPadBytes(common.HexToAddress(addressC).Bytes(), 32))
				n := &node{codes: map[string]string{addressC: code}}
				e, jwt := mount(t, f, n)
				out, _ := request(t, e, jwt, orgA, map[string]any{"to": addressA, "input": input}, nil)
				if (out.Error == nil) == emptyStorage {
					t.Fatal("registry-only upgrade target became code-qualified", out)
				}
			})
		}
	}
}
