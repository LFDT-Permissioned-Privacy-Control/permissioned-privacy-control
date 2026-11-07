package rpcexecution

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestMetadataNetworkAndRPCFailuresStop(t *testing.T) {
	for _, name := range []string{"chain", "genesis", "incomplete-header", "header-hash", "rpc-id", "rpc-version", "rpc-error", "rpc-unknown", "rpc-duplicate", "wire-limit"} {
		t.Run(name, func(t *testing.T) {
			n, s, tr := metadataFixture(t)
			l := DefaultMetadataLimits()
			expected := 3
			n.mu.Lock()
			switch name {
			case "chain":
				n.chain, expected = "0x2", 1
			case "genesis":
				s.Network.GenesisHash, expected = "0x"+strings.Repeat("12", 32), 2
			case "incomplete-header", "header-hash":
				expected = 2
				n.change = func(w http.ResponseWriter, _ *http.Request, r metadataTestRPC) bool {
					if r.Method != "eth_getHeaderByNumber" {
						return false
					}
					var value any = map[string]any{"number": "0x0", "timestamp": "0x1", "hash": s.Network.GenesisHash}
					if name == "header-hash" {
						raw, _ := json.Marshal(n.genesis)
						var m map[string]any
						_ = json.Unmarshal(raw, &m)
						m["hash"] = "0x" + strings.Repeat("12", 32)
						value = m
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": r.ID, "result": value})
					return true
				}
			default:
				if name == "wire-limit" {
					l.MaxResultBytes = 128
				}
				n.change = func(w http.ResponseWriter, _ *http.Request, r metadataTestRPC) bool {
					if r.Method != "eth_gasPrice" {
						return false
					}
					response := map[string]any{"jsonrpc": "2.0", "id": r.ID, "result": "0x1"}
					switch name {
					case "rpc-id":
						response["id"] = r.ID + 1
					case "rpc-version":
						response["jsonrpc"] = "1.0"
					case "rpc-error":
						response["error"] = map[string]any{"code": -32000, "message": "PRIVATE-NODE-DETAIL", "data": "PRIVATE-NODE-DETAIL"}
					case "rpc-unknown":
						response["other"] = true
					case "rpc-duplicate":
						_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":"0x1","result":"0x2"}`, r.ID)
						return true
					case "wire-limit":
						response["result"] = strings.Repeat("a", 1024)
					}
					_ = json.NewEncoder(w).Encode(response)
					return true
				}
			}
			n.mu.Unlock()
			obs, err := metadataClient(t, s, tr, l).Query(t.Context(), metadataQuery(t, MetadataGasPrice, "[]"))
			if err == nil || obs != nil || strings.Contains(err.Error(), "PRIVATE-NODE-DETAIL") {
				t.Fatal("failure returned authority/output/private error", err)
			}
			n.mu.Lock()
			count := len(n.calls)
			n.mu.Unlock()
			if count != expected {
				t.Fatal("continued after failed check", count, expected)
			}
		})
	}
}

func TestMetadataColdBindingAndLowerOnlyLimits(t *testing.T) {
	_, base, _ := metadataFixture(t)
	tr := headerLaneTransportFunc(func(*http.Request) (*http.Response, error) { t.Fatal("constructor touched node"); return nil, nil })
	for _, name := range []string{"chain-zero", "chain-overflow", "genesis-zero", "URL-user", "URL-host", "URL-fragment", "credential", "header", "empty-credential", "timeout", "params", "result", "accounts", "history", "percentiles"} {
		t.Run(name, func(t *testing.T) {
			s, l, credential := base, DefaultMetadataLimits(), Credential{base.CredentialHeader, "metadata-test-only"}
			switch name {
			case "chain-zero":
				s.Network.ChainID = "0"
			case "chain-overflow":
				s.Network.ChainID = "18446744073709551616"
			case "genesis-zero":
				s.Network.GenesisHash = "0x" + strings.Repeat("00", 32)
			case "URL-user":
				s.URL = "https://user@node.example"
			case "URL-host":
				s.URL = "https://:443"
			case "URL-fragment":
				s.URL += "#part"
			case "credential":
				credential.Value = "secret\nother"
			case "header":
				s.CredentialHeader, credential.Header = "Host", "Host"
			case "empty-credential":
				s.CredentialRef, s.CredentialHeader, credential = "", "", Credential{}
			case "timeout":
				l.Timeout = 6 * time.Second
			case "params":
				l.MaxParamsBytes++
			case "result":
				l.MaxResultBytes++
			case "accounts":
				l.MaxAccounts++
			case "history":
				l.MaxHistoryBlocks++
			case "percentiles":
				l.MaxPercentiles = 0
			}
			if c, err := NewMetadataClient(tr, s, credential, l); err == nil || c != nil {
				t.Fatal("invalid startup accepted", name)
			}
		})
	}
	s := base
	s.AllowUnauthenticated, s.CredentialRef, s.CredentialHeader = true, "", ""
	c, err := NewMetadataClient(tr, s, Credential{}, DefaultMetadataLimits())
	if err != nil {
		t.Fatal("explicit uncredentialed source refused", err)
	}
	if _, err := c.Query(t.Context(), metadataQuery(t, MetadataKeccak, `["0x"]`)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.wire.AcquireCall(context.Background(), Call{}, BlockSelector{}); err == nil {
		t.Fatal("metadata profile activated execution")
	}
}

func TestMetadataLowerCollectionsAndShapeBudget(t *testing.T) {
	l := DefaultMetadataLimits()
	l.MaxAccounts = 1
	q := metadataQuery(t, MetadataAccounts, "[]")
	if _, err := metadataResult(q, []byte(`["0x`+strings.Repeat("ab", 20)+`","0x`+strings.Repeat("ab", 20)+`"]`), l); err == nil {
		t.Fatal("lower account collection ignored")
	}
	// This would build millions of entries if checking count after Unmarshal.
	if _, err := metadataJSON([]byte(`[` + strings.Repeat(`0,`, 120001) + `0]`)); err == nil {
		t.Fatal("global value budget ignored")
	}
	if _, err := metadataJSON([]byte(strings.Repeat("[", 34) + "0" + strings.Repeat("]", 34))); err == nil {
		t.Fatal("depth budget ignored")
	}
	l.MaxParamsBytes = 6
	if _, err := ParseMetadataQuery(MetadataKeccak, []byte(`["0x01"]`), l); err == nil {
		t.Fatal("input byte bound ignored")
	}
	// Maximal permitted local input still stays within the one-MiB request cap.
	l = DefaultMetadataLimits()
	params := []byte(`["0x` + strings.Repeat("ab", int((l.MaxParamsBytes-6)/2)) + `"]`)
	if _, err := ParseMetadataQuery(MetadataKeccak, params, l); err != nil {
		t.Fatal("max local input failed", err)
	}
	if _, err := ParseMetadataQuery(MetadataKeccak, append(params, ' '), l); err == nil {
		t.Fatal("one-over raw input accepted")
	}
}

// Keep an actual malformed body read in the transport controls: a successful
// HTTP status is not evidence of a complete JSON-RPC result.
func TestMetadataTruncatedActualBody(t *testing.T) {
	n, s, tr := metadataFixture(t)
	n.mu.Lock()
	n.change = func(w http.ResponseWriter, _ *http.Request, req metadataTestRPC) bool {
		if req.Method != "eth_gasPrice" {
			return false
		}
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":`)
		return true
	}
	n.mu.Unlock()
	if obs, err := metadataClient(t, s, tr, DefaultMetadataLimits()).Query(t.Context(), metadataQuery(t, MetadataGasPrice, "[]")); err == nil || obs != nil {
		t.Fatal("truncated body accepted")
	}
}
