package activitylog_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	stdnet "net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	a "privacy-proxy/internal/activitylog"
	"privacy-proxy/internal/audit/buffer"
	"privacy-proxy/internal/networkidentity"
	s "privacy-proxy/internal/operational/activitysql"
	"privacy-proxy/internal/operational/rpcactivity"
	"privacy-proxy/internal/policybundle"
)

func rpcRecorder(t *testing.T, x *database, clock func() time.Time, hook func(uint64) error) *a.Recorder {
	t.Helper()
	writer, err := s.OpenWriter(t.Context(), x.writer, x.scope)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(writer.Close)
	c := a.Config{Network: x.registration.Network, SourceID: x.scope.SourceID, ExpectedGeneration: x.scope.ExpectedGeneration, ProducerID: uuid.NewString(), Configuration: a.Digest(x.registration.Configuration), Clock: clock, BufferDirectory: t.TempDir(), Methods: []string{"eth_call", "eth_sendRawTransaction", "rpc.invalid_request", "rpc.invalid_transport"}, Limits: a.Limits{InFlight: 1, BufferedEntries: 64, BufferedBytes: 64 * a.MaxEncodedBytes, SealBatch: 16}}
	var options []buffer.Option
	if hook != nil {
		options = append(options, buffer.WithBeforeSetForTest(hook))
	}
	recorder, err := a.NewRecorderForTest(t.Context(), c, writer, options...)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- recorder.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := recorder.Close(ctx); err != nil {
			t.Error("owned recorder close", err)
		}
		<-done
	})
	return recorder
}
func requestAsync(t *testing.T, client *http.Client, url, tok, body string, ctx context.Context) <-chan []byte {
	t.Helper()
	done := make(chan []byte, 1)
	go func() {
		req, _ := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := client.Do(req)
		if err != nil {
			done <- nil
			return
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		done <- b
	}()
	return done
}
func await(t *testing.T, c <-chan struct{}) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(3 * time.Second):
		t.Fatal("owned operation checkpoint timed out")
	}
}
func bodyResult(t *testing.T, c <-chan []byte) []byte {
	t.Helper()
	select {
	case b := <-c:
		return b
	case <-time.After(4 * time.Second):
		t.Fatal("owned operation did not settle")
		return nil
	}
}

func TestRPCActivityActualTLSAppendExpiryEffectsAndSharedCap(t *testing.T) {
	d := rawPostgres(t)
	if _, err := d.owner.Exec(t.Context(), `CREATE ROLE raw_observer LOGIN PASSWORD 'raw-test-only';CREATE ROLE raw_facts LOGIN PASSWORD 'raw-test-only'`); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{policybundle.RawSubmissionOPSPreflight, policybundle.RawSubmissionGuardV1} {
		t.Run(mode, func(t *testing.T) {
			f := creationIntentRuntimeFixture()
			f.creationObserved = true
			f.rawMode = mode
			var instant atomic.Int64
			instant.Store(now)
			f.clock = &instant
			n := &node{}
			e, tok, financial, _ := mountedRawEngine(t, f, n, d, false)
			net := financial.Metadata().Network
			network := networkidentity.Binding{Environment: net.Environment, ChainID: net.ChainID, GenesisHash: net.GenesisHash, DeploymentID: net.DeploymentID}
			x := setupActivityDatabase(t, network)
			call := `{"jsonrpc":"2.0","id":"one","method":"eth_call","params":[{"to":"` + addressA + `","data":"0x0102"}]}`
			for _, scenario := range []string{"success", "expiry-after-append", "revert-expiry-after-append", "cancel-during-append", "shared-http-cap-after-complete", "append-failure-after-broadcast", "transport-rejection"} {
				t.Run(scenario, func(t *testing.T) {
					instant.Store(now)
					var beforeRows int64
					if err := x.owner.QueryRow(t.Context(), `SELECT row_count FROM ops_activity_v1.sources WHERE network_key=$1`, x.scope.NetworkKey[:]).Scan(&beforeRows); err != nil {
						t.Fatal(err)
					}
					n.mu.Lock()
					n.mutate = nil
					n.methods = nil
					n.mu.Unlock()
					if scenario == "revert-expiry-after-append" {
						n.mutate = func(root map[string]any) { root["error"] = "execution reverted"; root["output"] = "0xdead" }
					}
					entered, release := make(chan struct{}), make(chan struct{})
					var once sync.Once
					defer once.Do(func() { close(release) })
					hook := func(uint64) error {
						close(entered)
						<-release
						if scenario == "append-failure-after-broadcast" {
							return errors.New("owned actual Pebble beforeSet fault")
						}
						return nil
					}
					recorder := rpcRecorder(t, x, func() time.Time { return time.Unix(instant.Load(), 0) }, hook)
					service, err := rpcactivity.New(rpcactivity.Config{Engine: e, Recorder: recorder, Network: network})
					if err != nil {
						t.Fatal(err)
					}
					if _, err := service.Handler("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"); err == nil {
						t.Fatal("unknown configured organization mounted")
					}
					for _, part := range []string{"genesis", "deployment"} {
						badNetwork := network
						if part == "genesis" {
							badNetwork.GenesisHash = "0x" + strings.Repeat("a", 64)
						} else {
							badNetwork.DeploymentID += "-other"
						}
						if _, err := rpcactivity.New(rpcactivity.Config{Engine: e, Recorder: recorder, Network: badNetwork}); err == nil {
							t.Fatal("same chain different strong network mixed", part)
						}
					}
					h, _ := service.Handler(orgA)
					alias, _ := service.Handler("")
					writeEntered, writeRelease := make(chan struct{}), make(chan struct{})
					var writeOnce sync.Once
					defer writeOnce.Do(func() { close(writeRelease) })
					mux := http.NewServeMux()
					mux.Handle("/alias", alias)
					mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if scenario == "shared-http-cap-after-complete" {
							h.ServeHTTP(&blockedWriter{ResponseWriter: w, entered: writeEntered, release: writeRelease}, r)
						} else {
							h.ServeHTTP(w, r)
						}
					}))
					server := httptest.NewTLSServer(mux)
					t.Cleanup(server.Close)
					body := call
					var hash string
					if scenario == "append-failure-after-broadcast" {
						tx := signedValue(t, uint64(900+len(mode)))
						hash = tx.Hash().Hex()
						body = `{"jsonrpc":"2.0","id":"one","method":"eth_sendRawTransaction","params":["` + tx.RawHex() + `"]}`
					}
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					var done <-chan []byte
					if scenario == "transport-rejection" {
						doneChan := make(chan []byte, 1)
						done = doneChan
						go func() {
							resp, err := server.Client().Get(server.URL)
							if err != nil {
								doneChan <- nil
								return
							}
							defer resp.Body.Close()
							b, _ := io.ReadAll(resp.Body)
							doneChan <- b
						}()
					} else {
						done = requestAsync(t, server.Client(), server.URL, tok, body, ctx)
					}
					await(t, entered)
					if scenario == "expiry-after-append" || scenario == "revert-expiry-after-append" {
						instant.Store(now + 300)
					}
					if scenario == "cancel-during-append" {
						cancel()
					}
					before, _ := n.counts()
					busy := requestAsync(t, server.Client(), server.URL+"/alias", tok, call, t.Context())
					if b := bodyResult(t, busy); !bytes.Contains(b, []byte(`"code":-32002`)) {
						t.Fatal("shared alias bypassed blocked Append", string(b))
					}
					after, _ := n.counts()
					if len(before) != len(after) {
						t.Fatal("busy request reached node", before, after)
					}
					once.Do(func() { close(release) })
					if scenario == "shared-http-cap-after-complete" {
						await(t, writeEntered)
						b := bodyResult(t, requestAsync(t, server.Client(), server.URL+"/alias", tok, call, t.Context()))
						if !bytes.Contains(b, []byte(`"code":-32002`)) {
							t.Fatal("HTTP slot released before actual write", string(b))
						}
						writeOnce.Do(func() { close(writeRelease) })
					}
					got := bodyResult(t, done)
					switch scenario {
					case "success", "shared-http-cap-after-complete":
						if !bytes.Contains(got, []byte("0xfeed")) {
							t.Fatal(string(got))
						}
					case "expiry-after-append", "revert-expiry-after-append":
						if bytes.Contains(got, []byte("0xfeed")) || bytes.Contains(got, []byte("0xdead")) || !bytes.Contains(got, []byte(`"code":-32002`)) {
							t.Fatal("expired output leaked", string(got))
						}
					case "append-failure-after-broadcast":
						if !bytes.Contains(got, []byte(`"code":-32004`)) || !bytes.Contains(got, []byte(hash)) {
							t.Fatal("attempt lost actual hash", string(got))
						}
						methods, _ := n.counts()
						sends := 0
						for _, m := range methods {
							if m == "eth_sendRawTransaction" {
								sends++
							}
						}
						if sends != 1 {
							t.Fatal("action replayed or not performed", methods)
						}
					case "transport-rejection":
						if !bytes.Contains(got, []byte(`"code":-32600`)) {
							t.Fatal(string(got))
						}
					}
					instant.Store(now)
					if scenario != "append-failure-after-broadcast" {
						deadline := time.Now().Add(3 * time.Second)
						for {
							var rows int64
							err := x.owner.QueryRow(t.Context(), `SELECT row_count FROM ops_activity_v1.sources WHERE network_key=$1`, x.scope.NetworkKey[:]).Scan(&rows)
							if err == nil && rows == beforeRows+1 {
								var raw []byte
								if err := x.owner.QueryRow(t.Context(), `SELECT l.request_params FROM ops_activity_v1.qualified_logs l JOIN ops_activity_v1.sources s ON l.chain_name=s.chain_name AND l.id=s.head_id WHERE s.network_key=$1`, x.scope.NetworkKey[:]).Scan(&raw); err != nil {
									t.Fatal(err)
								}
								var envelope a.Envelope
								if json.Unmarshal(raw, &envelope) != nil || len(raw) > a.MaxEncodedBytes || bytes.Contains(raw, []byte(tok)) {
									t.Fatal("invalid or sensitive completion metadata")
								}
								if scenario == "transport-rejection" {
									if envelope.ActorID != "" || envelope.DataOrg != "" || envelope.Method != "rpc.invalid_transport" || envelope.HTTP != 405 || envelope.Outcome != string(a.Invalid) {
										t.Fatal("transport attribution/outcome", envelope)
									}
								} else {
									expectedOutcome := string(a.Success)
									if scenario == "revert-expiry-after-append" {
										expectedOutcome = string(a.EvaluationFailed)
									}
									if envelope.ActorID == "" || envelope.DataOrg != orgA || envelope.Policy != strings.TrimPrefix(string(e.OperationBinding().ManifestDigest), "sha256:") || envelope.Method != "eth_call" || envelope.HTTP != 200 || envelope.Outcome != expectedOutcome {
										t.Fatal("selected operation rewritten by delivery/expiry", envelope)
									}
								}
								break
							}
							if err != nil || rows > beforeRows+1 || time.Now().After(deadline) {
								t.Fatal("actual SQL seal did not match exactly one local completion", rows, beforeRows, err)
							}
							time.Sleep(10 * time.Millisecond)
						}
					}
				})
			}
		})
	}
}

type blockedWriter struct {
	http.ResponseWriter
	entered chan struct{}
	release <-chan struct{}
}

func (w *blockedWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *blockedWriter) Write(b []byte) (int, error) {
	close(w.entered)
	<-w.release
	return w.ResponseWriter.Write(b)
}

func TestRPCActivityActualSlowBodyDeadlineReleasesHTTPGate(t *testing.T) {
	d := rawPostgres(t)
	if _, err := d.owner.Exec(t.Context(), `CREATE ROLE raw_observer LOGIN PASSWORD 'raw-test-only';CREATE ROLE raw_facts LOGIN PASSWORD 'raw-test-only'`); err != nil {
		t.Fatal(err)
	}
	f := creationIntentRuntimeFixture()
	f.creationObserved = true
	n := &node{}
	e, _, financial, _ := mountedRawEngine(t, f, n, d, false)
	net := financial.Metadata().Network
	network := networkidentity.Binding{Environment: net.Environment, ChainID: net.ChainID, GenesisHash: net.GenesisHash, DeploymentID: net.DeploymentID}
	x := setupActivityDatabase(t, network)
	recorder := rpcRecorder(t, x, func() time.Time { return time.Unix(now, 0) }, nil)
	service, err := rpcactivity.New(rpcactivity.Config{Engine: e, Recorder: recorder, Network: network})
	if err != nil {
		t.Fatal(err)
	}
	handler, _ := service.Handler(orgA)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 75*time.Millisecond)
		defer cancel()
		handler.ServeHTTP(w, r.WithContext(ctx))
	}))
	defer server.Close()
	// A raw owned TLS peer lets us observe the SERVER socket deadline directly;
	// net/http's upload goroutine can otherwise wait for an io.Pipe body even
	// after its connection was closed, obscuring the tested boundary.
	connection, err := tls.Dial("tcp", server.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := fmt.Fprintf(connection, "POST / HTTP/1.1\r\nHost: ops.test\r\nContent-Length: 100\r\n\r\n{"); err != nil {
		t.Fatal(err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var scratch [1024]byte
	nread, readErr := connection.Read(scratch[:])
	if timeout, ok := readErr.(stdnet.Error); ok && timeout.Timeout() {
		t.Fatal("server did not bound slow body socket", readErr)
	}
	if nread > 0 && bytes.Contains(scratch[:nread], []byte("0xfeed")) {
		t.Fatal("slow body reached protected output")
	}
	connection.Close()
	client := server.Client()
	methods, _ := n.counts()
	if len(methods) != 0 {
		t.Fatal("slow body reached node", methods)
	}
	// The deadline may prevent any JSON error body. A fresh actual request proves
	// the handler has released the shared HTTP slot and recorder reservation.
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 405 {
		t.Fatal("slot leaked after body deadline", response.StatusCode)
	}
}

// An actual broadcast can complete its node effect before cancellation or View
// expiry becomes observable. Its original outcome is separate from delivery.
func TestRPCActivityActualBroadcastCancelExpirySelectedOutcome(t *testing.T) {
	d := rawPostgres(t)
	if _, err := d.owner.Exec(t.Context(), `CREATE ROLE raw_observer LOGIN PASSWORD 'raw-test-only';CREATE ROLE raw_facts LOGIN PASSWORD 'raw-test-only'`); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{policybundle.RawSubmissionOPSPreflight, policybundle.RawSubmissionGuardV1} {
		t.Run(mode, func(t *testing.T) {
			f := creationIntentRuntimeFixture()
			f.creationObserved = true
			f.linkSigner = true // actual wallet proof qualifies the committed origin oracle
			f.rawMode = mode
			var instant atomic.Int64
			instant.Store(now)
			f.clock = &instant
			n := &node{}
			engine, tok, financial, _ := mountedRawEngine(t, f, n, d, false)
			binding := financial.Metadata().Network
			network := networkidentity.Binding{Environment: binding.Environment, ChainID: binding.ChainID, GenesisHash: binding.GenesisHash, DeploymentID: binding.DeploymentID}
			x := setupActivityDatabase(t, network)
			for i, scenario := range []string{"cancel", "expiry-ack", "expiry-bad-reply"} {
				t.Run(scenario, func(t *testing.T) {
					instant.Store(now)
					var before int64
					if err := x.owner.QueryRow(t.Context(), `SELECT row_count FROM ops_activity_v1.sources WHERE network_key=$1`, x.scope.NetworkKey[:]).Scan(&before); err != nil {
						t.Fatal(err)
					}
					recorder := rpcRecorder(t, x, func() time.Time { return time.Unix(instant.Load(), 0) }, nil)
					service, err := rpcactivity.New(rpcactivity.Config{Engine: engine, Recorder: recorder, Network: network})
					if err != nil {
						t.Fatal(err)
					}
					handler, _ := service.Handler(orgA)
					ready := make(chan struct{})
					var cancelOperation context.CancelFunc
					server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						ctx, cancel := context.WithCancel(r.Context())
						defer cancel()
						cancelOperation = cancel
						close(ready)
						handler.ServeHTTP(w, r.WithContext(ctx))
					}))
					defer server.Close()
					tx := signedValue(t, uint64(9000+i))
					hash := tx.Hash().Hex()
					var sends atomic.Int64
					n.mu.Lock()
					n.onSend = func(raw string) string {
						sends.Add(1)
						<-ready
						if raw != tx.RawHex() {
							t.Error("broadcast altered original signed transaction")
						}
						if scenario == "cancel" {
							cancelOperation()
						} else {
							instant.Store(now + 300)
						}
						if scenario == "expiry-bad-reply" {
							return "0x" + strings.Repeat("0", 64)
						}
						return hash
					}
					n.mu.Unlock()
					body := `{"jsonrpc":"2.0","id":"submission","method":"eth_sendRawTransaction","params":["` + tx.RawHex() + `"]}`
					got := bodyResult(t, requestAsync(t, server.Client(), server.URL, tok, body, t.Context()))
					if sends.Load() != 1 || !bytes.Contains(got, []byte(`"code":-32004`)) || !bytes.Contains(got, []byte(hash)) || bytes.Contains(got, []byte(`"result"`)) {
						t.Fatal("broadcast outcome/delivery/resend", sends.Load(), string(got))
					}
					var origins int
					key := financial.Metadata().NetworkKey
					if err := d.owner.QueryRow(t.Context(), `SELECT count(*) FROM ops_admission_v2.qualified_tx_origins WHERE network_key=$1 AND tx_hash=$2`, key[:], tx.Hash().Bytes()).Scan(&origins); err != nil || origins != 1 {
						t.Fatal("missing original committed origin", origins, err)
					}
					instant.Store(now)
					deadline := time.Now().Add(3 * time.Second)
					for {
						var raw []byte
						var count int64
						err := x.owner.QueryRow(t.Context(), `SELECT s.row_count,l.request_params FROM ops_activity_v1.sources s JOIN ops_activity_v1.qualified_logs l ON l.chain_name=s.chain_name AND l.id=s.head_id WHERE s.network_key=$1`, x.scope.NetworkKey[:]).Scan(&count, &raw)
						if err == nil && count == before+1 {
							var record a.Envelope
							if json.Unmarshal(raw, &record) != nil {
								t.Fatal("invalid sealed metadata")
							}
							expected := a.Unconfirmed
							expectedStatus := uint16(502)
							if scenario == "expiry-ack" {
								expected = a.Success
								expectedStatus = 200
							}
							if record.Outcome != string(expected) || record.Status != expectedStatus || record.HTTP != 200 || record.ActorID == "" || record.DataOrg != orgA || record.Method != "eth_sendRawTransaction" {
								t.Fatal("selected effect relabelled", scenario, record)
							}
							if scenario == "expiry-ack" {
								if record.RPCError != nil {
									t.Fatal("ack code fabricated")
								}
							} else if record.RPCError == nil || *record.RPCError != -32004 {
								t.Fatal("unconfirmed code changed", record)
							}
							break
						}
						if time.Now().After(deadline) {
							t.Fatal("actual broadcast completion not sealed once", count, before, err)
						}
						time.Sleep(10 * time.Millisecond)
					}
				})
			}
		})
	}
}
