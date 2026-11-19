package activitylog_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	a "privacy-proxy/internal/activitylog"
	"privacy-proxy/internal/audit/buffer"
	"privacy-proxy/internal/audit/sealer"
	"privacy-proxy/internal/operational/rpcactivity"
)

// This fixture tests actual local Pebble append/output ownership, not SQL
// sealing or a production node. Undefined sealing calls fail rather than
// manufacturing sealed history; these tests never start a background sealer.
type fairnessLocalStore struct{ metadata a.StoreMetadata }
type fairnessLocalRun struct {
	binding a.RunBinding
}

func (s fairnessLocalStore) Metadata() a.StoreMetadata { return s.metadata }
func (s fairnessLocalStore) StartRun(_ context.Context, q a.RunRequest) (a.RunStore, error) {
	return &fairnessLocalRun{binding: a.RunBinding{Metadata: s.metadata, ProducerID: q.ProducerID, RunID: q.RunID, RangeIndex: 1, Base: 1 << 40, Top: 2<<40 - 1}}, nil
}
func (r *fairnessLocalRun) Binding() a.RunBinding                                  { return r.binding }
func (r *fairnessLocalRun) HighWater(context.Context) (uint64, error)              { return 0, nil }
func (r *fairnessLocalRun) RangeHighWater(context.Context, uint64) (uint64, error) { return 0, nil }
func (r *fairnessLocalRun) Verify(_ context.Context, entries []buffer.Entry) ([]sealer.Verdict, error) {
	out := make([]sealer.Verdict, len(entries))
	for i := range out {
		out[i] = sealer.Missing
	}
	return out, nil
}
func (r *fairnessLocalRun) SealOne(context.Context, uint64, []byte) error {
	return errors.New("local-only fixture does not seal")
}
func (r *fairnessLocalRun) SealBatch(context.Context, []buffer.Entry) error {
	return errors.New("local-only fixture does not seal")
}
func (r *fairnessLocalRun) Settle(context.Context, uint64, []buffer.Entry) (uint64, error) {
	return 0, errors.New("local-only fixture does not seal")
}

func TestLocalFairnessActualAppendOutputAndIdentityBinding(t *testing.T) {
	for _, phase := range []string{"append", "output"} {
		t.Run(phase, func(t *testing.T) {
			n := newMetadataNode(t)
			fixture := metadataFixture()
			snapshot := fixture.load(t)
			var instant atomic.Int64
			instant.Store(now)
			clock := func() time.Time { return time.Unix(instant.Load(), 0) }
			engine := metadataEngine(t, metadataConfig(t, n, snapshot, &instant, []string{}))
			network := n.network()
			key, _ := network.Key()
			generation, source := uuid.NewString(), uuid.NewString()
			methods := append([]string{"rpc.invalid_request", "rpc.invalid_transport"}, engine.OperationBinding().Methods...)
			slices.Sort(methods)
			methods = slices.Compact(methods)
			cfg := a.Config{Network: network, SourceID: source, ExpectedGeneration: generation, ProducerID: uuid.NewString(), Configuration: a.Digest{1}, Clock: clock, BufferDirectory: t.TempDir(), Methods: methods, Limits: a.Limits{InFlight: 256, BufferedEntries: 1024, BufferedBytes: 2 << 20, SealBatch: 16}}
			store := fairnessLocalStore{a.StoreMetadata{NetworkKey: a.Digest(key), SourceID: source, Generation: generation, Configuration: cfg.Configuration, Format: a.Format()}}
			enteredAppend, release := make(chan struct{}, 50), make(chan struct{})
			var once sync.Once
			defer once.Do(func() { close(release) })
			var appends atomic.Int32
			recorder, err := a.NewRecorderForTest(t.Context(), cfg, store, buffer.WithBeforeSetForTest(func(uint64) error {
				appends.Add(1)
				if phase == "append" {
					enteredAppend <- struct{}{}
					<-release
				}
				return nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			var server *httptest.Server
			t.Cleanup(func() {
				once.Do(func() { close(release) })
				if server != nil {
					server.Close()
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := recorder.Close(ctx); err != nil {
					t.Error(err)
				}
			})
			serviceConfig := rpcactivity.Config{Snapshot: snapshot, Clock: clock, Metadata: engine, Recorder: recorder, Network: network}
			service, err := rpcactivity.New(serviceConfig)
			if err != nil {
				t.Fatal(err)
			}
			bad := serviceConfig
			bad.Snapshot = fixture.load(t)
			if bad.Snapshot == snapshot {
				t.Fatal("snapshot negative fixture aliases")
			}
			if _, err := rpcactivity.New(bad); err == nil {
				t.Fatal("distinct snapshot object admitted")
			}
			bad = serviceConfig
			bad.Clock = nil
			if _, err := rpcactivity.New(bad); err == nil {
				t.Fatal("nil assembly clock")
			}
			bad = serviceConfig
			bad.Snapshot = nil
			if _, err := rpcactivity.New(bad); err == nil {
				t.Fatal("nil selected snapshot")
			}
			handler, err := service.Handler(orgA)
			if err != nil {
				t.Fatal(err)
			}
			readEntered, writeEntered := make(chan struct{}, 50), make(chan struct{}, 50)
			server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/slow" {
					r.Body = &fairnessReadSignal{ReadCloser: r.Body, entered: readEntered}
					if phase == "output" {
						w = &fairnessWriteHold{ResponseWriter: w, entered: writeEntered, release: release}
					}
				}
				handler.ServeHTTP(w, r)
			}))
			tok := token(t, snapshot, []string{reader})
			other := tokenSubject(t, snapshot, []string{reader}, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
			body := `{"jsonrpc":"2.0","id":1,"method":"web3_sha3","params":["0x"]}`
			done := make(chan int, 50)
			var cancels []context.CancelFunc
			for i := 0; i < 50; i++ {
				ctx, cancel := context.WithCancel(t.Context())
				cancels = append(cancels, cancel)
				go func() { code, _ := fairnessRequest(server, ctx, tok, "/slow", body); done <- code }()
			}
			for _, cancel := range cancels {
				defer cancel()
			}
			for i := 0; i < 50; i++ {
				await(t, readEntered)
			}
			if phase == "append" {
				for i := 0; i < 50; i++ {
					await(t, enteredAppend)
				}
			} else {
				for i := 0; i < 50; i++ {
					await(t, writeEntered)
				}
			}
			before := appends.Load()
			code, reference := fairnessRequest(server, t.Context(), tok, "/fast", body)
			if code != 429 || reference != "" || appends.Load() != before || n.count() != 0 {
				t.Fatal("local rejection performed work", code, reference, appends.Load(), n.count())
			}
			if phase == "output" {
				code, reference = fairnessRequest(server, t.Context(), other, "/fast", body)
				if code != 200 || !a.CanonicalUUID(reference) {
					t.Fatal("other verified actor starved", code)
				}
			} else {
				cancels[0]()
				code, _ = fairnessRequest(server, t.Context(), tok, "/fast", body)
				if code != 429 {
					t.Fatal("cancel freed credit while append still owned request", code)
				}
				instant.Store(now + 300)
			}
			once.Do(func() { close(release) })
			for i := 0; i < 50; i++ {
				select {
				case code := <-done:
					if phase == "output" && code != 200 {
						t.Fatal("accepted output", code)
					}
					if phase == "append" && code != 503 && code != 0 {
						t.Fatal("expired request exposed output", code)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("owned request did not release")
				}
			}
			instant.Store(now)
			code, reference = fairnessRequest(server, t.Context(), tok, "/fast", body)
			if code != 200 || !a.CanonicalUUID(reference) {
				t.Fatal("credit not returned after actual completion", code)
			}
			// A transport clock mistake cannot turn its verification into engine
			// authority: the original engine clock rejects the exactly expired JWT.
			instant.Store(now + 300)
			bad = serviceConfig
			bad.Clock = func() time.Time { return time.Unix(now, 0) }
			mismatched, err := rpcactivity.New(bad)
			if err != nil {
				t.Fatal(err)
			}
			mismatchHandler, _ := mismatched.Handler(orgA)
			mismatchServer := httptest.NewTLSServer(mismatchHandler)
			defer mismatchServer.Close()
			r, _ := http.NewRequestWithContext(t.Context(), "POST", mismatchServer.URL, strings.NewReader(body))
			r.Header.Set("Authorization", "Bearer "+tok)
			response, err := mismatchServer.Client().Do(r)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if strings.Contains(string(raw), `"result"`) || !strings.Contains(string(raw), `"error"`) {
				t.Fatal("transport identity granted engine authorization", string(raw))
			}
			instant.Store(now)
			if err := recorder.Close(t.Context()); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 51; i++ {
				code, reference = fairnessRequest(server, t.Context(), tok, "/fast", body)
				if code != 503 || reference != "" {
					t.Fatal("failed recorder reservation leaked local credit", i, code, reference)
				}
			}
		})
	}
}

type fairnessReadSignal struct {
	io.ReadCloser
	entered chan<- struct{}
	once    sync.Once
}

func (r *fairnessReadSignal) Read(p []byte) (int, error) {
	r.once.Do(func() { r.entered <- struct{}{} })
	return r.ReadCloser.Read(p)
}

type fairnessWriteHold struct {
	http.ResponseWriter
	entered chan<- struct{}
	release <-chan struct{}
	status  int
}

func (w *fairnessWriteHold) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *fairnessWriteHold) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
func (w *fairnessWriteHold) Write(p []byte) (int, error) {
	if w.status == 200 {
		w.entered <- struct{}{}
		<-w.release
	}
	return w.ResponseWriter.Write(p)
}
func fairnessRequest(server *httptest.Server, ctx context.Context, token, path, body string) (int, string) {
	r, err := http.NewRequestWithContext(ctx, "POST", server.URL+path, strings.NewReader(body))
	if err != nil {
		return 0, ""
	}
	r.Header.Set("Authorization", "Bearer "+token)
	response, err := server.Client().Do(r)
	if err != nil {
		return 0, ""
	}
	defer response.Body.Close()
	_, err = io.Copy(io.Discard, response.Body)
	if err != nil && !errors.Is(err, context.Canceled) {
		return 0, ""
	}
	return response.StatusCode, response.Header.Get(rpcactivity.RequestReferenceHeader)
}
