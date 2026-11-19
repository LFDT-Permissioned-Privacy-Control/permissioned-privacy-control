package admissionsql_test

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	d "privacy-proxy/internal/disclosuredata"
	"privacy-proxy/internal/operational/admissionsql"
)

// Only the owned plaintext PostgreSQL fixture uses this proxy. It cuts the
// actual frontend COMMIT frame after the complete read, without a product hook.
func financeCommitProxy(t *testing.T, dsn string, skipCommits int32) (string, *atomic.Bool, <-chan struct{}) {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	target := u.Host
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	u.Host = listener.Addr().String()
	var armed atomic.Bool
	var remaining atomic.Int32
	remaining.Store(skipCommits)
	hit := make(chan struct{}, 1)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var conns []net.Conn
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			server, err := net.Dial("tcp", target)
			if err != nil {
				client.Close()
				continue
			}
			mu.Lock()
			conns = append(conns, client, server)
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer client.Close()
				defer server.Close()
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, _ = io.Copy(client, server)
					// PostgreSQL cancellation uses a short startup frame and
					// waits for EOF, not a normal query reply. Propagate the
					// server's close so pool cleanup cannot wait on this proxy.
					_ = client.Close()
				}()
				var startup [4]byte
				if _, err := io.ReadFull(client, startup[:]); err != nil {
					return
				}
				n := binary.BigEndian.Uint32(startup[:])
				if n < 8 || n > 1<<20 {
					return
				}
				if _, err := server.Write(startup[:]); err != nil {
					return
				}
				if _, err := io.CopyN(server, client, int64(n)-4); err != nil {
					return
				}
				for {
					var head [5]byte
					if _, err := io.ReadFull(client, head[:]); err != nil {
						return
					}
					n := binary.BigEndian.Uint32(head[1:])
					if n < 4 || n > 1<<20 {
						return
					}
					payload := make([]byte, n-4)
					if _, err := io.ReadFull(client, payload); err != nil {
						return
					}
					if armed.Load() && head[0] == 'Q' && strings.EqualFold(strings.TrimSpace(strings.TrimSuffix(string(payload), "\x00")), "commit") && remaining.Add(-1) < 0 {
						select {
						case hit <- struct{}{}:
						default:
						}
						return
					}
					if _, err := server.Write(head[:]); err != nil {
						return
					}
					if _, err := server.Write(payload); err != nil {
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		mu.Lock()
		for _, c := range conns {
			c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return u.String(), &armed, hit
}

func financeReadCommitFailure(t *testing.T, cfg admissionsql.FinanceReaderConfig, dsn string, scope d.ReadScope, finalCheck ...bool) {
	t.Helper()
	var skip int32
	if d.NativeFinancePlan(cfg.Plan) {
		// Native reads first commit the existing independent readiness check.
		// Forward that COMMIT and cut the actual sampled RR transaction instead.
		skip = 1
	}
	proxy, arm, hit := financeCommitProxy(t, dsn, skip)
	store, err := admissionsql.OpenReader(t.Context(), proxy)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	cfg.Store = store
	var reader *admissionsql.FinanceReader
	if d.ValidRetainedPlan(cfg.Plan) {
		reader, err = admissionsql.NewRetainedFinanceReader(cfg)
	} else {
		reader, err = admissionsql.NewFinanceReader(cfg)
	}
	if err != nil {
		t.Fatal(err)
	}
	open := func() (*admissionsql.FinanceSnapshot, error) {
		if d.NativeFinancePlan(cfg.Plan) {
			if scope.Query.View() == d.List {
				return reader.OpenLivePage(t.Context(), scope, nil, nil)
			}
			return reader.OpenSummary(t.Context(), scope)
		}
		if scope.Query.View() == d.List {
			return reader.OpenPage(t.Context(), scope, nil, nil)
		}
		return reader.Open(t.Context(), scope, nil)
	}
	if len(finalCheck) > 0 && finalCheck[0] {
		snapshot, err := open()
		if err != nil {
			t.Fatal("control read", err)
		}
		defer snapshot.Close()
		arm.Store(true)
		if err = snapshot.CheckCurrent(t.Context()); !errors.Is(err, d.ErrUnavailable) {
			t.Fatal("unknown final read commit accepted", err)
		}
	} else {
		arm.Store(true)
		snapshot, err := open()
		if snapshot != nil || !errors.Is(err, d.ErrUnavailable) {
			t.Fatal("unknown read commit published sample", snapshot, err)
		}
	}
	select {
	case <-hit:
	default:
		t.Fatal("read did not reach actual COMMIT")
	}
}
