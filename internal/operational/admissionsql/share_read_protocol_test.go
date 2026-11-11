package admissionsql_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	h "privacy-proxy/internal/historyfacts"
	"privacy-proxy/internal/networkidentity"
	"privacy-proxy/internal/operational/admissionsql"
)

// This test-only TCP bridge lets PostgreSQL complete the actual read-only
// COMMIT, but withholds its acknowledgement. No model or SQL method is stubbed.
func shareLostCommitRelay(t *testing.T, dsn string) (string, *atomic.Bool, <-chan struct{}, *atomic.Int64) {
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
	t.Cleanup(func() { _ = listener.Close() })
	u.Host = listener.Addr().String()
	armed := &atomic.Bool{}
	committed := make(chan struct{}, 1)
	maxRow := &atomic.Int64{}
	go func() {
		for {
			front, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer front.Close()
				back, err := net.DialTimeout("tcp", target, time.Second)
				if err != nil {
					return
				}
				defer back.Close()
				var suppress atomic.Bool
				go func() {
					defer front.Close()
					for {
						var header [5]byte
						if _, err := io.ReadFull(back, header[:]); err != nil {
							return
						}
						n := binary.BigEndian.Uint32(header[1:])
						if n < 4 || n > 1<<20 {
							return
						}
						body := make([]byte, n-4)
						if _, err := io.ReadFull(back, body); err != nil {
							return
						}
						if header[0] == 'D' {
							for old := maxRow.Load(); int64(len(body)) > old; old = maxRow.Load() {
								if maxRow.CompareAndSwap(old, int64(len(body))) {
									break
								}
							}
						}
						if suppress.Load() {
							if header[0] == 'C' && bytes.Equal(body, []byte("COMMIT\x00")) {
								select {
								case committed <- struct{}{}:
								default:
								}
								return
							}
							continue
						}
						if _, err := front.Write(append(header[:], body...)); err != nil {
							return
						}
					}
				}()
				var startup [4]byte
				if _, err := io.ReadFull(front, startup[:]); err != nil {
					return
				}
				n := binary.BigEndian.Uint32(startup[:])
				if n < 4 || n > 1<<20 {
					return
				}
				body := make([]byte, n-4)
				if _, err := io.ReadFull(front, body); err != nil {
					return
				}
				if _, err := back.Write(append(startup[:], body...)); err != nil {
					return
				}
				for {
					var header [5]byte
					if _, err := io.ReadFull(front, header[:]); err != nil {
						return
					}
					n := binary.BigEndian.Uint32(header[1:])
					if n < 4 || n > 1<<20 {
						return
					}
					body := make([]byte, n-4)
					if _, err := io.ReadFull(front, body); err != nil {
						return
					}
					if armed.Load() && header[0] == 'Q' && bytes.Equal(bytes.ToLower(body), []byte("commit\x00")) {
						suppress.Store(true)
					}
					if _, err := back.Write(append(header[:], body...)); err != nil {
						return
					}
				}
			}()
		}
	}()
	return u.String(), armed, committed, maxRow
}

func TestHistorySharesActualUnknownCommitAndRepeatableRead(t *testing.T) {
	d := setupObserver(t)
	binding, scope := creationScope(t, d.db)
	network := networkidentity.Binding{Environment: binding.Environment, ChainID: binding.ChainID, GenesisHash: binding.GenesisHash, DeploymentID: binding.DeploymentID}
	expected := h.ShareBinding{Network: network, State: scope.State, SchemaProfile: h.ShareSchemaProfile}
	row := historyShare(t, scope, scope.Actor)
	putHistoryShare(t, d.app, scope, row)
	dsn, armed, committed, maxRow := shareLostCommitRelay(t, d.db.readerDSN)
	store, err := admissionsql.OpenReader(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	reader, err := admissionsql.NewShareReader(store, expected)
	if err != nil {
		t.Fatal(err)
	}
	armed.Store(true)
	if pass, err := reader.Read(t.Context(), h.ShareQuery{Hashes: []common.Hash{scope.Hash}}); err == nil || pass != nil {
		t.Fatal("unknown actual COMMIT published pass", err)
	}
	select {
	case <-committed:
	case <-time.After(time.Second):
		t.Fatal("actual server COMMIT not observed")
	}
	armed.Store(false)
	if _, err := reader.Read(t.Context(), h.ShareQuery{Hashes: []common.Hash{scope.Hash}}); err != nil {
		t.Fatal("same reader recovered fresh connection", err)
	}

	lock, err := d.db.owner.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback(context.Background())
	if _, err := lock.Exec(t.Context(), `LOCK TABLE ops_admission_v2.tx_shares IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	type answer struct {
		pass *h.SharePass
		err  error
	}
	done := make(chan answer, 1)
	go func() {
		p, err := reader.Read(t.Context(), h.ShareQuery{Hashes: []common.Hash{scope.Hash}})
		done <- answer{p, err}
	}()
	deadline := time.Now().Add(500 * time.Millisecond)
	for {
		var waiting bool
		if err := lock.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='admission_reader' AND wait_event_type='Lock')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("actual RR query did not wait")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := lock.Exec(t.Context(), `UPDATE ops_admission_v2.tx_shares SET anchor_timestamp=anchor_timestamp+1 WHERE network_key=$1 AND tx_hash=$2`, scope.Network[:], scope.Hash[:]); err != nil {
		t.Fatal(err)
	}
	if err := lock.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	result := <-done
	if result.err != nil {
		t.Fatal("original coherent RR", result.err)
	}
	got, ok := result.pass.Share(scope.Hash)
	if !ok || got.Witness.AnchorTimestamp != row.Witness.AnchorTimestamp {
		t.Fatal("late row mutation crossed original state/rows snapshot")
	}
	if reader.Recheck(t.Context(), result.pass) == nil {
		t.Fatal("fresh final RR missed changed original positive")
	}
	if _, err := reader.Read(t.Context(), h.ShareQuery{Hashes: []common.Hash{scope.Hash}}); err != nil {
		t.Fatal("fresh observation of valid current positive", err)
	}
	// Owner-only corruption control after a valid startup: SQL projection
	// guards must withhold oversized recipients BEFORE pgx receives the field.
	if _, err := d.db.owner.Exec(t.Context(), `ALTER TABLE ops_admission_v2.tx_shares DROP CONSTRAINT tx_shares_recipients_check`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.db.owner.Exec(t.Context(), `UPDATE ops_admission_v2.tx_shares SET recipients=ARRAY[$3] WHERE network_key=$1 AND tx_hash=$2`, scope.Network[:], scope.Hash[:], strings.Repeat("x", 1<<15)); err != nil {
		t.Fatal(err)
	}
	maxRow.Store(0)
	if p, err := reader.Read(t.Context(), h.ShareQuery{Hashes: []common.Hash{scope.Hash}}); err == nil || p != nil {
		t.Fatal("oversized malformed positive accepted")
	}
	if maxRow.Load() > 8192 {
		t.Fatal("oversized SQL value reached application wire", maxRow.Load())
	}
	if _, err := d.db.owner.Exec(t.Context(), `UPDATE ops_admission_v2.tx_shares SET recipients=$3 WHERE network_key=$1 AND tx_hash=$2`, scope.Network[:], scope.Hash[:], row.Recipients); err != nil {
		t.Fatal(err)
	}
	if _, err := d.db.owner.Exec(t.Context(), `ALTER TABLE ops_admission_v2.tx_shares ADD CONSTRAINT tx_shares_recipients_check CHECK(ops_admission_v2.valid_recipients(recipients))`); err != nil {
		t.Fatal(err)
	}
	if err := store.CheckSchema(t.Context()); err != nil {
		t.Fatal("restored exact source catalog", err)
	}
}
