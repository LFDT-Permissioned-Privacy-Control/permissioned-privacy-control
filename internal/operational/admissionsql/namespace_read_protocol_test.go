package admissionsql_test

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	h "privacy-proxy/internal/historynamespace"
	"privacy-proxy/internal/operational/admissionsql"
)

// The relay counts actual frontend synchronization boundaries, including
// implicit statement preparation, connection-validation SQL and cleanup. It
// changes no application SQL or product source and uses only the owned fixture.
type namespaceProtocolRelay struct {
	enabled     atomic.Bool
	roundtrips  atomic.Int64
	connections atomic.Int64
	url         url.URL
}

func namespaceReadProtocolRelay(t *testing.T, dsn string) *namespaceProtocolRelay {
	t.Helper()
	upstream, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	relay := &namespaceProtocolRelay{url: *upstream}
	relay.url.Host = listener.Addr().String()
	go func() {
		for {
			front, err := listener.Accept()
			if err != nil {
				return
			}
			relay.connections.Add(1)
			go func() {
				defer front.Close()
				back, err := net.DialTimeout("tcp", upstream.Host, time.Second)
				if err != nil {
					return
				}
				defer back.Close()
				go func() { _, _ = io.Copy(front, back); _ = front.Close() }()
				// Fixture sslmode=disable begins with one untyped StartupMessage.
				var startup [4]byte
				if _, err := io.ReadFull(front, startup[:]); err != nil {
					return
				}
				n := binary.BigEndian.Uint32(startup[:])
				if n < 4 || n > 1<<20 {
					return
				}
				payload := make([]byte, n-4)
				if _, err := io.ReadFull(front, payload); err != nil {
					return
				}
				if _, err := back.Write(append(startup[:], payload...)); err != nil {
					return
				}
				for {
					var header [5]byte
					if _, err := io.ReadFull(front, header[:]); err != nil {
						return
					}
					n = binary.BigEndian.Uint32(header[1:])
					if n < 4 || n > 1<<20 {
						return
					}
					payload = make([]byte, n-4)
					if _, err := io.ReadFull(front, payload); err != nil {
						return
					}
					if relay.enabled.Load() && (header[0] == 'Q' || header[0] == 'S') {
						relay.roundtrips.Add(1)
					}
					if _, err := back.Write(append(header[:], payload...)); err != nil {
						return
					}
				}
			}()
		}
	}()
	return relay
}

func TestNamespaceResolveActualPostgresPhysicalQueryBudget(t *testing.T) {
	fixture := namespaceObservedRead(t, false)
	relay := namespaceReadProtocolRelay(t, fixture.readerDSN)
	for _, maximum := range []int{1, 2, 8, 9, 512} {
		t.Run(fmt.Sprintf("maximum_%d", maximum), func(t *testing.T) {
			limits := h.DefaultReadLimits()
			limits.MaxQueries = maximum
			reader, err := admissionsql.OpenNamespaceReaderWithLimits(t.Context(), relay.url.String(), fixture.binding, fixture.scope.State.Generation, fixture.input.Era, limits)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			relay.roundtrips.Store(0)
			relay.enabled.Store(true)
			result, err := reader.DiscoverRequirements(t.Context(), fixture.input)
			relay.enabled.Store(false)
			actual := relay.roundtrips.Load()
			t.Logf("actual physical SQL roundtrips=%d bound=%d", actual, maximum)
			if actual > int64(maximum) || maximum == 1 && actual != 0 {
				t.Fatal("physical budget overrun", actual, maximum)
			}
			if maximum < 9 {
				if result != nil || !errors.Is(err, h.ErrTooBroad) {
					t.Fatal("insufficient budget released partial discovery", result, err)
				}
			} else if err != nil || result == nil || actual != 9 {
				t.Fatal("adequate budget did not complete exactly once", result, err, actual)
			}
		})
	}
	t.Run("cold_connection_and_idle_pool", func(t *testing.T) {
		for _, cold := range []bool{true, false} {
			local := relay.url
			if cold {
				q := local.Query()
				// After the wait below, acquisition retires the startup
				// connection and opens a fresh one for the real read.
				q.Set("pool_max_conn_lifetime", "1s")
				local.RawQuery = q.Encode()
			}
			limits := h.DefaultReadLimits()
			limits.MaxQueries = 9
			reader, err := admissionsql.OpenNamespaceReaderWithLimits(t.Context(), local.String(), fixture.binding, fixture.scope.State.Generation, fixture.input.Era, limits)
			if err != nil {
				t.Fatal(err)
			}
			before := relay.connections.Load()
			time.Sleep(1100 * time.Millisecond) // crosses both the cold lifetime and default implicit-Ping threshold
			relay.roundtrips.Store(0)
			relay.enabled.Store(true)
			result, err := reader.DiscoverRequirements(t.Context(), fixture.input)
			relay.enabled.Store(false)
			actual := relay.roundtrips.Load()
			reader.Close()
			if err != nil || result == nil || actual != 9 || cold && relay.connections.Load() <= before {
				t.Fatal("cold/idle connection added hidden SQL or lost result", cold, actual, result, err)
			}
		}
	})
	t.Run("unsupported_session_target_is_rejected_before_connection", func(t *testing.T) {
		for _, mode := range []string{"read-write", "read-only"} {
			local := relay.url
			q := local.Query()
			q.Set("target_session_attrs", mode)
			local.RawQuery = q.Encode()
			before := relay.connections.Load()
			reader, err := admissionsql.OpenNamespaceReader(t.Context(), local.String(), fixture.binding, fixture.scope.State.Generation, fixture.input.Era)
			if err == nil || reader != nil || relay.connections.Load() != before {
				t.Fatal("unsupported DSN emitted hidden validation SQL", mode, reader, err)
			}
		}
		local := relay.url
		q := local.Query()
		q.Set("target_session_attrs", "any")
		local.RawQuery = q.Encode()
		reader, err := admissionsql.OpenNamespaceReader(t.Context(), local.String(), fixture.binding, fixture.scope.State.Generation, fixture.input.Era)
		if err != nil {
			t.Fatal("explicit any changed supported startup", err)
		}
		reader.Close()
	})
}
