// Package creationobserver maintains a bounded canonical header prefix and
// capture liveness. Header readiness is operational evidence; it grants no
// ownership or permission and cannot repair historical uncovered captures.
package creationobserver

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"time"

	f "privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/rpcexecution"
)

var ErrUnavailable = errors.New("creation observer unavailable")
var ErrBinding = errors.New("invalid creation observer binding")

type HeaderStore interface {
	AcquireObserverLease(context.Context, f.Digest, f.State, string, f.Digest, f.Digest) (f.ObserverSnapshot, error)
	RenewObserverLease(context.Context, f.Lease) (f.ObserverSnapshot, error)
	ReadObserver(context.Context, f.Lease) (f.ObserverSnapshot, error)
	ReadObserverHeaders(context.Context, f.Lease, []uint64) ([]f.Header, error)
	MarkObserverTip(context.Context, f.ObserverSnapshot, f.Header) error
	ClearObserverCapture(context.Context, f.ObserverSnapshot) error
	PublishObserverHeaders(context.Context, f.HeaderUpdate) (f.ObserverSnapshot, error)
	QuarantineObserver(context.Context, f.ObserverSnapshot, string) error
}
type HeaderOptions struct {
	Network           f.Network
	State             f.State
	Owner             string
	SourceSet         f.Digest
	Reference         f.Source
	CaughtUpAssertion string
	Client            *rpcexecution.HeaderClient
	Store             HeaderStore
}
type HeaderWorker struct {
	options   HeaderOptions
	mu        sync.Mutex
	current   f.ObserverSnapshot
	lastRenew time.Time
}

func NewHeaderWorker(o HeaderOptions) (*HeaderWorker, error) {
	if !o.Network.Valid() || !o.State.Valid() || !f.UUID(o.Owner) || o.SourceSet == (f.Digest{}) || !o.Reference.Valid() || o.Reference.Network != o.Network || o.Reference.Profile != "reth-prague-included-creations/v1" || o.CaughtUpAssertion != f.CaughtUpAssertion || o.Client == nil || o.Client.Source() != o.Reference || o.Store == nil {
		return nil, ErrBinding
	}
	return &HeaderWorker{options: o}, nil
}
func selector(number uint64) rpcexecution.HeaderQuery {
	return rpcexecution.HeaderQuery{NumberOrTag: "0x" + strconv.FormatUint(number, 16)}
}
func (w *HeaderWorker) read(ctx context.Context, queries []rpcexecution.HeaderQuery) ([]f.Header, error) {
	batch, err := w.options.Client.Read(ctx, queries)
	if err != nil || !batch.Synced() || batch.Source() != w.options.Reference {
		return nil, ErrUnavailable
	}
	headers := batch.Headers()
	if len(headers) != len(queries) {
		return nil, ErrUnavailable
	}
	return headers, nil
}

// Step performs one bounded operation. It never holds SQL locks during node
// calls, and rejects concurrent use. Every composed Read shares this ONE 15s
// deadline. A reorg step rolls back only; suffix catch-up follows on the next
// step. Thus even ancestor-depth128 search uses <=143 physical RPC attempts
// across <=4 reads and <3MiB worst-case bounded response envelopes.
func (w *HeaderWorker) Step(ctx context.Context) error {
	if w == nil || ctx == nil {
		return ErrBinding
	}
	if !w.mu.TryLock() {
		return ErrUnavailable
	}
	defer w.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	o := w.options
	var err error
	readAt := time.Now()
	if !w.current.Lease.Valid() {
		w.current, err = o.Store.AcquireObserverLease(ctx, o.Network.Key, o.State, o.Owner, o.SourceSet, o.Reference.Digest())
		w.lastRenew = time.Now()
	} else {
		w.current, err = o.Store.ReadObserver(ctx, w.current.Lease)
		if err == nil && (time.Since(w.lastRenew) >= 10*time.Second || w.current.State.LeaseRemainingTTL-time.Since(readAt) < 20*time.Second) {
			readAt = time.Now()
			w.current, err = o.Store.RenewObserverLease(ctx, w.current.Lease)
			w.lastRenew = time.Now()
		}
	}
	if err != nil {
		w.current = f.ObserverSnapshot{}
		return ErrUnavailable
	}
	if w.current.State.LeaseRemainingTTL-time.Since(readAt) < 20*time.Second {
		return ErrUnavailable
	}
	before := w.current
	latest, err := w.read(ctx, []rpcexecution.HeaderQuery{{NumberOrTag: "latest"}})
	if err != nil {
		_ = o.Store.ClearObserverCapture(ctx, before)
		return err
	}
	tip := latest[0]
	if tip != before.State.Head || before.State.KnownTipSet && before.State.KnownTip.Number == tip.Number && before.State.KnownTip.Hash != tip.Hash {
		if err := o.Store.MarkObserverTip(ctx, before, tip); err != nil {
			return ErrUnavailable
		}
	}
	if tip.Timestamp < o.Reference.PragueStart || tip.Timestamp >= o.Reference.PragueEnd {
		return ErrUnavailable
	}
	// A selected node behind the floor/head is not by itself evidence of reorg.
	if tip.Number < before.State.Floor.Number {
		return ErrUnavailable
	}
	compare := before.State.Head.Number
	if tip.Number < compare {
		compare = tip.Number
	}
	canonical, err := w.read(ctx, []rpcexecution.HeaderQuery{selector(compare)})
	if err != nil {
		_ = o.Store.ClearObserverCapture(ctx, before)
		return err
	}
	stored, err := o.Store.ReadObserverHeaders(ctx, before.Lease, []uint64{compare})
	if err != nil || len(stored) != 1 {
		return ErrUnavailable
	}
	if canonical[0] != stored[0] {
		return w.reorganize(ctx, before, tip, compare)
	}
	if tip.Number < before.State.Head.Number {
		return ErrUnavailable
	}
	if before.State.KnownTipSet && tip.Number < before.State.KnownTip.Number {
		return ErrUnavailable
	}
	count := tip.Number - before.State.Head.Number
	if count > 127 {
		count = 127
	}
	queries := make([]rpcexecution.HeaderQuery, 0, int(count)+1)
	for i := uint64(1); i <= count; i++ {
		queries = append(queries, selector(before.State.Head.Number+i))
	}
	queries = append(queries, rpcexecution.HeaderQuery{NumberOrTag: "latest"})
	batch, err := w.read(ctx, queries)
	if err != nil || batch[len(batch)-1] != tip {
		_ = o.Store.ClearObserverCapture(ctx, before)
		return ErrUnavailable
	}
	update := f.HeaderUpdate{Before: before, Common: before.State.Head, Headers: batch[:len(batch)-1], Tip: tip}
	w.current, err = o.Store.PublishObserverHeaders(ctx, update)
	if err != nil {
		w.current = f.ObserverSnapshot{}
		return ErrUnavailable
	}
	return nil
}
func (w *HeaderWorker) reorganize(ctx context.Context, before f.ObserverSnapshot, tip f.Header, compare uint64) error {
	floor := before.State.Floor.Number
	lowest := floor
	if before.State.Head.Number > 128 && before.State.Head.Number-128 > lowest {
		lowest = before.State.Head.Number - 128
	}
	if compare < lowest {
		return ErrUnavailable
	} // ordinary forward lag, not a proved deep fork
	numbers := make([]uint64, 0, 128)
	queries := make([]rpcexecution.HeaderQuery, 0, 128)
	for n := compare; ; n-- {
		if n < before.State.Head.Number {
			numbers = append(numbers, n)
			queries = append(queries, selector(n))
		}
		if n == lowest {
			break
		}
	}
	var actual []f.Header
	var err error
	if len(queries) > 0 {
		actual, err = w.read(ctx, queries)
		if err != nil {
			return err
		}
	}
	stored, err := w.options.Store.ReadObserverHeaders(ctx, before.Lease, numbers)
	if err != nil || len(stored) != len(actual) {
		return ErrUnavailable
	}
	// The final latest check prevents publishing a mixed/changing node view.
	confirmed, err := w.read(ctx, []rpcexecution.HeaderQuery{{NumberOrTag: "latest"}})
	if err != nil || confirmed[0] != tip {
		return ErrUnavailable
	}
	for i, h := range actual {
		if h == stored[i] {
			w.current, err = w.options.Store.PublishObserverHeaders(ctx, f.HeaderUpdate{Before: before, Common: h, Tip: tip})
			if err != nil {
				w.current = f.ObserverSnapshot{}
				return ErrUnavailable
			}
			return nil
		}
	}
	reason := "deep-reorg"
	if lowest == floor {
		reason = "below-floor"
	}
	if err := w.options.Store.QuarantineObserver(ctx, before, reason); err != nil {
		return ErrUnavailable
	}
	w.current = f.ObserverSnapshot{}
	return ErrUnavailable
}

// Run checks liveness once per second; it does not spin after unavailable
// evidence. Process assembly must enforce the separate <=4-network bound.
func (w *HeaderWorker) Run(ctx context.Context) error {
	if w == nil || ctx == nil {
		return ErrBinding
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		_ = w.Step(ctx)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
