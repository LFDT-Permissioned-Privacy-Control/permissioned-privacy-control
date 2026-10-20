package server

import (
	"strconv"
	"testing"
)

// TestCountAcrossPages verifies the paged counter sums survivors across ALL
// pages — not just the first — which is the core of the address-stats fix:
// privacy/gRPC mode clamps each fetch to ~100 rows, so a single fetch capped
// the count at 100. Since RD-1149 the walk advances on the backend's opaque
// continuation cursor, so it also pins: full counting through a block larger
// than one page (the old bare-block advance skipped the remainder), the
// maxScan bound, dedup against a re-serving backend, and termination on a
// non-advancing cursor.
func TestCountAcrossPages(t *testing.T) {
	type item struct {
		id    int
		block uint64
		vis   bool
	}
	const total = 250
	// Newest-first feed across blocks total..1, one tx per block; every 3rd is
	// not visible (would be dropped by redaction).
	feed := make([]item, 0, total)
	for b := uint64(total); b >= 1; b-- {
		feed = append(feed, item{id: int(b), block: b, vis: b%3 != 0})
	}
	wantVisible := 0
	for _, it := range feed {
		if it.vis {
			wantVisible++
		}
	}

	const perPage = 100 // simulate the privacy/gRPC indexer page clamp
	// keysetFetch pages a feed slice on a positional cursor (the stringified
	// index of the next row) — the same contract the real backends provide:
	// up to perPage rows plus a continuation that resumes exactly after the
	// last returned row ("" = exhausted).
	keysetFetch := func(f []item) func(cursor string) ([]item, string, error) {
		return func(cursor string) ([]item, string, error) {
			start := 0
			if cursor != "" {
				start, _ = strconv.Atoi(cursor)
			}
			if start >= len(f) {
				return nil, "", nil
			}
			end := start + perPage
			if end > len(f) {
				end = len(f)
			}
			next := ""
			if end < len(f) {
				next = strconv.Itoa(end)
			}
			return f[start:end], next, nil
		}
	}
	keyOf := func(it item) string { return strconv.Itoa(it.id) }
	survivors := func(page []item) (int, error) {
		n := 0
		for _, it := range page {
			if it.vis {
				n++
			}
		}
		return n, nil
	}

	t.Run("counts across all pages (not capped at one page)", func(t *testing.T) {
		got, err := countAcrossPages(keysetFetch(feed), keyOf, survivors, 100000)
		if err != nil {
			t.Fatalf("countAcrossPages: %v", err)
		}
		if got != wantVisible {
			t.Errorf("count = %d, want %d (must scan all %d items, not just the first %d)",
				got, wantVisible, total, perPage)
		}
		if wantVisible <= perPage {
			t.Fatalf("test setup: wantVisible (%d) must exceed perPage (%d) to prove uncapped", wantVisible, perPage)
		}
	})

	t.Run("respects maxScan bound (rounds up to a page)", func(t *testing.T) {
		// maxScan=150 with perPage=100 -> scans 2 pages (200 items) then stops.
		got, err := countAcrossPages(keysetFetch(feed), keyOf, survivors, 150)
		if err != nil {
			t.Fatalf("countAcrossPages: %v", err)
		}
		want := 0
		for _, it := range feed[:200] {
			if it.vis {
				want++
			}
		}
		if got != want {
			t.Errorf("bounded count = %d, want %d (first 2 pages)", got, want)
		}
		if got >= wantVisible {
			t.Errorf("bounded count = %d should be < full %d (maxScan must engage)", got, wantVisible)
		}
	})

	t.Run("single block larger than a page is fully counted (RD-1149)", func(t *testing.T) {
		// All 150 items share block 7. The old bare-block advance fetched one
		// page, moved the cursor to `before block 7`, and silently omitted the
		// remaining 50. The keyset cursor resumes mid-block, so every row is
		// counted.
		sameBlock := make([]item, 0, 150)
		for i := 1; i <= 150; i++ {
			sameBlock = append(sameBlock, item{id: 1000 + i, block: 7, vis: true})
		}
		got, err := countAcrossPages(keysetFetch(sameBlock), keyOf, survivors, 100000)
		if err != nil {
			t.Fatalf("countAcrossPages: %v", err)
		}
		if got != len(sameBlock) {
			t.Errorf("count = %d, want %d (mid-block resume must not drop the block remainder)", got, len(sameBlock))
		}
	})

	t.Run("re-serving backend with a stuck cursor is counted once and terminates", func(t *testing.T) {
		// Degenerate backend: always returns the same first page with the same
		// non-empty cursor. Identity dedup counts the page once; the
		// non-advancing cursor terminates the walk.
		calls := 0
		fetch := func(cursor string) ([]item, string, error) {
			calls++
			return feed[:perPage], "stuck", nil
		}
		got, err := countAcrossPages(fetch, keyOf, survivors, 100000)
		if err != nil {
			t.Fatalf("countAcrossPages: %v", err)
		}
		wantFirstPage := 0
		for _, it := range feed[:perPage] {
			if it.vis {
				wantFirstPage++
			}
		}
		if got != wantFirstPage {
			t.Errorf("count = %d, want %d (re-served page counted once, not doubled)", got, wantFirstPage)
		}
		if calls != 2 {
			t.Errorf("fetch calls = %d, want 2 (first page, then the stuck cursor terminates)", calls)
		}
	})

	t.Run("overlapping pages stay bounded by rows fetched and are not double-counted", func(t *testing.T) {
		// Backend whose pages heavily overlap (the cursor advances by only 10
		// rows per 100-row page). Dedup keeps the count correct; the maxScan
		// bound counts FETCHED rows, so overlap cannot drive unbounded work.
		fetch := func(cursor string) ([]item, string, error) {
			start := 0
			if cursor != "" {
				start, _ = strconv.Atoi(cursor)
			}
			if start >= len(feed) {
				return nil, "", nil
			}
			end := start + perPage
			if end > len(feed) {
				end = len(feed)
			}
			next := ""
			if end < len(feed) {
				next = strconv.Itoa(start + 10) // 90-row overlap with the next page
			}
			return feed[start:end], next, nil
		}
		got, err := countAcrossPages(fetch, keyOf, survivors, 400)
		if err != nil {
			t.Fatalf("countAcrossPages: %v", err)
		}
		// 4 fetches of 100 rows hit the 400-row bound: pages start at rows
		// 0/10/20/30, covering rows 0..129 distinct.
		want := 0
		for _, it := range feed[:130] {
			if it.vis {
				want++
			}
		}
		if got != want {
			t.Errorf("count = %d, want %d (overlap deduped, bounded by rows fetched)", got, want)
		}
	})
}
