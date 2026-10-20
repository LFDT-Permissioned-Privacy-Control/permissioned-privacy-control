package indexerclient

import (
	"testing"

	"privacy-proxy/internal/explorer"
)

func ptr(s string) *string { return &s }

func TestMatchesFilter(t *testing.T) {
	hidden := []string{"0xaaa", "0xbbb"}
	visible := []string{"0xccc"}
	visibleHashes := []string{"0xspecial"}

	tests := []struct {
		name   string
		tx     *explorer.Transaction
		filter *explorer.VisibilityFilter
		want   bool
	}{
		{
			name:   "nil filter passes",
			tx:     &explorer.Transaction{Hash: "0x1", From: "0xaaa", To: ptr("0xbbb")},
			filter: nil,
			want:   true,
		},
		{
			name:   "inactive filter passes",
			tx:     &explorer.Transaction{Hash: "0x1", From: "0xaaa", To: ptr("0xbbb")},
			filter: &explorer.VisibilityFilter{},
			want:   true,
		},
		{
			name: "blocklist: both sides hidden → excluded",
			tx:   &explorer.Transaction{Hash: "0x1", From: "0xaaa", To: ptr("0xbbb")},
			filter: &explorer.VisibilityFilter{
				HiddenAddresses: hidden,
			},
			want: false,
		},
		{
			name: "blocklist: only one side hidden → included",
			tx:   &explorer.Transaction{Hash: "0x1", From: "0xaaa", To: ptr("0xccc")},
			filter: &explorer.VisibilityFilter{
				HiddenAddresses: hidden,
			},
			want: true,
		},
		{
			name: "blocklist: contract creation from hidden → excluded",
			tx:   &explorer.Transaction{Hash: "0x1", From: "0xaaa", To: nil},
			filter: &explorer.VisibilityFilter{
				HiddenAddresses: hidden,
			},
			want: false,
		},
		{
			name: "blocklist: contract creation from visible → included",
			tx:   &explorer.Transaction{Hash: "0x1", From: "0xccc", To: nil},
			filter: &explorer.VisibilityFilter{
				HiddenAddresses: hidden,
			},
			want: true,
		},
		{
			name: "visibleTxHashes wins over blocklist",
			tx:   &explorer.Transaction{Hash: "0xspecial", From: "0xaaa", To: ptr("0xbbb")},
			filter: &explorer.VisibilityFilter{
				HiddenAddresses: hidden,
				VisibleTxHashes: visibleHashes,
			},
			want: true,
		},
		{
			name: "allowlist: participant in allowlist → included",
			tx:   &explorer.Transaction{Hash: "0x1", From: "0xaaa", To: ptr("0xccc")},
			filter: &explorer.VisibilityFilter{
				AllPrivate:       true,
				VisibleAddresses: visible,
			},
			want: true,
		},
		{
			name: "allowlist: no participant in allowlist → excluded",
			tx:   &explorer.Transaction{Hash: "0x1", From: "0xaaa", To: ptr("0xbbb")},
			filter: &explorer.VisibilityFilter{
				AllPrivate:       true,
				VisibleAddresses: visible,
			},
			want: false,
		},
		{
			name: "allowlist: empty visible + no hash overrides → fail closed",
			tx:   &explorer.Transaction{Hash: "0x1", From: "0xccc", To: ptr("0xccc")},
			filter: &explorer.VisibilityFilter{
				AllPrivate: true,
			},
			want: false,
		},
		{
			name: "allowlist: visibleTxHashes overrides empty allowlist",
			tx:   &explorer.Transaction{Hash: "0xspecial", From: "0xaaa", To: ptr("0xbbb")},
			filter: &explorer.VisibilityFilter{
				AllPrivate:      true,
				VisibleTxHashes: visibleHashes,
			},
			want: true,
		},
		{
			name: "case insensitive address match",
			tx:   &explorer.Transaction{Hash: "0x1", From: "0xAAA", To: ptr("0xBBB")},
			filter: &explorer.VisibilityFilter{
				HiddenAddresses: hidden, // already lowercase
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesFilter(tt.tx, tt.filter)
			if got != tt.want {
				t.Errorf("matchesFilter() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilterTxs(t *testing.T) {
	txs := []explorer.Transaction{
		{Hash: "0x1", From: "0xaaa", To: ptr("0xbbb")}, // excluded
		{Hash: "0x2", From: "0xccc", To: ptr("0xaaa")}, // included
		{Hash: "0x3", From: "0xaaa", To: ptr("0xaaa")}, // excluded
	}
	filter := &explorer.VisibilityFilter{HiddenAddresses: []string{"0xaaa", "0xbbb"}}
	got := filterTxs(txs, filter)
	if len(got) != 1 || got[0].Hash != "0x2" {
		t.Errorf("filterTxs() = %+v, want 1 element with hash=0x2", got)
	}
}

func TestOverfetchLimit(t *testing.T) {
	cases := []struct {
		want, expected int
	}{
		{25, 50},   // multiplier
		{100, 200}, // still under cap
		{200, 200}, // capped
		{500, 200}, // capped
		{0, 0},     // preserves 0
	}
	for _, c := range cases {
		got := overfetchLimit(c.want)
		if got != c.expected {
			t.Errorf("overfetchLimit(%d) = %d, want %d", c.want, got, c.expected)
		}
	}
}
