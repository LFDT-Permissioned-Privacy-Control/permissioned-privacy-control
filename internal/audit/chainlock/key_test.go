package chainlock

import "testing"

func TestExistingChainLockKeyGolden(t *testing.T) {
	// Independent preexisting class730076/FNV32 derivation, including Unicode
	// bytes. No DB role, metadata or network policy changes this protocol key.
	for _, v := range []struct {
		chain string
		want  int64
	}{
		{"", 3135654709730757},
		{"access_logs", 3135653091474103},
	} {
		if got := Key(v.chain); got != v.want {
			t.Fatalf("%q got%d want%d", v.chain, got, v.want)
		}
	}
}
