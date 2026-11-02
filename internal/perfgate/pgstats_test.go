package perfgate

import (
	"testing"
	"time"
)

func TestParsePSTime(t *testing.T) {
	for in, want := range map[string]float64{"0:01.50": 1.5, "12:00.00": 720, "1:00:00": 3600, "2-01:00:00": 2*86400 + 3600} {
		got, err := parsePSTime(in)
		if err != nil || got != want {
			t.Fatalf("parsePSTime(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := parsePSTime("garbage"); err == nil {
		t.Fatal("garbage parsed")
	}
}

func TestClusterDelta(t *testing.T) {
	at := time.Unix(100, 0)
	a := ClusterSnapshot{At: at, Databases: map[string]DBCounters{"main": {Commits: 10}}, WALBytes: 1000, CPUMicros: 2_000_000}
	b := ClusterSnapshot{At: at.Add(2 * time.Second), Databases: map[string]DBCounters{"main": {Commits: 30, Inserted: 5}, "new": {Commits: 4}}, WALBytes: 5000, CPUMicros: 5_000_000}
	d := Delta(a, b)
	if d.CommitsPerSec["main"] != 10 || d.CommitsPerSec["new"] != 2 || d.WALBytes != 4000 || d.CPUSeconds != 3 || d.CPUUtilisation != 1.5 || d.Databases["main"].Inserted != 5 {
		t.Fatalf("delta %+v", d)
	}
}
