package perfgate

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

// HistogramSummary is a Prometheus histogram's change over the window.
// Percentiles are bucket upper bounds (the conservative reading).
type HistogramSummary struct {
	Count   float64 `json:"count"`
	MeanMS  float64 `json:"mean_ms"`
	P50LeMS float64 `json:"p50_le_ms"`
	P99LeMS float64 `json:"p99_le_ms"`
}

type histogram struct {
	buckets map[float64]float64
	sum     float64
	count   float64
}

// parseHistograms reads histogram series from Prometheus text exposition,
// keyed by "family{labels-without-le}".
func parseHistograms(text string) map[string]*histogram {
	out := map[string]*histogram{}
	get := func(key string) *histogram {
		h := out[key]
		if h == nil {
			h = &histogram{buckets: map[float64]float64{}}
			out[key] = h
		}
		return h
	}
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		space := strings.LastIndexByte(line, ' ')
		if space < 0 {
			continue
		}
		value, err := strconv.ParseFloat(line[space+1:], 64)
		if err != nil {
			continue
		}
		series := line[:space]
		name, labels := series, ""
		if i := strings.IndexByte(series, '{'); i >= 0 {
			name, labels = series[:i], strings.TrimSuffix(series[i+1:], "}")
		}
		switch {
		case strings.HasSuffix(name, "_bucket"):
			var kept []string
			le := math.NaN()
			for _, label := range splitLabels(labels) {
				if v, ok := strings.CutPrefix(label, `le="`); ok {
					le, _ = strconv.ParseFloat(strings.TrimSuffix(v, `"`), 64)
					continue
				}
				kept = append(kept, label)
			}
			if !math.IsNaN(le) {
				get(strings.TrimSuffix(name, "_bucket") + "{" + strings.Join(kept, ",") + "}").buckets[le] = value
			}
		case strings.HasSuffix(name, "_sum"):
			get(strings.TrimSuffix(name, "_sum") + "{" + labels + "}").sum = value
		case strings.HasSuffix(name, "_count"):
			get(strings.TrimSuffix(name, "_count") + "{" + labels + "}").count = value
		}
	}
	for key, h := range out {
		if len(h.buckets) == 0 {
			delete(out, key)
		}
	}
	return out
}

func splitLabels(labels string) []string {
	var out []string
	inQuote, start := false, 0
	for i := 0; i < len(labels); i++ {
		switch labels[i] {
		case '"':
			if i == 0 || labels[i-1] != '\\' {
				inQuote = !inQuote
			}
		case ',':
			if !inQuote {
				out = append(out, labels[start:i])
				start = i + 1
			}
		}
	}
	if start < len(labels) {
		out = append(out, labels[start:])
	}
	return out
}

// histogramDeltas summarises every histogram series that changed between two
// scrapes. Values are assumed to be in seconds and reported in milliseconds.
func histogramDeltas(before, after string) map[string]HistogramSummary {
	a, b := parseHistograms(before), parseHistograms(after)
	out := map[string]HistogramSummary{}
	for key, end := range b {
		start := a[key]
		if start == nil {
			start = &histogram{buckets: map[float64]float64{}}
		}
		count := end.count - start.count
		if count <= 0 {
			continue
		}
		bounds := make([]float64, 0, len(end.buckets))
		for le := range end.buckets {
			bounds = append(bounds, le)
		}
		sort.Float64s(bounds)
		quantile := func(q float64) float64 {
			for _, le := range bounds {
				if end.buckets[le]-start.buckets[le] >= q*count {
					return le * 1e3
				}
			}
			return math.Inf(1)
		}
		s := HistogramSummary{Count: count, MeanMS: (end.sum - start.sum) / count * 1e3, P50LeMS: quantile(.5), P99LeMS: quantile(.99)}
		if math.IsInf(s.P99LeMS, 1) {
			s.P99LeMS = -1 // above the largest finite bucket
		}
		if math.IsInf(s.P50LeMS, 1) {
			s.P50LeMS = -1
		}
		out[key] = s
	}
	return out
}

// counterDeltas returns after−before for every non-histogram series whose
// name starts with one of prefixes.
func counterDeltas(before, after string, prefixes ...string) map[string]float64 {
	read := func(text string) map[string]float64 {
		out := map[string]float64{}
		scanner := bufio.NewScanner(strings.NewReader(text))
		scanner.Buffer(make([]byte, 1<<20), 1<<20)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" || line[0] == '#' {
				continue
			}
			matched := false
			for _, prefix := range prefixes {
				matched = matched || strings.HasPrefix(line, prefix)
			}
			space := strings.LastIndexByte(line, ' ')
			if !matched || space < 0 || strings.Contains(line[:space], "_bucket{") {
				continue
			}
			if v, err := strconv.ParseFloat(line[space+1:], 64); err == nil {
				out[line[:space]] = v
			}
		}
		return out
	}
	a, b := read(before), read(after)
	out := map[string]float64{}
	for key, v := range b {
		if d := v - a[key]; d != 0 {
			out[key] = d
		}
	}
	return out
}

func runQuiet(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).Output()
	return strings.TrimSpace(string(out)), err
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:4])
}
