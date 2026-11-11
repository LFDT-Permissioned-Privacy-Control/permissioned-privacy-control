package readprivacyabi

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/explorerdata"
)

const layoutABI = `[{"type":"event","name":"E","anonymous":false,"inputs":[{"name":"account","type":"address","indexed":true},{"name":"other","type":"address","indexed":false}]}]`

func layoutMatcher(t *testing.T) *EventLayoutMatcher {
	t.Helper()
	m, err := NewEventLayoutMatcher(DefaultLayoutLimits())
	if err != nil {
		t.Fatal(err)
	}
	return m
}
func layoutEventLog(t *testing.T, raw string, values ...any) (abi.Event, []string, string) {
	t.Helper()
	parsed, err := abi.JSON(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	event := parsed.Events["E"]
	payload, err := event.Inputs.NonIndexed().Pack(values...)
	if err != nil {
		t.Fatal(err)
	}
	return event, []string{event.ID.Hex(), common.HexToHash("0x112233").Hex()}, "0x" + hex.EncodeToString(payload)
}
func TestEventLayoutMatchedSingleABIFeedsActualAddressMask(t *testing.T) {
	private := common.HexToAddress("0x998877")
	_, topics, data := layoutEventLog(t, layoutABI, private)
	m := layoutMatcher(t)
	prepared, err := m.Prepare(json.RawMessage(layoutABI))
	if err != nil {
		t.Fatal(err)
	}
	one, ok, err := m.MatchPrepared(prepared, topics, data)
	if err != nil || !ok {
		t.Fatal("actual canonical layout", ok, err)
	}
	vis := explorerdata.VisibilityMap{common.HexToAddress("0x112233").Hex(): explorerdata.VisibilityFull}
	// Helpers index lower-case addresses; the fixture's numeric addresses are
	// already canonical. The actual private nonindexed address is zeroed.
	pointers := []*string{&topics[0], &topics[1]}
	redTopics, redData := RedactLogAddressFields(pointers, data, one, &topics[0], vis)
	if *redTopics[1] != topics[1] || redData != "0x"+strings.Repeat("0", 64) {
		t.Fatal("single matched layout did not drive real masks", redData)
	}
	one[0] = 'x'
	if next, ok, err := m.MatchPrepared(prepared, topics, data); err != nil || !ok || next[0] != '[' {
		t.Fatal("returned ABI aliases memo")
	}
	if _, _, err := layoutMatcher(t).MatchPrepared(prepared, topics, data); !errors.Is(err, ErrLayoutTooBroad) {
		t.Fatal("foreign owner handle accepted", err)
	}
}
func TestEventLayoutUnsupportedAndMalformedNeverMatch(t *testing.T) {
	_, topics, data := layoutEventLog(t, layoutABI, common.HexToAddress("0x998877"))
	for _, raw := range []string{"[]", "not-json", layoutABI + "trailing", `[{"type":"event","name":"E","anonymous":true,"inputs":[]}]`, `[{"type":"unknown"}]`} {
		if _, ok, err := layoutMatcher(t).Match(json.RawMessage(raw), topics, data); ok || err != nil {
			t.Fatal("unsupported ABI matched", raw, err)
		}
	}
	for _, bad := range []struct {
		topics []string
		data   string
	}{{[]string{common.Hash{1}.Hex(), topics[1]}, data}, {topics, data + "00"}, {[]string{topics[0], "0x" + strings.Repeat("f", 64)}, data}, {topics, "0x01"}} {
		if _, ok, err := layoutMatcher(t).Match(json.RawMessage(layoutABI), bad.topics, bad.data); ok || err != nil {
			t.Fatal("malformed layout matched", err)
		}
	}
}
func TestEventLayoutAmbiguityAndExactIndexedWords(t *testing.T) {
	first := `{"type":"event","name":"E","anonymous":false,"inputs":[{"name":"a","type":"address","indexed":true},{"name":"n","type":"uint256","indexed":false}]}`
	second := `{"type":"event","name":"E","anonymous":false,"inputs":[{"name":"a","type":"address","indexed":false},{"name":"n","type":"uint256","indexed":true}]}`
	all := json.RawMessage("[" + first + "," + second + "]")
	_, topics, data := layoutEventLog(t, "["+first+"]", big.NewInt(3))
	if _, ok, err := layoutMatcher(t).Match(all, topics, data); ok || err != nil {
		t.Fatal("ambiguous indexed layout admitted", err)
	}
	high := new(big.Int).Lsh(big.NewInt(1), 200)
	_, topics, data = layoutEventLog(t, "["+first+"]", high)
	one, ok, err := layoutMatcher(t).Match(all, topics, data)
	if err != nil || !ok || !bytes.Contains(one, []byte(`"indexed":true`)) {
		t.Fatal("one unique fitting layout lost", err)
	}
	var entries []json.RawMessage
	if json.Unmarshal(one, &entries) != nil || len(entries) != 1 {
		t.Fatal("not exact one-event ABI")
	}
	for _, typ := range []string{"uint8", "bool", "bytes4", "function"} {
		raw := `[{"type":"event","name":"E","anonymous":false,"inputs":[{"name":"v","type":"` + typ + `","indexed":true}]}]`
		parsed, err := abi.JSON(strings.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		event := parsed.Events["E"]
		bad := make([]byte, 32)
		bad[0] = 1
		bad[31] = 2
		if _, ok, err := layoutMatcher(t).Match(json.RawMessage(raw), []string{event.ID.Hex(), "0x" + hex.EncodeToString(bad)}, "0x"); ok || err != nil {
			t.Fatal("noncanonical indexed word admitted", typ, err)
		}
	}
}
func TestEventLayoutWholeMetadataQuotasAreTypedAndSticky(t *testing.T) {
	_, topics, data := layoutEventLog(t, layoutABI, common.HexToAddress("0x998877"))
	l := DefaultLayoutLimits()
	l.MaxBytes = 1
	m, err := NewEventLayoutMatcher(l)
	if err != nil {
		t.Fatal(err)
	}
	if raw, ok, err := m.Match(json.RawMessage(layoutABI), topics, data); !errors.Is(err, ErrLayoutTooBroad) || ok || raw != nil {
		t.Fatal("quota became omitted successful log", err)
	}
	if _, _, err := m.Match(json.RawMessage("[]"), topics, "0x"); !errors.Is(err, ErrLayoutTooBroad) {
		t.Fatal("quota reset on another ABI")
	}
	l = DefaultLayoutLimits()
	l.MaxEntries = 1
	m, _ = NewEventLayoutMatcher(l)
	two := strings.TrimSuffix(layoutABI, "]") + `,{"type":"function","name":"f","inputs":[],"outputs":[]}]`
	if _, _, err := m.Match(json.RawMessage(two), topics, data); !errors.Is(err, ErrLayoutTooBroad) {
		t.Fatal("entry quota ignored", err)
	}
	l = DefaultLayoutLimits()
	l.MaxDocuments = 1
	m, _ = NewEventLayoutMatcher(l)
	if _, ok, err := m.Match(json.RawMessage(layoutABI), topics, data); !ok || err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.Match(json.RawMessage("[]"), topics, data); !errors.Is(err, ErrLayoutTooBroad) {
		t.Fatal("document quota reset")
	}
	m = layoutMatcher(t)
	if err := m.ReserveMetadata(m.limits.MaxBytes); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.Match(json.RawMessage(layoutABI), topics, data); !errors.Is(err, ErrLayoutTooBroad) {
		t.Fatal("owner metadata reservation not shared")
	}
}
