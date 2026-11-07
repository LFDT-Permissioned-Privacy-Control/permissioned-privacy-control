package rpcexecution

import (
	"context"
	"math"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"privacy-proxy/internal/executionfacts"
)

var timelineRoot = common.HexToAddress("0x1111111111111111111111111111111111111111")
var timelineFactory = common.HexToAddress("0x2222222222222222222222222222222222222222")
var timelineCreated = common.HexToAddress("0x3333333333333333333333333333333333333333")

func timelineRecord(kind executionfacts.Kind, parent, depth int, from, to common.Address) executionfacts.Record {
	known := func(a common.Address) executionfacts.Address { return executionfacts.Address{Value: a, Known: true} }
	return executionfacts.Record{Kind: kind, ParentIndex: parent, Depth: depth, From: from, To: known(to), NominalCodeAddress: known(to), StorageAddress: known(to), CallerAddress: known(from), Value: new(big.Int)}
}

func timelineExecution(t *testing.T, records []executionfacts.Record) *CallExecution {
	t.Helper()
	base := map[common.Address]CodeInfo{}
	for _, r := range records {
		for _, a := range []common.Address{r.From, r.To.Value} {
			base[a] = CodeInfo{hash: crypto.Keccak256Hash(nil), nonceKnown: true}
		}
	}
	for _, a := range []common.Address{timelineRoot, timelineFactory} {
		base[a] = CodeInfo{code: []byte{0x60, 0}, hash: crypto.Keccak256Hash([]byte{0x60, 0}), nonce: 1, nonceKnown: true}
	}
	retained := 4
	ensure := func(a common.Address, _ bool) (CodeInfo, error) {
		if c, ok := base[a]; ok {
			return c, nil
		}
		return CodeInfo{}, failure(InvalidEvidence)
	}
	timeline, err := buildTimeline(context.Background(), records, &retained, DefaultLimits(), ensure)
	if err != nil {
		t.Fatal(err)
	}
	return &CallExecution{timeline: timeline, codes: base}
}

func TestTimelineInstallsAfterConstructorExitAndRollsBackAtAncestorExit(t *testing.T) {
	r := []executionfacts.Record{
		timelineRecord(executionfacts.Call, -1, 0, common.Address{}, timelineRoot),
		timelineRecord(executionfacts.Call, 0, 1, timelineRoot, timelineFactory),
		timelineRecord(executionfacts.Create, 1, 2, timelineFactory, timelineCreated),
		timelineRecord(executionfacts.Call, 1, 2, timelineFactory, timelineCreated),
		timelineRecord(executionfacts.Call, 0, 1, timelineRoot, timelineCreated),
	}
	r[1].Error = "execution reverted"
	r[2].Input, r[2].Output, r[2].AncestorFailed = []byte{0x60, 0x02}, []byte{0x60, 0x01}, true
	e := timelineExecution(t, r)
	input, ok := e.FrameCode(2)
	if !ok || input.Origin() != ConstructorAttempt || input.Bytes()[1] != 2 {
		t.Fatal("constructor frame was not its attempted input")
	}
	if _, known := input.FreshnessNonce(); known {
		t.Fatal("initcode was represented as account nonce evidence")
	}
	underConstruction, _ := e.RuntimeCodeAt(2, timelineCreated)
	nonce, known := underConstruction.FreshnessNonce()
	if underConstruction.HasCode() || !known || nonce != 1 {
		t.Fatal("constructor account runtime was not empty/reserved")
	}
	inside, _ := e.RuntimeCodeAt(3, timelineCreated)
	if !inside.HasCode() || inside.Bytes()[1] != 1 || inside.Origin() != CreatedRuntime {
		t.Fatal("successful child was suppressed by its eventual ancestor failure")
	}
	after, _ := e.RuntimeCodeAt(4, timelineCreated)
	nonce, known = after.FreshnessNonce()
	if after.HasCode() || !known || nonce != 0 || e.timeline.survivors[2] {
		t.Fatal("ancestor EXIT did not restore anchor state")
	}
	bytes := inside.Bytes()
	bytes[0] = 0
	if again, _ := e.RuntimeCodeAt(3, timelineCreated); again.Bytes()[0] != 0x60 {
		t.Fatal("code bytes escaped mutably")
	}
}

func TestTimelineSelfKeepsRuntimeAndNonceUntilFinalization(t *testing.T) {
	beneficiary := common.HexToAddress("0x4444444444444444444444444444444444444444")
	r := []executionfacts.Record{
		timelineRecord(executionfacts.Call, -1, 0, common.Address{}, timelineRoot),
		timelineRecord(executionfacts.Create2, 0, 1, timelineRoot, timelineCreated),
		timelineRecord(executionfacts.Call, 0, 1, timelineRoot, timelineCreated),
		timelineRecord(executionfacts.SelfDestruct, 2, 2, timelineCreated, beneficiary),
		timelineRecord(executionfacts.Call, 0, 1, timelineRoot, timelineCreated),
		timelineRecord(executionfacts.Create2, 0, 1, timelineRoot, timelineCreated),
	}
	r[1].Input, r[1].Output = []byte{0x60, 2}, []byte{0x60, 1}
	r[5].Input, r[5].Error = []byte{0x60, 2}, "contract address collision"
	e := timelineExecution(t, r)
	for _, index := range []int{3, 4, 5} {
		code, ok := e.RuntimeCodeAt(index, timelineCreated)
		nonce, known := code.FreshnessNonce()
		if !ok || !code.HasCode() || !known || nonce != 1 {
			t.Fatal("SELF prematurely cleared code/nonce", index)
		}
	}
	if e.timeline.survivors[1] {
		t.Fatal("eligible same-transaction SELF survived finalization")
	}
	c, _ := e.CreationContext(5)
	if c.Kind != KnownAttempt {
		t.Fatal("failed collision created a fresh epoch")
	}
	r[5].Error = ""
	base := e.codes
	retained := 4
	if _, err := buildTimeline(t.Context(), r, &retained, DefaultLimits(), func(a common.Address, _ bool) (CodeInfo, error) { return base[a], nil }); err == nil {
		t.Fatal("successful collision after SELF accepted")
	}
}

func TestTimelineQualificationWorkIsPrecomputedAndChecked(t *testing.T) {
	for _, row := range []struct {
		n, transitions int
		expected       uint64
	}{{1, 0, 17}, {1, 1, 34}, {4096, 32768, 4096 + 32768 + 16*4096*17}} {
		got, ok := qualificationWork(row.n, row.transitions)
		if !ok || got != row.expected {
			t.Fatal(row, got, ok)
		}
	}
	if _, ok := qualificationWork(math.MaxInt, math.MaxInt); ok {
		t.Fatal("work overflow accepted")
	}
	if _, ok := qualificationWork(-1, 0); ok {
		t.Fatal("negative count accepted")
	}
}

func TestFreshnessNonceDoesNotClaimToInterpretCreatorIncrements(t *testing.T) {
	r := []executionfacts.Record{
		timelineRecord(executionfacts.Call, -1, 0, common.Address{}, timelineRoot),
		timelineRecord(executionfacts.Create, 0, 1, timelineRoot, timelineCreated),
		timelineRecord(executionfacts.Call, 0, 1, timelineRoot, timelineRoot),
	}
	r[1].Input, r[1].Output = []byte{0x60, 1}, []byte{0x60, 2}
	e := timelineExecution(t, r)
	creator, known := e.RuntimeCodeAt(2, timelineRoot)
	nonce, nonceKnown := creator.FreshnessNonce()
	// Actual CREATE increments the creator's state nonce. This getter retains
	// only its initial nonzero freshness evidence; it is not the exact later
	// value2 and is deliberately unsuitable for deriving a later CREATE address.
	if !known || !nonceKnown || nonce != 1 {
		t.Fatal("freshness API silently became an exact creator-nonce interpreter")
	}
	created, known := e.RuntimeCodeAt(2, timelineCreated)
	reservation, reserved := created.FreshnessNonce()
	if !known || !reserved || reservation != 1 {
		t.Fatal("successful runtime lost its nonzero reservation evidence")
	}
}

func TestTimelineSelfMarksRollbackWithoutDeletingCodeOrNonce(t *testing.T) {
	beneficiary := common.HexToAddress("0x9999999999999999999999999999999999999999")
	r := []executionfacts.Record{
		timelineRecord(executionfacts.Call, -1, 0, common.Address{}, timelineRoot),
		timelineRecord(executionfacts.Create, 0, 1, timelineRoot, timelineCreated),
		timelineRecord(executionfacts.Call, 0, 1, timelineRoot, timelineFactory),
		timelineRecord(executionfacts.Call, 2, 2, timelineFactory, timelineCreated),
		timelineRecord(executionfacts.SelfDestruct, 3, 3, timelineCreated, beneficiary),
		timelineRecord(executionfacts.Call, 2, 2, timelineFactory, timelineCreated),
		timelineRecord(executionfacts.SelfDestruct, 5, 3, timelineCreated, beneficiary),
		timelineRecord(executionfacts.Call, 0, 1, timelineRoot, timelineCreated),
		timelineRecord(executionfacts.SelfDestruct, 0, 1, timelineRoot, beneficiary),
	}
	r[1].Input, r[1].Output, r[2].Error = []byte{0x60, 1}, []byte{0x60, 2}, "execution reverted"
	e := timelineExecution(t, r)
	if !e.timeline.survivors[1] {
		t.Fatal("eventual ancestor failure did not roll back repeated SELF marks")
	}
	for _, index := range []int{4, 5, 6, 7} {
		code, known := e.RuntimeCodeAt(index, timelineCreated)
		nonce, nonceKnown := code.FreshnessNonce()
		if !known || !code.HasCode() || !nonceKnown || nonce != 1 {
			t.Fatal("SELF/rollback cleared callable runtime or nonce", index)
		}
	}
	root, _ := e.RuntimeCodeAt(8, timelineRoot)
	if !root.HasCode() || root.Origin() != AnchoredRuntime {
		t.Fatal("existing-contract SELF became a same-transaction deletion")
	}
}
