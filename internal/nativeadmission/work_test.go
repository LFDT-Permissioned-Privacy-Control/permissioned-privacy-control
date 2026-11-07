package nativeadmission

import (
	"math"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/policycore"
	"privacy-proxy/internal/runtimepolicy"
)

func TestAdmissionComposedWorkBoundariesAndOverflow(t *testing.T) {
	// Empty policies still scan every mapped group for every observed frame.
	if work, ok := admissionWork(500, 4000, ruleWork{}, 0); !ok || work != 2_000_000 {
		t.Fatal("exact zero-rule boundary", work, ok)
	}
	if _, ok := admissionWork(501, 4000, ruleWork{}, 0); ok {
		t.Fatal("zero-rule groups escaped bound")
	}
	// One rule + one argument + sorting + 996 linked comparisons + group
	// scan costs 1000 units per frame, within the actual trace/wallet limits.
	w := ruleWork{rules: 1, items: 2, linked: 1}
	if work, ok := admissionWork(2000, 1, w, 996); !ok || work != 2_000_000 {
		t.Fatal("linked boundary", work, ok)
	}
	if _, ok := admissionWork(2001, 1, w, 996); ok {
		t.Fatal("linked scan cost omitted")
	}
	for _, w := range []ruleWork{{rules: math.MaxUint64}, {items: math.MaxUint64}, {linked: math.MaxUint64}} {
		if _, ok := admissionWork(math.MaxUint64, 1, w, 4096); ok {
			t.Fatal("arithmetic overflow accepted")
		}
	}
}

func TestRegisteredIsolationLabelsDoNotMintOperationalClaims(t *testing.T) {
	for _, qualified := range []string{"", "B", "A"} {
		frame := policycore.Frame{StorageOrg: "A"}
		setFrameMasks(&frame, []runtimepolicy.GroupMask{{GroupID: "admin", Claims: 7}}, qualified, "A")
		if (frame.GroupClaims["admin"] == 7) != (qualified == "A") {
			t.Fatal("registry label supplied operational claims without qualified code", qualified)
		}
	}
}

func TestWalletSnapshotsAreBoundedActorOwnedAdapterFacts(t *testing.T) {
	addresses := []common.Address{common.HexToAddress("0x1111111111111111111111111111111111111111")}
	w, err := NewWalletSnapshot("actor", "version", time.Unix(1, 0), addresses)
	if err != nil {
		t.Fatal(err)
	}
	addresses[0] = common.Address{}
	w.Addresses()[0] = common.Address{}
	if !w.Contains(common.HexToAddress("0x1111111111111111111111111111111111111111")) {
		t.Fatal("wallet address slice escaped")
	}
	if _, err := NewWalletSnapshot("actor", "version", time.Unix(1, 0), make([]common.Address, MaxWalletAddresses+1)); err == nil {
		t.Fatal("oversized adapter fact accepted")
	}
	if _, err := NewWalletSnapshot("actor", "", time.Unix(1, 0), nil); err == nil {
		t.Fatal("unversioned adapter fact accepted")
	}
	if _, err := NewWalletSnapshot("actor", "version", time.Time{}, nil); err == nil {
		t.Fatal("missing evidence time accepted")
	}
}
