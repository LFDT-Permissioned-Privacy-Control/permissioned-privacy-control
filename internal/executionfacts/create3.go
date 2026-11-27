package executionfacts

import (
	"bytes"

	"github.com/ethereum/go-ethereum/crypto"
)

const (
	create3HelperInit = "\x67\x36\x3d\x3d\x37\x36\x3d\x34\xf0\x3d\x52\x60\x08\x60\x18\xf3"
	create3HelperCode = "\x36\x3d\x3d\x37\x36\x3d\x34\xf0"
)

// Create3HelperRecord recognizes the V1 demo factory's adjacent CREATE2, CALL,
// CREATE sequence. It reports the helper's trace ordinal, not call ancestry
// or authority. The caller must separately qualify the factory.
func Create3HelperRecord(records []Record, finalIndex int) (int, bool) {
	if finalIndex < 3 || finalIndex >= len(records) {
		return 0, false
	}
	helperIndex := finalIndex - 2
	helper, call, final := records[helperIndex], records[finalIndex-1], records[finalIndex]
	if helper.Kind != Create2 || call.Kind != Call || final.Kind != Create ||
		helper.Failed() || helper.AncestorFailed || call.Failed() || call.AncestorFailed || final.Failed() || final.AncestorFailed ||
		helper.ParentIndex < 0 || helper.ParentIndex != call.ParentIndex || final.ParentIndex != finalIndex-1 ||
		helper.Depth != call.Depth || final.Depth != call.Depth+1 ||
		!helper.StorageAddress.Known || !call.StorageAddress.Known || !final.StorageAddress.Known ||
		call.From != helper.From || call.StorageAddress.Value != helper.StorageAddress.Value ||
		final.From != helper.StorageAddress.Value || !final.CallerAddress.Known || final.CallerAddress.Value != final.From ||
		!bytes.Equal(helper.Input, []byte(create3HelperInit)) || !bytes.Equal(helper.Output, []byte(create3HelperCode)) ||
		!bytes.Equal(call.Input, final.Input) || call.Value == nil || final.Value == nil || call.Value.Cmp(final.Value) != 0 ||
		final.StorageAddress.Value != crypto.CreateAddress(helper.StorageAddress.Value, 1) {
		return 0, false
	}
	return helperIndex, true
}
