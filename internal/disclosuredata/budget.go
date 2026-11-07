package disclosuredata

import "errors"

var (
	ErrInvalid     = errors.New("invalid protected data request")
	ErrUnsupported = errors.New("unsupported protected data scope")
	ErrTooBroad    = errors.New("protected data query too broad")
	ErrConflict    = errors.New("protected data context changed")
	ErrUnavailable = errors.New("protected data source unavailable")
)

const (
	MaxRequestBytes  = 128 << 10
	MaxResponseBytes = 2 << 20
	MaxVariableBytes = 2 << 20
	MaxEntries       = 16384
	MaxWalletFacts   = 4096
	MaxPage          = 100
)

// Budget counts occurrences, including shared/repeated strings. It never credits
// aliasing: JSON emits each occurrence independently. Zero value is ready to use.
type Budget struct{ bytes, items uint64 }

func NewBudget() *Budget { return &Budget{} }
func (b *Budget) AddBytes(n uint64) error {
	if n > MaxVariableBytes-b.bytes {
		return ErrTooBroad
	}
	b.bytes += n
	return nil
}
func (b *Budget) AddItems(n uint64) error {
	if n > MaxEntries-b.items {
		return ErrTooBroad
	}
	b.items += n
	return nil
}
func (b *Budget) AddRepeatedBytes(each, count uint64) error {
	if count != 0 && each > (MaxVariableBytes-b.bytes)/count {
		return ErrTooBroad
	}
	return b.AddBytes(each * count)
}
