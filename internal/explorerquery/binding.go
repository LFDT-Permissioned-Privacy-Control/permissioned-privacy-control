// Package explorerquery defines bounded indexed chain facts; they grant no permissions.
package explorerquery

import (
	"github.com/google/uuid"
	"privacy-proxy/internal/networkidentity"
)

const APIVersion = "chain_indexer.v2"
const Mode = "chain_indexer.v2/typed-reads"

type Binding struct {
	Network    networkidentity.Binding
	APIVersion string
}

func (b Binding) Valid() bool {
	_, err := b.Network.Key()
	return err == nil && b.APIVersion == APIVersion
}

type ReaderIdentity struct{ marker byte }

func NewReaderIdentity() *ReaderIdentity { return &ReaderIdentity{1} }
func (i *ReaderIdentity) Valid() bool    { return i != nil && i.marker == 1 }

type Metadata struct {
	Binding  Binding
	Mode     string
	Identity *ReaderIdentity
}

func ValidDatasetEpoch(s string) bool {
	id, e := uuid.Parse(s)
	return e == nil && id != uuid.Nil && id.String() == s
}
