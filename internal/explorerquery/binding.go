// Package explorerquery defines the bounded indexed-read purpose boundary.
// A configured binding is not an attestation of database chain contents.
package explorerquery

import (
	"github.com/google/uuid"
	"privacy-proxy/internal/networkidentity"
)

type Binding struct {
	Network         networkidentity.Binding
	SourceReference [32]byte
	SchemaDigest    [32]byte
	ConfiguredEpoch string
}

func (b Binding) Valid() bool {
	_, err := b.Network.Key()
	id, epochErr := uuid.Parse(b.ConfiguredEpoch)
	return err == nil && epochErr == nil && id != uuid.Nil && id.String() == b.ConfiguredEpoch && b.SourceReference != ([32]byte{}) && b.SchemaDigest != ([32]byte{})
}

// ReaderIdentity distinguishes concrete borrowed instances, not permissions.
type ReaderIdentity struct{ marker byte }

func NewReaderIdentity() *ReaderIdentity { return &ReaderIdentity{1} }
func (i *ReaderIdentity) Valid() bool    { return i != nil && i.marker == 1 }

type Metadata struct {
	Binding  Binding
	Mode     string
	Identity *ReaderIdentity
}
