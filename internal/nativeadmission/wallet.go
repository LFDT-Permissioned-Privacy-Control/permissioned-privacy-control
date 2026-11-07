package nativeadmission

import (
	"errors"
	"slices"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

const MaxWalletAddresses = 4096
const MaxWalletBytes = 128 << 10

// WalletSnapshot is trusted operational adapter output bound to one canonical
// actor. This constructor checks shape/ownership, not a wallet proof or DB trust.
type WalletSnapshot struct {
	actorID, version string
	evidenceAt       time.Time
	addresses        []common.Address
	valid            bool
}

func NewWalletSnapshot(actorID, version string, evidenceAt time.Time, addresses []common.Address) (WalletSnapshot, error) {
	if actorID == "" || len(actorID) > 256 || version == "" || len(version) > 256 || evidenceAt.IsZero() || len(addresses) > MaxWalletAddresses || len(addresses) > MaxWalletBytes/common.AddressLength {
		return WalletSnapshot{}, errors.New("invalid wallet snapshot")
	}
	seen := make(map[common.Address]bool, len(addresses))
	for _, address := range addresses {
		if seen[address] {
			return WalletSnapshot{}, errors.New("invalid wallet snapshot")
		}
		seen[address] = true
	}
	return WalletSnapshot{actorID: actorID, version: version, evidenceAt: evidenceAt, addresses: slices.Clone(addresses), valid: true}, nil
}
func (w WalletSnapshot) ActorID() string             { return w.actorID }
func (w WalletSnapshot) Version() string             { return w.version }
func (w WalletSnapshot) EvidenceAt() time.Time       { return w.evidenceAt }
func (w WalletSnapshot) Addresses() []common.Address { return slices.Clone(w.addresses) }
func (w WalletSnapshot) Contains(address common.Address) bool {
	return w.valid && slices.Contains(w.addresses, address)
}
