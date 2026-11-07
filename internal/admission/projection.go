package admission

import (
	"encoding/hex"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/transactioninput"
)

func lifecycleEvidenceProfile(profile string) bool {
	return profile == rpcexecution.LifecycleSignedProfileID || profile == rpcexecution.LifecycleGuardProfileID
}

func supportedEvidenceProfile(profile string) bool {
	return profile == rpcexecution.GuardRetainedProfileID || profile == SignedEvidenceProfile || lifecycleEvidenceProfile(profile)
}

// financialProjection is shared by admission and read-only preview. Creation
// initcode is executable code, never ERC20 calldata: only its native value is
// projected to the independently derived destination through the same Checker.
func financialProjection(tx transactioninput.VerifiedTransaction, profile string) (common.Address, string, error) {
	if !tx.Valid() {
		return common.Address{}, "", ErrInvalid
	}
	if tx.Creation() {
		if !lifecycleEvidenceProfile(profile) {
			return common.Address{}, "", ErrInvalid
		}
		return crypto.CreateAddress(tx.Signer(), tx.Nonce()), "0x", nil
	}
	to, ok := tx.Destination()
	if !ok {
		return common.Address{}, "", ErrInvalid
	}
	return to, "0x" + hex.EncodeToString(tx.Input()), nil
}
