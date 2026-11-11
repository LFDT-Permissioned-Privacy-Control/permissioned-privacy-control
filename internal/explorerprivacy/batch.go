package explorerprivacy

import (
	"strings"

	"privacy-proxy/internal/readprivacy"
	"privacy-proxy/internal/readprivacyabi"
)

// Batch supplies detached, already resolved facts. These checks establish
// completeness of the pure rendering input, not authenticity, source currentness
// or permission provenance. Those belong to the operation's current-fact owner.
// Legacy adapters call the extracted row primitives to retain their old lookup
// and error behavior; new consumers use this complete-batch boundary.
type Batch struct {
	Transactions *TransactionInput
	Transfers    *TransferInput
	Internals    *InternalInput
	Logs         *LogInput
	Holders      *HolderInput
	Options      RedactOpts
	EventAccess  map[string]bool
}

type BatchOutput struct {
	Transactions []Transaction
	Transfers    []TokenTransfer
	Internals    []InternalTransaction
	Logs         []Log
	Holders      []TokenHolder
}

const maxBatchRows = 20000

func knownLevel(v VisibilityLevel) bool {
	return v == VisibilityFull || v == VisibilityPseudonymous || v == VisibilityRedacted || v == VisibilityHidden
}

func detailedAddress(m map[string]AddressVisibility, address string) bool {
	if address == "" {
		return true
	}
	v, ok := m[strings.ToLower(address)]
	return ok && knownLevel(v.Level)
}

func plainAddress(m VisibilityMap, address string) bool {
	if address == "" {
		return true
	}
	v, ok := m[strings.ToLower(address)]
	return ok && knownLevel(v)
}

func explicitFlag(m map[string]bool, address string) bool {
	_, ok := m[strings.ToLower(address)]
	return ok
}

func completeBatch(b Batch) bool {
	total := 0
	var profile readprivacy.ReadProfile
	profileSet := false
	sameProfile := func(p readprivacy.ReadProfile) bool {
		if p != readprivacy.ReadProfileStandard && p != readprivacy.ReadProfileStrict || profileSet && profile != p {
			return false
		}
		profile, profileSet = p, true
		return true
	}
	add := func(n int) bool {
		if n > maxBatchRows-total {
			return false
		}
		total += n
		return true
	}
	if in := b.Transactions; in != nil {
		if !sameProfile(in.Profile) || !add(len(in.Rows)) || !in.Profile.Strict() && len(in.CalldataParticipants) != len(in.Rows) {
			return false
		}
		for _, tx := range in.Rows {
			if !detailedAddress(in.Detailed, tx.From) || tx.HasRecipient() && !detailedAddress(in.Detailed, *tx.To) || tx.ContractAddress != nil && !detailedAddress(in.Detailed, *tx.ContractAddress) {
				return false
			}
			if !in.Profile.Strict() {
				if !explicitFlag(in.LogParticipants, tx.Hash) || !b.Options.ViewerIsAdmin && tx.TokenTransferCount > 0 && tx.HasRecipient() && !explicitFlag(b.EventAccess, *tx.To) {
					return false
				}
			}
		}
	}
	if in := b.Transfers; in != nil {
		if !sameProfile(in.Profile) || !add(len(in.Rows)) {
			return false
		}
		for _, row := range in.Rows {
			if !detailedAddress(in.Detailed, row.From) || !detailedAddress(in.Detailed, row.To) {
				return false
			}
			if in.Profile.Strict() {
				if _, ok := in.StrictAdmitted[TransferLogKey(row.TxHash, row.LogIndex)]; !ok {
					return false
				}
			} else if !b.Options.ViewerIsAdmin && !explicitFlag(b.EventAccess, row.TokenAddress) {
				return false
			}
		}
	}
	if in := b.Internals; in != nil {
		if !sameProfile(in.Profile) || !add(len(in.Rows)) {
			return false
		}
		for _, row := range in.Rows {
			if !detailedAddress(in.Detailed, row.From) || row.To != nil && !detailedAddress(in.Detailed, *row.To) {
				return false
			}
			if in.Profile.Strict() && in.Parents[strings.ToLower(row.TxHash)] == nil {
				return false
			}
		}
	}
	if in := b.Logs; in != nil {
		if !sameProfile(in.Profile) || !add(len(in.Rows)) || in.ABIResolverAbsent {
			return false
		}
		for _, row := range in.Rows {
			addr := strings.ToLower(row.Address)
			if !plainAddress(in.Visibility, addr) {
				return false
			}
			if in.Visibility[addr] == VisibilityHidden {
				continue // the preserved Hidden-emitter floor needs no bypass facts
			}
			if !explicitFlag(in.AdminContracts, addr) || !explicitFlag(in.UnlockableContracts, addr) || !explicitFlag(in.AllowDynamicPayload, addr) || !in.RulesResolved[addr] {
				return false
			}
			if _, ok := in.Rules[addr]; !ok {
				return false
			}
			abi, ok := in.ContractABIs[addr]
			resolved, present := in.ResolvedABIs[addr]
			if !ok || !present || string(abi) != resolved {
				return false
			}
			for _, embedded := range readprivacyabi.ExtractLogAddresses([]*string{row.Topic0, row.Topic1, row.Topic2, row.Topic3}, row.Data, abi, row.Topic0) {
				if !plainAddress(in.Visibility, embedded) {
					return false
				}
			}
		}
	}
	if in := b.Holders; in != nil {
		if !add(len(in.Rows)) {
			return false
		}
		for _, row := range in.Rows {
			if !plainAddress(in.Visibility, row.Address) {
				return false
			}
		}
	}
	return true
}

// RedactBatch runs the same row/field bodies used by the V1 adapters. Missing
// context is an error before rendering any branch, so omitted rule maps cannot
// select the legacy no-resolver wildcard posture for a new consumer.
func RedactBatch(b Batch) (BatchOutput, error) {
	if !completeBatch(b) {
		return BatchOutput{}, errContext
	}
	var out BatchOutput
	var err error
	if in := b.Transactions; in != nil {
		out.Transactions, err = RedactTransactions(*in, b.Options)
		if err != nil {
			return BatchOutput{}, err
		}
		if !in.Profile.Strict() && !b.Options.ViewerIsAdmin {
			out.Transactions = ApplyTransactionEventAccess(out.Transactions, b.EventAccess)
		}
	}
	if in := b.Transfers; in != nil {
		rendered := RedactTransfers(*in, b.Options)
		out.Transfers = rendered.Rows
		if in.Profile.Strict() || !b.Options.ViewerIsAdmin {
			out.Transfers, err = ApplyTransferEventAccess(rendered.Rows, rendered.EventAccessExempt, b.EventAccess)
			if err != nil {
				return BatchOutput{}, err
			}
		}
	}
	if in := b.Internals; in != nil {
		out.Internals, err = RedactInternalTransactions(*in, b.Options)
		if err != nil {
			return BatchOutput{}, err
		}
	}
	if in := b.Logs; in != nil {
		out.Logs, err = RedactLogs(*in, &b.Options)
		if err != nil {
			return BatchOutput{}, err
		}
	}
	if in := b.Holders; in != nil {
		out.Holders, err = RedactTokenHolders(*in)
		if err != nil {
			return BatchOutput{}, err
		}
	}
	return out, nil
}
