package explorerprivacy

import "strings"

// ApplyTransactionEventAccess is the old post-batch-lookup field strip, with
// already resolved access facts. It is not a permission source or an I/O hook.
func ApplyTransactionEventAccess(redactedTxs []Transaction, eventAccess map[string]bool) []Transaction {
	for i := range redactedTxs {
		if redactedTxs[i].TokenTransferCount > 0 && redactedTxs[i].HasRecipient() {
			toAddr := strings.ToLower(*redactedTxs[i].To)
			if !eventAccess[toAddr] {
				redactedTxs[i].TokenTransferCount = 0
				redactedTxs[i].TxCategories = RemoveCategory(redactedTxs[i].TxCategories, "token_transfer")
				// If stripping "token_transfer" left no categories, restore
				// "contract_call" — the tx still called a contract.
				// Note: can't check InputData here because it may have been
				// stripped by the redaction loop above.
				if len(redactedTxs[i].TxCategories) == 0 && redactedTxs[i].HasRecipient() {
					redactedTxs[i].TxCategories = []string{"contract_call"}
				}
			}
		}
	}
	return redactedTxs
}

func ApplyTransferEventAccess(result []TokenTransfer, exempt []bool, eventAccess map[string]bool) ([]TokenTransfer, error) {
	if len(result) != len(exempt) {
		return nil, errContext
	}
	var filtered []TokenTransfer
	for i, t := range result {
		if exempt[i] || eventAccess[strings.ToLower(t.TokenAddress)] {
			filtered = append(filtered, t)
		}
	}
	return filtered, nil
}
