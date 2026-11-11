package protectedsource

import (
	"bytes"
	"encoding/hex"
	"slices"

	d "privacy-proxy/internal/disclosuredata"
)

func targetWallets(scope d.ReadScope, wallets []d.WalletFact) ([][20]byte, map[[20]byte][]string, error) {
	if len(wallets) > 4096 {
		return nil, nil, d.ErrTooBroad
	}
	selected := scope.Query.Scope()
	actors := map[[20]byte][]string{}
	for _, wallet := range wallets {
		if !slices.Contains(selected.TargetActors, wallet.ActorID) {
			continue
		}
		address := "0x" + hex.EncodeToString(wallet.Address[:])
		if selected.Addresses.Mode == "list" && !slices.Contains(selected.Addresses.Values, address) {
			continue
		}
		actors[wallet.Address] = append(actors[wallet.Address], wallet.ActorID)
	}
	addresses := make([][20]byte, 0, len(actors))
	for address, ids := range actors {
		slices.Sort(ids)
		actors[address] = slices.Compact(ids)
		addresses = append(addresses, address)
	}
	slices.SortFunc(addresses, func(a, b [20]byte) int { return bytes.Compare(a[:], b[:]) })
	return addresses, actors, nil
}

func transactionFact(scope d.ReadScope, reference d.Digest, actors map[[20]byte][]string, fact d.TransactionFact) (d.TransactionFact, error) {
	ids := slices.Clone(actors[fact.From])
	from := len(ids) > 0
	to := false
	if fact.To != nil {
		to = len(actors[*fact.To]) > 0
		if *fact.To != fact.From {
			ids = append(ids, actors[*fact.To]...)
		}
	}
	slices.Sort(ids)
	ids = slices.Compact(ids)
	if len(ids) == 0 {
		return d.TransactionFact{}, d.ErrUnavailable
	}
	fact.Provenance = d.Provenance{Source: reference, DataOrganizationID: scope.DataOrganizationID, TargetActorIDs: ids, Kind: d.RetainedHistoryPopulation}
	switch {
	case from && to:
		fact.Direction = "self"
	case from:
		fact.Direction = "outgoing"
	default:
		fact.Direction = "incoming"
	}
	return fact, nil
}
