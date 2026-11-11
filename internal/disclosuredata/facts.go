package disclosuredata

import (
	"bytes"
	"math"
	"math/big"
	"net"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	p "privacy-proxy/internal/disclosurepolicy"
)

type factContext struct {
	scope       ReadScope
	descriptors map[SourceKind]SourceDescriptor
	targets     map[[20]byte][]string
	mine        map[[20]byte]bool
	historyKind string
}

func scopeAddress(q NormalizedQuery, a [20]byte) bool {
	return q.scope.Addresses.Mode == "all-target-addresses" || slices.Contains(q.scope.Addresses.Values, addressString(a))
}
func factTime(q NormalizedQuery, t time.Time) bool {
	return utc(t) && !t.Before(time.Unix(q.scope.DataTime.Start, 0)) && !t.After(time.Unix(q.scope.DataTime.End, 0))
}
func (c factContext) provenance(v Provenance, k SourceKind, kind string) bool {
	d, ok := c.descriptors[k]
	if !ok || v.Source != d.Reference || v.Kind != kind || v.DataOrganizationID != c.scope.DataOrganizationID || len(v.TargetActorIDs) == 0 || len(v.TargetActorIDs) > 256 {
		return false
	}
	for i, a := range v.TargetActorIDs {
		if !actor(a) || !slices.Contains(c.scope.Query.scope.TargetActors, a) || i > 0 && v.TargetActorIDs[i-1] >= a {
			return false
		}
	}
	return true
}
func validateFacts(scope ReadScope, ds []SourceDescriptor, f Facts, after *Position) (factContext, error) {
	return validateFactsForHistory(scope, ds, f, after, "CURRENT_SCOPED_WALLET_HISTORY")
}

func validateFactsForHistory(scope ReadScope, ds []SourceDescriptor, f Facts, after *Position, historyKind string) (factContext, error) {
	c := factContext{scope: scope, descriptors: map[SourceKind]SourceDescriptor{}, targets: map[[20]byte][]string{}, mine: map[[20]byte]bool{}, historyKind: historyKind}
	if e := PositionForQuery(scope.Query, after); e != nil {
		return c, e
	}
	if e := CheckFactsBudget(f); e != nil {
		return c, e
	}
	if len(f.Wallets) > 4096 {
		return c, ErrTooBroad
	}
	branches := 0
	for _, present := range []bool{f.Addresses != nil, f.Activities != nil, f.Transactions != nil, f.ActivitySummary != nil, f.Sanctions != nil, f.Compliance != nil} {
		if present {
			branches++
		}
	}
	if branches != 1 {
		return c, ErrUnavailable
	}
	for _, d := range ds {
		if d.NetworkKey == "" {
			return c, ErrUnavailable
		}
		c.descriptors[d.Kind] = d
	}
	q := scope.Query
	needsWallet := false
	for _, d := range ds {
		if d.Kind == WalletSource {
			needsWallet = true
		}
	}
	if !needsWallet && len(f.Wallets) > 0 {
		return c, ErrUnavailable
	}
	walletActors := map[string]bool{}
	var previous *WalletFact
	for i := range f.Wallets {
		w := f.Wallets[i]
		if !actor(w.ActorID) || !utc(w.AcceptedAt) || !slices.Contains(q.scope.TargetActors, w.ActorID) && w.ActorID != scope.RecipientActorID {
			return c, ErrUnavailable
		}
		if previous != nil && (previous.ActorID > w.ActorID || previous.ActorID == w.ActorID && bytes.Compare(previous.Address[:], w.Address[:]) >= 0) {
			return c, ErrUnavailable
		}
		previous = &f.Wallets[i]
		walletActors[w.ActorID] = true
		if len(walletActors) > 257 {
			return c, ErrTooBroad
		}
		if w.ActorID == scope.RecipientActorID {
			c.mine[w.Address] = true
		}
		if slices.Contains(q.scope.TargetActors, w.ActorID) && scopeAddress(q, w.Address) {
			c.targets[w.Address] = append(c.targets[w.Address], w.ActorID)
		}
	}
	for a, ids := range c.targets {
		sort.Strings(ids)
		c.targets[a] = ids
	}
	positions := []Position{}
	switch q.resource {
	case p.AddressHistory:
		if f.Addresses == nil {
			return c, ErrUnavailable
		}
		limit := int(q.limit)
		if q.view == Resolve {
			limit = 4096
			if !f.End || f.Next != nil {
				return c, ErrUnavailable
			}
		}
		if len(f.Addresses) > limit {
			return c, ErrTooBroad
		}
		for _, a := range f.Addresses {
			if !c.addressFact(a) {
				return c, ErrUnavailable
			}
			positions = append(positions, Position{Kind: WalletSource, Address: &AddressPosition{a.Address}})
		}
	case p.ActivityLogs:
		if f.Activities == nil || len(f.Activities) > int(q.limit) {
			return c, ErrUnavailable
		}
		seen := map[string]bool{}
		for _, a := range f.Activities {
			if !c.provenance(a.Provenance, ActivitySource, "AUTHENTICATED_RECORDED_REQUEST_DATA_ORG") || len(a.Provenance.TargetActorIDs) != 1 || !uuidValid(a.ID) || seen[a.ID] || !factTime(q, a.ObservedAt) || !text(a.Method, 100) || a.StatusCode < 100 || a.StatusCode > 599 {
				return c, ErrUnavailable
			}
			if a.TrustedIP != nil {
				ip := net.ParseIP(*a.TrustedIP)
				if ip == nil || ip.String() != *a.TrustedIP || len(*a.TrustedIP) > 45 {
					return c, ErrUnavailable
				}
			}
			seen[a.ID] = true
			pos := Position{Kind: ActivitySource, Activity: &ActivityPosition{a.ObservedAt.UnixMicro(), a.ProducerID, a.RunID, a.CompletionOrdinal, a.ID}}
			if !validPosition(pos) {
				return c, ErrUnavailable
			}
			positions = append(positions, pos)
		}
	case p.Transactions:
		max := int(q.limit)
		if q.view == Detail {
			max = 1
		}
		if f.Transactions == nil || len(f.Transactions) > max || q.view == Detail && len(f.Transactions) != 1 {
			return c, ErrUnavailable
		}
		seenHash := map[[32]byte]bool{}
		seenIndex := map[string]bool{}
		for _, t := range f.Transactions {
			if !c.transaction(t) {
				return c, ErrUnavailable
			}
			index := string(t.BlockNumber) + "/" + strconv.FormatUint(uint64(t.TransactionIndex), 10)
			if seenHash[t.Hash] || seenIndex[index] {
				return c, ErrUnavailable
			}
			seenHash[t.Hash] = true
			seenIndex[index] = true
			positions = append(positions, Position{Kind: HistorySource, Transaction: &TransactionPosition{t.BlockNumber, t.TransactionIndex, t.Hash}})
		}
	case p.ActivitySummary:
		if f.ActivitySummary == nil || !summaryValid(*f.ActivitySummary) {
			return c, ErrUnavailable
		}
	case p.SanctionsReport:
		if f.Sanctions == nil || !c.sanctions(*f.Sanctions) {
			return c, ErrUnavailable
		}
	case p.ComplianceReport:
		if f.Compliance == nil || !summaryValid(f.Compliance.Activity) || !c.sanctions(f.Compliance.Sanctions) || f.Compliance.KYC != "not_evaluated" || len(f.Compliance.Evidence) > 100 {
			return c, ErrUnavailable
		}
		var last uint64
		for i, e := range f.Compliance.Evidence {
			if !c.evidence(e) || i > 0 && countValue(e.ID) <= last {
				return c, ErrUnavailable
			}
			last = countValue(e.ID)
		}
	default:
		return c, ErrUnsupported
	}
	if q.view == List {
		var prev *Position = after
		for i := range positions {
			pos := positions[i]
			if !validPosition(pos) {
				return c, ErrUnavailable
			}
			if prev != nil {
				n, e := ComparePositions(pos, *prev)
				if e != nil || n <= 0 {
					return c, ErrUnavailable
				}
			}
			prev = &positions[i]
		}
		if f.End {
			if f.Next != nil {
				return c, ErrUnavailable
			}
		} else {
			if len(positions) != int(q.limit) || f.Next == nil {
				return c, ErrUnavailable
			}
			n, e := ComparePositions(*f.Next, positions[len(positions)-1])
			if e != nil || n != 0 {
				return c, ErrUnavailable
			}
		}
	} else if !f.End || f.Next != nil {
		return c, ErrUnavailable
	}
	return c, nil
}
func (c factContext) addressFact(a AddressFact) bool {
	ids := c.targets[a.Address]
	return len(ids) > 0 && c.provenance(a.Provenance, HistorySource, c.historyKind) && slices.Equal(ids, a.Provenance.TargetActorIDs) && (a.ENSName == nil || text(*a.ENSName, 255))
}
func (c factContext) participants(t TransactionFact) ([]string, [][20]byte) {
	ids := []string{}
	addresses := [][20]byte{}
	for _, a := range [][20]byte{t.From} {
		if found := c.targets[a]; len(found) > 0 {
			ids = append(ids, found...)
			addresses = append(addresses, a)
		}
	}
	if t.To != nil && *t.To != t.From {
		if found := c.targets[*t.To]; len(found) > 0 {
			ids = append(ids, found...)
			addresses = append(addresses, *t.To)
		}
	}
	sort.Strings(ids)
	ids = slices.Compact(ids)
	return ids, addresses
}
func (c factContext) direction(t TransactionFact) string {
	from := len(c.targets[t.From]) > 0
	to := t.To != nil && len(c.targets[*t.To]) > 0
	if from && to {
		return "self"
	}
	if from {
		return "outgoing"
	}
	return "incoming"
}
func (c factContext) transaction(t TransactionFact) bool {
	q := c.scope.Query
	ids, _ := c.participants(t)
	if len(ids) == 0 || !c.provenance(t.Provenance, HistorySource, c.historyKind) || !slices.Equal(ids, t.Provenance.TargetActorIDs) || !countValid(t.BlockNumber) || !countValid(t.GasUsed) || !amountValid(t.Value) || t.Status > 1 || t.BlockTime < q.scope.DataTime.Start || t.BlockTime > q.scope.DataTime.End || t.Direction != c.direction(t) {
		return false
	}
	if q.view == Detail {
		return hashString(t.Hash) == q.hash && t.Full != nil && detailValid(t)
	}
	return t.Full == nil
}
func detailValid(t TransactionFact) bool {
	v := t.Full
	if v == nil || !amountValid(v.EffectiveGasPrice) || !countValid(v.GasLimit) || !countValid(v.Nonce) || countValue(t.GasUsed) > countValue(v.GasLimit) || len(v.Input) < 2 || len(v.Input) > 1<<20 || !strings.HasPrefix(v.Input, "0x") || (len(v.Input)-2)%2 != 0 {
		return false
	}
	for _, c := range v.Input[2:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	for _, s := range []*string{v.Error, v.RevertReason} {
		if s != nil && (len(*s) > 16384 || !validUTF8(*s)) {
			return false
		}
	}
	if v.ContractAddress != nil && (t.To != nil || t.Status != 1) {
		return false
	}
	if v.Type == 0 || v.Type == 1 {
		return v.SignedLegacyGasPrice != nil && amountValid(*v.SignedLegacyGasPrice) && *v.SignedLegacyGasPrice == v.EffectiveGasPrice && v.MaxFeePerGas == nil && v.MaxPriorityFeePerGas == nil
	}
	if v.Type < 2 || v.Type > 4 || v.SignedLegacyGasPrice != nil || v.MaxFeePerGas == nil || v.MaxPriorityFeePerGas == nil || v.BlockBaseFeePerGas == nil || !amountValid(*v.MaxFeePerGas) || !amountValid(*v.MaxPriorityFeePerGas) || !amountValid(*v.BlockBaseFeePerGas) {
		return false
	}
	cap, _ := new(big.Int).SetString(string(*v.MaxFeePerGas), 10)
	tip, _ := new(big.Int).SetString(string(*v.MaxPriorityFeePerGas), 10)
	base, _ := new(big.Int).SetString(string(*v.BlockBaseFeePerGas), 10)
	if tip.Cmp(cap) > 0 || base.Cmp(cap) > 0 {
		return false
	}
	paid := new(big.Int).Add(base, tip)
	if paid.Cmp(cap) > 0 {
		paid.Set(cap)
	}
	return paid.String() == string(v.EffectiveGasPrice)
}
func summaryValid(s ActivityAggregate) bool {
	if !countValid(s.Total) || !countValid(s.Successful) || !countValid(s.Failed) || s.Methods == nil || len(s.Methods) > 512 {
		return false
	}
	total, good, bad := countValue(s.Total), countValue(s.Successful), countValue(s.Failed)
	if good > total || bad != total-good {
		return false
	}
	var nt, ng, nb uint64
	prev := ""
	for _, m := range s.Methods {
		if !text(m.Method, 100) || m.Method <= prev || !countValid(m.Total) || !countValid(m.Successful) || !countValid(m.Failed) {
			return false
		}
		t, g, b := countValue(m.Total), countValue(m.Successful), countValue(m.Failed)
		if g > t || b != t-g || t > total-nt || g > good-ng || b > bad-nb {
			return false
		}
		nt += t
		ng += g
		nb += b
		prev = m.Method
	}
	return nt == total && ng == good && nb == bad
}
func (c factContext) sanctions(s SanctionsAggregate) bool {
	d, ok := c.descriptors[SanctionsSource]
	if !ok || s.SourceDigest != d.Reference || !utc(s.CheckedAt) || s.Matches == nil || len(s.Matches) > 4096 || int(s.ScopedAddressCount) > len(c.targets) {
		return false
	}
	unique := map[[20]byte]bool{}
	sourceIDs := map[string]bool{}
	for _, m := range s.Matches {
		if len(c.targets[m.Address]) == 0 || !uuidValid(m.SourceID) || sourceIDs[m.SourceID] || len(m.Reason) > 1<<20 || !validUTF8(m.Reason) {
			return false
		}
		sourceIDs[m.SourceID] = true
		unique[m.Address] = true
	}
	if len(unique) > int(s.ScopedAddressCount) {
		return false
	}
	if s.ScopedAddressCount == 0 {
		return s.Status == "not-applicable" && len(s.Matches) == 0
	}
	if len(s.Matches) == 0 {
		return s.Status == "clear"
	}
	return s.Status == "hit"
}
func (c factContext) evidence(e ComplianceEvidence) bool {
	if !c.provenance(e.Provenance, FinanceSource, "ADMISSION_DECISION") || !countValid(e.ID) || countValue(e.ID) == 0 || !factTime(c.scope.Query, e.DecisionAt) || e.Decision != "allowed" && e.Decision != "denied" || !digestValid(e.PolicyDigest) || len(e.Reason) > 2048 || !validUTF8(e.Reason) || e.RecordID != nil && !uuidValid(*e.RecordID) {
		return false
	}
	if e.Kind == "admission_only" {
		if e.Decision != "allowed" || e.Monitored || e.Reason != "" || e.RecordID != nil || e.Quote != nil || e.QuoteDigest != nil || e.Coverage != "not_detected" && e.Coverage != "disabled" && e.Coverage != "relay_request" {
			return false
		}
	} else if (e.Kind != "root_native" && e.Kind != "root_erc20") || e.Coverage != "root_transfer" {
		return false
	}
	if (e.Quote == nil) != (e.QuoteDigest == nil) {
		return false
	}
	if e.Quote != nil {
		q := e.Quote
		v, err := strconv.ParseFloat(q.Value, 64)
		if !digestValid(q.Digest) || q.Digest != *e.QuoteDigest || len(q.Value) > 512 || err != nil || math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v >= 1e100 || strconv.FormatFloat(v, 'g', -1, 64) != q.Value || !text(q.ID, 128) || !text(q.SourceID, 128) || len(q.Currency) != 3 || !utc(q.ProviderAsOf) || !utc(q.FetchedAt) {
			return false
		}
	}
	return true
}
func cloneValue(v reflect.Value) reflect.Value {
	if !v.IsValid() || v.Type() == timeType {
		return v
	}
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return reflect.Zero(v.Type())
		}
		n := reflect.New(v.Type().Elem())
		n.Elem().Set(cloneValue(v.Elem()))
		return n
	case reflect.Slice:
		if v.IsNil() {
			return reflect.Zero(v.Type())
		}
		n := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		for i := 0; i < v.Len(); i++ {
			n.Index(i).Set(cloneValue(v.Index(i)))
		}
		return n
	case reflect.Struct:
		n := reflect.New(v.Type()).Elem()
		for i := 0; i < v.NumField(); i++ {
			n.Field(i).Set(cloneValue(v.Field(i)))
		}
		return n
	}
	return v
}

// DetachFacts applies the cheap aggregate preflight before copying provider memory.
func DetachFacts(f Facts) (Facts, error) {
	if e := CheckFactsBudget(f); e != nil {
		return Facts{}, e
	}
	return cloneValue(reflect.ValueOf(f)).Interface().(Facts), nil
}
