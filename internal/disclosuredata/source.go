package disclosuredata

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"slices"
	"time"

	p "privacy-proxy/internal/disclosurepolicy"
)

func RequiredKinds(r p.Resource) ([]SourceKind, error) {
	switch r {
	case p.ActivityLogs, p.ActivitySummary:
		return []SourceKind{ActivitySource}, nil
	case p.AddressHistory, p.Transactions:
		return []SourceKind{HistorySource, WalletSource}, nil
	case p.SanctionsReport:
		return []SourceKind{HistorySource, SanctionsSource, WalletSource}, nil
	case p.ComplianceReport:
		return []SourceKind{ActivitySource, FinanceSource, HistorySource, SanctionsSource, WalletSource}, nil
	}
	return nil, ErrUnsupported
}
func population(k SourceKind) string {
	switch k {
	case WalletSource:
		return "CURRENT_PROVED_ASSOCIATIONS"
	case ActivitySource:
		return "SEALED_RPC_COMPLETIONS_AS_OF_CHAIN_HEAD"
	case HistorySource:
		return "CURRENT_SCOPED_WALLET_HISTORY"
	case FinanceSource:
		return "RETAINED_ADMISSION_DECISIONS_AS_OF_SNAPSHOT"
	case SanctionsSource:
		return "CURRENT_APPROVED_SANCTIONS"
	}
	return ""
}
func SourceReferences(ds []SourceDescriptor) ([]SourceRef, error) {
	if len(ds) < 1 || len(ds) > 5 {
		return nil, ErrUnavailable
	}
	out := make([]SourceRef, 0, len(ds))
	for i, d := range ds {
		if d.Version != 1 || population(d.Kind) == "" || d.Population != population(d.Kind) || !digestValid(d.Reference) || !digestValid(d.NetworkKey) || !digestValid(d.Epoch) || !digestValid(d.PlanDigest) || !digestValid(d.FormatDigest) || !digestValid(d.CoverageDigest) || !uuidValid(d.Generation) || !utc(d.AsOf) || i > 0 && ds[i-1].Kind >= d.Kind {
			return nil, ErrUnavailable
		}
		out = append(out, SourceRef{d.Kind, d.Reference})
	}
	return out, nil
}
func SourceSetDigest(ds []SourceDescriptor, r p.Resource, v View) (Digest, error) {
	refs, e := SourceReferences(ds)
	if e != nil {
		return "", e
	}
	k, e := RequiredKinds(r)
	if e != nil {
		return "", e
	}
	if len(k) != len(refs) {
		return "", ErrUnavailable
	}
	for i := range refs {
		if refs[i].Kind != k[i] {
			return "", ErrUnavailable
		}
	}
	type stable struct {
		V          uint8      `json:"v"`
		Kind       SourceKind `json:"kind"`
		Ref        Digest     `json:"ref"`
		Network    Digest     `json:"network"`
		Epoch      Digest     `json:"epoch"`
		Generation string     `json:"generation"`
		Plan       Digest     `json:"plan"`
		Format     Digest     `json:"format"`
		Coverage   Digest     `json:"coverage"`
		Population string     `json:"population"`
	}
	type reference struct {
		Kind SourceKind `json:"kind"`
		ID   Digest     `json:"id"`
	}
	canonical := struct {
		V           uint8       `json:"v"`
		Descriptors []stable    `json:"descriptors"`
		Refs        []reference `json:"refs"`
		Resource    p.Resource  `json:"resource"`
		View        View        `json:"view"`
	}{V: 1, Resource: r, View: v, Descriptors: []stable{}, Refs: []reference{}}
	for _, d := range ds {
		canonical.Descriptors = append(canonical.Descriptors, stable{d.Version, d.Kind, d.Reference, d.NetworkKey, d.Epoch, d.Generation, d.PlanDigest, d.FormatDigest, d.CoverageDigest, d.Population})
		canonical.Refs = append(canonical.Refs, reference{d.Kind, d.Reference})
	}
	raw, _ := jsonBytes(canonical)
	return hashParts("ops.disclosure.source-set/v1", raw), nil
}
func cloneKeys(k Keys) (Keys, error) {
	out := Keys{}
	all := []Key{k.Active}
	if k.Previous != nil {
		all = append(all, *k.Previous)
	}
	for i, x := range all {
		if !keyID(x.ID) || len(x.Bytes) != 32 || slices.Equal(x.Bytes, make([]byte, 32)) {
			return out, ErrInvalid
		}
		if i == 1 && (x.ID == all[0].ID || hmac.Equal(x.Bytes, all[0].Bytes)) {
			return out, ErrInvalid
		}
		n := Key{x.ID, append([]byte{}, x.Bytes...)}
		if i == 0 {
			out.Active = n
		} else {
			out.Previous = &n
		}
	}
	return out, nil
}
func RenderGeneration(k Keys) (Digest, error) {
	keys, e := cloneKeys(k)
	if e != nil {
		return "", e
	}
	mac := hmac.New(sha256.New, keys.Active.Bytes)
	mac.Write(framed([]byte("ops.disclosure.render-generation/v1"), []byte(keys.Active.ID)))
	return Digest("sha256:" + hex.EncodeToString(mac.Sum(nil))), nil
}
func RenderContextDigest(c RenderContext) (Digest, error) {
	g, e := RenderGeneration(c.Keys)
	if e != nil || !digestValid(c.Namespace) || !uuidValid(c.CaseID) || !uuidValid(c.DataOrganizationID) || !actor(c.RecipientActorID) || rank(c.Query.scope.Level) < 0 {
		return "", ErrInvalid
	}
	raw, _ := digestBytes(g)
	return hashParts("ops.disclosure.render-context/v1", raw, []byte(c.Namespace), []byte(c.CaseID), []byte(c.DataOrganizationID), []byte(c.RecipientActorID), []byte(c.Query.scope.Level)), nil
}

// Length/cardinality checks intentionally precede UTF8 scans, copies and hashing.
// All source types are closed and acyclic; time.Time's internal pointers are not data.
func CheckFactsBudget(f Facts) error { return valueBudget(reflect.ValueOf(f), NewBudget()) }

var timeType = reflect.TypeOf(time.Time{})

func valueBudget(v reflect.Value, b *Budget) error {
	if !v.IsValid() || v.Type() == timeType {
		return nil
	}
	switch v.Kind() {
	case reflect.String:
		return b.AddBytes(uint64(v.Len()))
	case reflect.Pointer:
		if !v.IsNil() {
			if e := b.AddItems(1); e != nil {
				return e
			}
			return valueBudget(v.Elem(), b)
		}
	case reflect.Slice:
		if e := b.AddItems(uint64(v.Len())); e != nil {
			return e
		}
		for i := 0; i < v.Len(); i++ {
			if e := valueBudget(v.Index(i), b); e != nil {
				return e
			}
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if e := valueBudget(v.Field(i), b); e != nil {
				return e
			}
		}
	}
	return nil
}

// CopyKeys validates and detaches key material across the service/package boundary.
func CopyKeys(k Keys) (Keys, error) { return cloneKeys(k) }
func StrongNamespace(base string, network [32]byte) (Digest, error) {
	if !digestValid(Digest(base)) {
		return "", ErrInvalid
	}
	return hashParts("ops.disclosure.strong-case-namespace/v2", []byte(base), network[:]), nil
}
