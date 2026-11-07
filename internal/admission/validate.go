package admission

import (
	"bytes"
	"encoding/json"
	"io"
	"unicode/utf8"

	"privacy-proxy/internal/compliance"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/strictjson"
)

func NormalizePII(raw []byte) (json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > MaxPIIBytes || !utf8.Valid(raw) {
		return nil, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	value, err := strictjson.ReadValue(d, 0, 16)
	if err != nil {
		return nil, ErrInvalid
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrInvalid
	}
	if _, ok := value.(map[string]any); !ok {
		return nil, ErrInvalid
	}
	out, err := json.Marshal(value)
	if err != nil || len(out) > MaxPIIBytes {
		return nil, ErrInvalid
	}
	return out, nil
}
func (w Witness) Valid() bool {
	return w.ID == w.Digest() && w.AnchorHash != ([32]byte{}) && (w.EvidenceProfile == rpcexecution.GuardRetainedProfileID || w.EvidenceProfile == SignedEvidenceProfile) && w.WalletVersion != (Digest{}) && !w.DecisionAt.IsZero() && !w.WalletEvidenceAt.IsZero() && w.ManifestDigest != (Digest{}) && w.ComplianceDigest != (Digest{})
}
func (o Origin) Valid() bool {
	return validActor(o.Actor) && ValidUUID(o.Organization) && !o.FirstAdmittedAt.IsZero() && o.Hash != ([32]byte{}) && o.Primary.Valid()
}
func (s Share) Valid() bool {
	recipients, digest, err := NormalizeRecipients(s.Recipients)
	return err == nil && len(recipients) > 0 && s.RecipientDigest == digest && slicesEqual(s.Recipients, recipients) && validActor(s.Actor) && ValidUUID(s.Organization) && !s.DeclaredAt.IsZero() && s.Hash != ([32]byte{}) && s.Witness.AnchorHash != ([32]byte{}) && s.Witness.ManifestDigest != (Digest{}) && s.Witness.WalletVersion != (Digest{}) && !s.Witness.WalletEvidenceAt.IsZero()
}
func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func (e Event) Valid() bool {
	if !e.Scope.Valid() || e.DecisionAt.IsZero() || e.PolicyDigest == (Digest{}) || !text(e.Reason, 2048, true) || (e.Decision != "allowed" && e.Decision != "denied") || e.Anchor.Hash == ([32]byte{}) || (e.Anchor.Profile != rpcexecution.GuardRetainedProfileID && e.Anchor.Profile != SignedEvidenceProfile) {
		return false
	}
	if e.Kind == "admission_only" {
		return (e.Coverage == "not_detected" || e.Coverage == "disabled" || e.Coverage == "relay_request") && e.Decision == "allowed" && !e.Monitored && e.From == nil && e.To == nil && e.Token == nil && e.AmountWei == nil && e.AmountFiat == nil && e.Threshold == nil && e.Currency == nil && e.RecordID == nil && e.Quote == nil && e.Reason == ""
	}
	if (e.Kind != "root_native" && e.Kind != "root_erc20") || e.Coverage != "root_transfer" || e.From == nil || e.To == nil || e.AmountWei == nil || e.Currency == nil || !compliance.IsValidCurrency(*e.Currency) || (e.Kind == "root_native" && e.Token != nil) || (e.Kind == "root_erc20" && e.Token == nil) {
		return false
	}
	if _, err := ParseUint256(*e.AmountWei, false); err != nil {
		return false
	}
	for _, v := range []*float64{e.AmountFiat, e.Threshold} {
		if v != nil {
			if _, err := CanonicalFiat(*v); err != nil {
				return false
			}
		}
	}
	if e.RecordID != nil && !ValidUUID(*e.RecordID) {
		return false
	}
	if e.Quote != nil && (!e.Quote.Valid() || e.AmountFiat == nil || e.Quote.Currency != *e.Currency || e.Quote.Digest != quoteDigest(*e.Quote)) {
		return false
	}
	return true
}
