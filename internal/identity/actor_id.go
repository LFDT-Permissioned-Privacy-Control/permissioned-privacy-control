package identity

import (
	"encoding/base64"
	"strings"
)

// SourceIdentity is canonical identifier input, not verified provider evidence.
// Callers still verify signatures, source facts, freshness and holder binding.
type SourceIdentity struct {
	ProfileID          string
	Kind               Kind
	Authority, Subject string
	Tenant             *string
}

// SourceActorID validates the source tuple against one selected immutable
// profile and uses the same encoder as Core access verification. It does not
// authenticate the caller, verify provider evidence or grant group membership.
func (c *Catalog) SourceActorID(source SourceIdentity) (string, error) {
	if c == nil {
		return "", invalid("catalog", "source-identity")
	}
	profile, ok := c.profiles[source.ProfileID]
	if !ok {
		return "", invalid("profile", "source-identity")
	}
	return sourceActorID(source, profile, c.limits)
}
func sourceActorID(source SourceIdentity, p Profile, l Limits) (string, error) {
	if source.ProfileID != p.ID || source.Kind != expectedKind(p) || !text(source.Subject, l.MaxSourceSubjectBytes) || !text(source.Authority, l.MaxURLBytes) {
		return "", invalid("source-identity", "token")
	}
	if p.Kind == AzureHuman || p.Kind == AzureService {
		if source.Authority != p.Issuer || source.Tenant == nil || *source.Tenant != p.TenantID || !uuid(source.Subject) {
			return "", invalid("source-identity", "token")
		}
		return actorID("azure-v2", p.Issuer, p.TenantID, source.Subject, string(source.Kind)), nil
	}
	if p.Kind != PrivadoIdentity && p.Kind != PrivadoRole {
		return "", invalid("source-identity", "token")
	}
	network, ok := did(source.Subject, l.MaxSourceSubjectBytes)
	if !ok || network != p.Network || source.Tenant != nil || source.Authority != "privado" {
		return "", invalid("source-identity", "token")
	}
	return actorID("privado", source.Subject, string(source.Kind)), nil
}

// ValidActorID checks the canonical identifier syntax, not the holder's
// identity or authority. Those are established by VerifyAccess and its catalog.
func ValidActorID(actor string) bool {
	const prefix = "ops:p1:"
	if len(actor) != len(prefix)+43 || !strings.HasPrefix(actor, prefix) {
		return false
	}
	encoded := actor[len(prefix):]
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	return err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == encoded
}
