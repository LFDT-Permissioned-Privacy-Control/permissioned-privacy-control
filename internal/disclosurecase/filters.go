package disclosurecase

import (
	"privacy-proxy/internal/disclosurepolicy"
	"privacy-proxy/internal/identity"
	"time"
)

// CaseFilters select metadata inside an already authorized organization or
// recipient scope. Status is evaluated at query time, never an access grant.
type CaseFilters struct {
	Status, PrivacyLevel, RecipientActorID string
	CreatedFrom, CreatedTo                 int64
}

func (f CaseFilters) Valid() bool {
	return (f.Status == "" || f.Status == "active" || f.Status == "expired" || f.Status == "revoked") &&
		(f.PrivacyLevel == "" || f.PrivacyLevel == "redacted" || f.PrivacyLevel == "pseudonymous" || f.PrivacyLevel == "full") &&
		(f.RecipientActorID == "" || identity.ValidActorID(f.RecipientActorID)) &&
		f.CreatedFrom >= 0 && f.CreatedTo >= 0 && f.CreatedFrom <= disclosurepolicy.MaxUnixSeconds && f.CreatedTo <= disclosurepolicy.MaxUnixSeconds &&
		(f.CreatedFrom == 0 || f.CreatedTo == 0 || f.CreatedFrom < f.CreatedTo)
}
func (f CaseFilters) Matches(c Case, at time.Time) bool {
	status := c.Status
	if status == "open" {
		status = "active"
		if !at.Before(c.ExpiresAt) {
			status = "expired"
		}
	}
	return (f.Status == "" || f.Status == status) && (f.PrivacyLevel == "" || f.PrivacyLevel == string(c.Scope.Level)) &&
		(f.RecipientActorID == "" || f.RecipientActorID == c.RecipientActor) &&
		(f.CreatedFrom == 0 || c.CreatedAt.Unix() >= f.CreatedFrom) && (f.CreatedTo == 0 || c.CreatedAt.Unix() < f.CreatedTo)
}
