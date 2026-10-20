package disclosure

import "time"

// DisclosureFilter provides filtering options for listing disclosures.
type DisclosureFilter struct {
	// Status filters by request status (pending, approved, rejected, revoked, expired)
	Status *RequestStatus `json:"status,omitempty"`

	// TargetUserID filters by the user whose data is being disclosed
	TargetUserID string `json:"target_user_id,omitempty"`

	// RequesterDID filters by the DID of the requester
	RequesterDID string `json:"requester_did,omitempty"`

	// DisclosureLevel filters by the disclosure level (full, pseudonymous, redacted)
	DisclosureLevel *DisclosureLevel `json:"disclosure_level,omitempty"`

	// DateFrom filters requests created on or after this date
	DateFrom *time.Time `json:"date_from,omitempty"`

	// DateTo filters requests created on or before this date
	DateTo *time.Time `json:"date_to,omitempty"`

	// OrgID filters by organization ID
	OrgID string `json:"org_id,omitempty"`

	// Limit is the maximum number of results to return
	Limit int `json:"limit,omitempty"`

	// Offset is the number of results to skip
	Offset int `json:"offset,omitempty"`
}

// DisclosureListResult contains the results of a disclosure list query with metadata.
type DisclosureListResult struct {
	// Requests is the list of matching disclosure requests
	Requests []*RequestWithDetails `json:"requests"`

	// Total is the total count of matching records (for pagination)
	Total int64 `json:"total"`

	// Limit is the limit that was applied
	Limit int `json:"limit"`

	// Offset is the offset that was applied
	Offset int `json:"offset"`
}

// GrantListResult contains the results of a grant list query with metadata.
type GrantListResult struct {
	// Grants is the list of matching grants with their requests
	Grants []*GrantWithRequest `json:"grants"`

	// Total is the total count of matching records (for pagination)
	Total int64 `json:"total"`

	// Limit is the limit that was applied
	Limit int `json:"limit"`

	// Offset is the offset that was applied
	Offset int `json:"offset"`
}

// NewDefaultFilter returns a filter with sensible defaults.
func NewDefaultFilter() *DisclosureFilter {
	return &DisclosureFilter{
		Limit:  100,
		Offset: 0,
	}
}
