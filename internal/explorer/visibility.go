package explorer

import "privacy-proxy/internal/explorerdata"

type VisibilityLevel = explorerdata.VisibilityLevel
type VisibilityReason = explorerdata.VisibilityReason
type AddressVisibility = explorerdata.AddressVisibility

const (
	VisibilityFull            = explorerdata.VisibilityFull
	VisibilityPseudonymous    = explorerdata.VisibilityPseudonymous
	VisibilityRedacted        = explorerdata.VisibilityRedacted
	VisibilityHidden          = explorerdata.VisibilityHidden
	ReasonOwnAddress          = explorerdata.ReasonOwnAddress
	ReasonPublicAddress       = explorerdata.ReasonPublicAddress
	ReasonNoAccess            = explorerdata.ReasonNoAccess
	ReasonRBACGroupMember     = explorerdata.ReasonRBACGroupMember
	ReasonParticipantOverride = explorerdata.ReasonParticipantOverride
	ReasonVisibleToGrant      = explorerdata.ReasonVisibleToGrant
)

func GeneratePseudonym(address string, key []byte) string {
	return explorerdata.GeneratePseudonym(address, key)
}
func StrictAllowlist(detailed map[string]AddressVisibility) []string {
	return explorerdata.StrictAllowlist(detailed)
}
func GenerateAddressID(address, grantID string) string {
	return explorerdata.GenerateAddressID(address, grantID)
}
func GenerateAddressIDKeyed(address, grantID string, key []byte) string {
	return explorerdata.GenerateAddressIDKeyed(address, grantID, key)
}
