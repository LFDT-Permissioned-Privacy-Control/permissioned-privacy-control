package admission

// EventFilters restrict an organization audit query; they confer no authority.
// Empty values select every event within the caller's verified organization.
type EventFilters struct {
	Decision, TransferType, ActorID string
}

func (f EventFilters) Valid() bool {
	return (f.Decision == "" || f.Decision == "allowed" || f.Decision == "denied" || f.Decision == "monitored") &&
		(f.TransferType == "" || f.TransferType == "eth" || f.TransferType == "erc20") &&
		(f.ActorID == "" || validActor(f.ActorID))
}

func (f EventFilters) Kind() string {
	if f.TransferType == "eth" {
		return "root_native"
	}
	if f.TransferType == "erc20" {
		return "root_erc20"
	}
	return ""
}

func (f EventFilters) Matches(e Event) bool {
	decision := f.Decision == "" || f.Decision == e.Decision || f.Decision == "monitored" && e.Monitored
	return decision && (f.Kind() == "" || f.Kind() == e.Kind) && (f.ActorID == "" || f.ActorID == e.Scope.Actor)
}
