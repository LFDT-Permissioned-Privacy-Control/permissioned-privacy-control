package explorerv2data

// ScopedCount never places an incomplete subtotal in a legacy total field.
// An unavailable observation has neither Value nor LowerBound.
type ScopedCount struct {
	Status      string      `json:"status"`
	Value       *Quantity   `json:"value,omitempty"`
	LowerBound  *Quantity   `json:"lowerBound,omitempty"`
	Population  string      `json:"population"`
	Consistency string      `json:"consistency"`
	ObservedAt  *string     `json:"observedAt,omitempty"`
	Range       *CountRange `json:"range,omitempty"`
	Coverage    string      `json:"coverage"`
}
type CountRange struct {
	FromBlock    Quantity `json:"fromBlock"`
	ThroughBlock Quantity `json:"throughBlock"`
	HeadHash     Hash     `json:"headHash"`
}
type Counts map[string]ScopedCount
