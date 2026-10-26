package gate

import "refmod/store"

// Sink receives counts.
type Sink interface{ Count(string) }

// Check decides access.
func Check(who string) bool { return who != "" && len((&store.DB{}).Rows()) >= 0 }

// Use installs a sink.
func Use(s Sink) { s.Count("use") }

// Describer is satisfied by anything that can describe itself.
type Describer interface{ Describe() string }
