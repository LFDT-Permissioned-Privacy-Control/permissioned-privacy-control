package app

import (
	"refmod/gate"
	"refmod/legacy"
)

// Router routes requests.
type Router struct{ Legacy bool }

// Serve dispatches to the legacy path in legacy mode.
func (r Router) Serve() {
	if r.Legacy {
		legacy.Old()
	}
	go func() { legacy.Other() }()
}

// Wide is a dispatch point that names more than its entry lists.
func (r Router) Wide() {
	if r.Legacy {
		legacy.Old()
		legacy.Other()
	}
}

// Plain calls legacy code without being a dispatch point.
func Plain() { legacy.Old() }

// Holder keeps an optional legacy component; declaring the field runs nothing.
type Holder struct{ L *legacy.Thing }

var hook = legacy.Old

var d gate.Sink = &legacy.Thing{}

// Wire installs a legacy component without being a dispatch point.
func Wire() (h Holder) {
	h.L = legacy.New()
	return h
}

// Listed installs a legacy component from a dispatch point that lists it.
func Listed() (h Holder) {
	h.L = legacy.New()
	return h
}

// Leak returns a legacy value held in a core field.
func Leak(h Holder) gate.Sink { return h.L }

// Local calls a legacy value through a core interface held in a local.
func Local(h Holder) {
	var s gate.Sink = h.L
	s.Count("x")
}

// Embedder gains a legacy type's methods by embedding it.
type Embedder struct{ *legacy.Thing }

// More hands legacy values over in ways a plain assignment does not show.
func More(h Holder, ch chan gate.Sink) gate.Sink {
	legacy.Hidden()
	_ = legacy.Pick(1)
	count := (*legacy.Thing).Count
	_ = count
	var list []gate.Sink
	list = append(list, h.L)
	ch <- h.L
	sinks := []gate.Sink{h.L}
	byName := map[string]gate.Sink{"a": h.L}
	_, _ = sinks, byName
	return list[0]
}
