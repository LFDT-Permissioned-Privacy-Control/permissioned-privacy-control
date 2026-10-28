package legacy

import "refmod/gate"

// Install runs only when a dispatch point calls it; a hand-over inside legacy
// code is not checked.
func Install() { gate.Use(&Thing{}) }
