package app

import _ "refmod/gate"

// Describe changes what a core type does, from a legacy file.
func (r Router) Describe() string { return "legacy" }

var _ = func() int { return 1 }()

// legacyOnly is a legacy method no interface names; only a direct call runs it.
func (r Router) legacyOnly() {}
