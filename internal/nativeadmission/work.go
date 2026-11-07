package nativeadmission

import (
	"math"
	"math/bits"

	"privacy-proxy/internal/policycore"
)

const MaxAdmissionWork uint64 = 2_000_000

type ruleWork struct{ rules, items, linked uint64 }

func sourceWork(p *policycore.Policy) map[string]ruleWork {
	out := make(map[string]ruleWork, len(p.Bindings))
	for _, binding := range p.Bindings {
		var w ruleWork
		for _, r := range binding.Allow {
			w.rules++
			w.items += 1 + uint64(len(r.Args)) + uint64(len(r.Except))
			for _, exception := range r.Except {
				w.items += uint64(len(exception.Groups))
			}
			for _, arg := range r.Args {
				if arg.AddressEquals != nil && arg.AddressEquals.Source == policycore.AddressSourcePrincipalLinked {
					w.linked++
				}
			}
		}
		out[binding.Group] = w
	}
	return out
}
func add(a, b uint64) (uint64, bool) {
	if b > math.MaxUint64-a {
		return 0, false
	}
	return a + b, true
}
func multiply(a, b uint64) (uint64, bool) {
	if a != 0 && b > math.MaxUint64/a {
		return 0, false
	}
	return a * b, true
}

func admissionWork(frames, groups uint64, w ruleWork, links uint64) (uint64, bool) {
	// Bound the existing evaluator's deterministic per-frame sorting, including
	// its work for selected groups with no native rules.
	log := uint64(bits.Len64(max(uint64(2), w.rules) - 1))
	sortWork, ok := multiply(w.rules, log)
	if !ok {
		return 0, false
	}
	weight, ok := add(w.items, sortWork)
	if !ok {
		return 0, false
	}
	linkedWork, ok := multiply(w.linked, links)
	if !ok {
		return 0, false
	}
	weight, ok = add(weight, linkedWork)
	if !ok {
		return 0, false
	}
	weight, ok = add(weight, groups)
	if !ok {
		return 0, false
	}
	work, ok := multiply(frames, weight)
	return work, ok && work <= MaxAdmissionWork
}
