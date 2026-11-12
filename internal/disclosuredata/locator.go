package disclosuredata

import "bytes"

// ResolveAddressLocator resolves an existing case/organization/recipient-bound
// alias within a bounded, sorted actual target selection. A locator conveys no
// permission or historical attribution and never widens an empty selection.
func ResolveAddressLocator(c RenderContext, id string, candidates [][20]byte) ([20]byte, error) {
	var out [20]byte
	if len(candidates) > 4096 {
		return out, ErrTooBroad
	}
	if !validLocator(id) {
		return out, ErrInvalid
	}
	if _, err := RenderContextDigest(c); err != nil {
		return out, err
	}
	keys, err := CopyKeys(c.Keys)
	if err != nil {
		return out, err
	}
	c.Keys = keys
	found := false
	for i, address := range candidates {
		if i > 0 && bytes.Compare(candidates[i-1][:], address[:]) >= 0 {
			return out, ErrInvalid
		}
		if locatorMatches(c, id, address) {
			if found {
				return out, ErrConflict
			}
			found = true
			out = address
		}
	}
	if !found {
		return out, ErrNotFound
	}
	return out, nil
}
