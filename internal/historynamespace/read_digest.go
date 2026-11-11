package historynamespace

import "encoding/json"

// Cheap bounded field/count guards precede this encoder. The exact bytes that
// are hashed are capped before hashing and before any exported detached copy.
// These canonical-payload bounds are distinct from peak heap/RSS or every
// internal encoder/getter lifetime.
func boundedReadDigest(domain string, value any, maxBytes int, budget *workBudget) (Digest, int, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return Digest{}, 0, ErrInvalid
	}
	if len(raw) > maxBytes {
		return Digest{}, 0, ErrTooBroad
	}
	if budget != nil {
		if err := budget.use(1 + (len(raw)+31)/32); err != nil {
			return Digest{}, 0, err
		}
	}
	return semanticDigestBytes(domain, raw), len(raw), nil
}
