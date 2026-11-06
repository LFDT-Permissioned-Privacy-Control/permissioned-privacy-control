package identity

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
)

func digest(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", invalid("encoding", "source")
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func actorID(tuple ...string) string {
	h := sha256.New()
	var size [4]byte
	for _, part := range tuple {
		binary.BigEndian.PutUint32(size[:], uint32(len(part)))
		h.Write(size[:])
		h.Write([]byte(part))
	}
	return "ops:p1:" + base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
