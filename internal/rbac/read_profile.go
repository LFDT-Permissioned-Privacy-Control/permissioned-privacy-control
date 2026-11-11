package rbac

import "privacy-proxy/internal/readprivacy"

type ReadProfile = readprivacy.ReadProfile

const (
	ReadProfileUnset    = readprivacy.ReadProfileUnset
	ReadProfileStandard = readprivacy.ReadProfileStandard
	ReadProfileStrict   = readprivacy.ReadProfileStrict
)

func ParseReadProfile(s string) (ReadProfile, error) { return readprivacy.ParseReadProfile(s) }
