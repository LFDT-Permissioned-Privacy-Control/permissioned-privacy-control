package identity

import (
	"encoding/hex"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)
var fieldPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var networkPattern = regexp.MustCompile(`^[a-z0-9]+:[a-z0-9]+$`)

const base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func name(s string, max int) bool { return len(s) > 0 && len(s) <= max && namePattern.MatchString(s) }
func text(s string, max int) bool {
	return len(s) > 0 && len(s) <= max && utf8.ValidString(s) && strings.TrimSpace(s) == s && !strings.ContainsAny(s, "\x00\r\n\t")
}
func ascii(s string, max int) bool {
	if !text(s, max) {
		return false
	}
	for _, c := range s {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}
func uuid(s string) bool {
	if len(s) != 36 || s != strings.ToLower(s) || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	raw := strings.ReplaceAll(s, "-", "")
	if len(raw) != 32 {
		return false
	}
	b, err := hex.DecodeString(raw)
	if err != nil {
		return false
	}
	for _, v := range b {
		if v != 0 {
			return true
		}
	}
	return false
}
func sha(s string) bool {
	if len(s) != 71 || !strings.HasPrefix(s, "sha256:") || s != strings.ToLower(s) {
		return false
	}
	_, err := hex.DecodeString(s[7:])
	return err == nil
}
func https(s string, max int, query bool) bool {
	if !ascii(s, max) {
		return false
	}
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Fragment == "" && (query || u.RawQuery == "")
}
func did(s string, max int) (string, bool) {
	if !ascii(s, max) {
		return "", false
	}
	parts := strings.Split(s, ":")
	if len(parts) != 5 || parts[0] != "did" || (parts[1] != "iden3" && parts[1] != "polygonid") || !networkPattern.MatchString(parts[2]+":"+parts[3]) || parts[4] == "" {
		return "", false
	}
	for _, c := range parts[4] {
		if !strings.ContainsRune(base58, c) {
			return "", false
		}
	}
	return parts[2] + ":" + parts[3], true
}

func expectedKind(p Profile) Kind {
	if p.Kind == AzureService {
		return Service
	}
	return Human
}

func validateProfile(p *Profile, l Limits) error {
	if !name(p.ID, min(l.MaxProfileIDBytes, l.MaxSourceIDBytes)) {
		return invalid("profile-id", "profiles.id")
	}
	if p.Kind == AzureHuman || p.Kind == AzureService {
		if !uuid(p.TenantID) || !uuid(p.APIAudience) || p.Issuer != "https://login.microsoftonline.com/"+p.TenantID+"/v2.0" || len(p.Issuer) > l.MaxURLBytes || (p.FactSource != "appRoles" && p.FactSource != "groupIds") {
			return invalid("azure-profile", "profiles")
		}
		if p.Kind == AzureHuman {
			if !uuid(p.ClientID) || !ascii(p.DelegatedScope, 512) {
				return invalid("azure-profile", "profiles")
			}
		} else {
			if len(p.AllowedClientIDs) == 0 {
				return invalid("azure-profile", "profiles.allowedClientIds")
			}
			for _, id := range p.AllowedClientIDs {
				if !uuid(id) {
					return invalid("azure-profile", "profiles.allowedClientIds")
				}
			}
			if !uniqueSort(p.AllowedClientIDs) {
				return invalid("duplicate", "profiles.allowedClientIds")
			}
		}
		return nil
	}
	if !ascii(p.VerifierID, 1024) || !strings.Contains(p.VerifierID, ":") || !networkPattern.MatchString(p.Network) || len(p.IdentityStateContract) != 42 || !strings.HasPrefix(p.IdentityStateContract, "0x") || p.IdentityStateContract != strings.ToLower(p.IdentityStateContract) {
		return invalid("privado-profile", "profiles")
	}
	address, err := hex.DecodeString(p.IdentityStateContract[2:])
	nonzero := false
	for _, v := range address {
		nonzero = nonzero || v != 0
	}
	if err != nil || !nonzero {
		return invalid("privado-profile", "profiles.identityStateContract")
	}
	if p.Kind == PrivadoIdentity {
		return nil
	}
	if p.Kind != PrivadoRole || len(p.AllowedCredentialIssuers) == 0 || !sha(p.ContextDigest) || !https(p.Context, l.MaxURLBytes, true) || !name(p.Type, 128) || p.CircuitID != "credentialAtomicQuerySigV2" || len(p.Predicates) == 0 {
		return invalid("privado-profile", "profiles")
	}
	for _, issuer := range p.AllowedCredentialIssuers {
		if _, ok := did(issuer, l.MaxSourceSubjectBytes); !ok {
			return invalid("privado-profile", "profiles.allowedCredentialIssuers")
		}
	}
	if !uniqueSort(p.AllowedCredentialIssuers) {
		return invalid("duplicate", "profiles.allowedCredentialIssuers")
	}
	seen := map[string]bool{}
	for _, predicate := range p.Predicates {
		if !name(predicate.ID, 128) || !fieldPattern.MatchString(predicate.Field) || len(predicate.Field) > 128 || predicate.Operator != "eq" || seen[predicate.ID] || len(predicate.Value) > l.MaxPredicateDecimalBytes || !decimal(predicate.Value) {
			return invalid("predicate", "profiles.predicates")
		}
		if _, err := strconv.ParseUint(predicate.Value, 10, 32); err != nil {
			return invalid("predicate", "profiles.predicates.value")
		}
		seen[predicate.ID] = true
	}
	sortPredicates(p.Predicates)
	return nil
}

func decimal(s string) bool {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func validFact(p Profile, f Fact, l Limits) bool {
	if !text(f.Value, l.MaxFactValueBytes) {
		return false
	}
	switch p.Kind {
	case AzureHuman, AzureService:
		if p.FactSource == "appRoles" {
			return f.Kind == "azure.role"
		}
		return f.Kind == "azure.group" && uuid(f.Value)
	case PrivadoRole:
		if f.Kind != "privado.predicate" {
			return false
		}
		for _, predicate := range p.Predicates {
			if predicate.ID == f.Value {
				return true
			}
		}
	}
	return false
}
