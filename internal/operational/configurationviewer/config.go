// Package configurationviewer exposes a bounded read-only public source view.
// It neither selects Core policy nor resolves secrets or writes configuration.
package configurationviewer

import (
	"errors"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/runtimepolicy"
)

const Path = "/api/v2/configuration/sources"
const MaxRoots = 16
const MaxFiles = 2048
const MaxCandidates = 128
const MaxFileBytes = 1 << 20
const MaxSourceBytes = 64 << 20
const MaxWireBytes = 90 << 20
const maxCacheBytes = 192 << 20
const maxBufferBytes = 384 << 20

// Reserve old/new encoding buffers and bounded file scratch before a capture.
const captureReservation = 192 << 20

var ErrInvalid = errors.New("invalid configuration viewer settings")
var errUnavailable = errors.New("configuration source unavailable")
var errBusy = errors.New("configuration viewer busy")
var sourceName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
var fileName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*\.json$`)
var orgID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type Audience struct {
	OwnerOrganizationIDs []string `json:"ownerOrganizationIds,omitempty" optional:"true"`
	OperatorActorIDs     []string `json:"operatorActorIds,omitempty" optional:"true"`
}
type Settings struct {
	Directory       string              `json:"directory"`
	Layout          string              `json:"layout"`
	Audience        Audience            `json:"audience"`
	FolderAudiences map[string]Audience `json:"folderAudiences,omitempty" optional:"true"`
}

// Validate checks trusted deployment syntax without reading external files.
// Missing external content must not turn into a Core readiness dependency.
func (s *Settings) Validate() error {
	if s == nil {
		return nil
	}
	if !filepath.IsAbs(s.Directory) || filepath.Clean(s.Directory) != s.Directory || strings.ContainsAny(s.Directory, "\x00\r\n") || s.Directory == string(filepath.Separator) || (s.Layout != "single" && s.Layout != "folders") || len(s.FolderAudiences) > MaxCandidates {
		return ErrInvalid
	}
	if s.Layout == "single" && len(s.FolderAudiences) != 0 {
		return ErrInvalid
	}
	if validAudience(s.Audience) != nil {
		return ErrInvalid
	}
	for name, a := range s.FolderAudiences {
		if !sourceName.MatchString(name) || validAudience(a) != nil {
			return ErrInvalid
		}
	}
	return nil
}
func validAudience(a Audience) error {
	if len(a.OwnerOrganizationIDs) > 256 || len(a.OperatorActorIDs) > 256 {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, id := range a.OwnerOrganizationIDs {
		if !orgID.MatchString(id) || id == "00000000-0000-0000-0000-000000000000" || seen[id] {
			return ErrInvalid
		}
		seen[id] = true
	}
	seen = map[string]bool{}
	for _, id := range a.OperatorActorIDs {
		if !identity.ValidActorID(id) || seen[id] {
			return ErrInvalid
		}
		seen[id] = true
	}
	return nil
}
func isAdmin(v *runtimepolicy.View, id string) bool {
	o, ok := v.Org(id)
	return ok && (o.IsOrgAdmin() || o.IsOrgReadonlyAdmin())
}
func anyAdmin(v *runtimepolicy.View) bool {
	if v.Kind() != identity.Human || v.RequireLive() != nil {
		return false
	}
	for _, id := range v.OrgIDs() {
		if isAdmin(v, id) {
			return true
		}
	}
	return false
}
func permits(v *runtimepolicy.View, a Audience) bool {
	if !anyAdmin(v) {
		return false
	}
	if slices.Contains(a.OperatorActorIDs, v.ActorID()) {
		return true
	}
	if len(a.OwnerOrganizationIDs) == 0 {
		return false
	}
	for _, id := range a.OwnerOrganizationIDs {
		if !isAdmin(v, id) {
			return false
		}
	}
	return true
}
func (s *Settings) audience(id string) Audience {
	if a, ok := s.FolderAudiences[id]; ok {
		return a
	}
	return s.Audience
}
