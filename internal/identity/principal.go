package identity

import (
	"slices"
	"sort"
	"time"
)

type RequestPrincipal struct {
	actor   string
	kind    Kind
	expires time.Time
	facts   []Fact
	profile string
	catalog *Catalog
}

func (p *RequestPrincipal) ActorID() string      { return p.actor }
func (p *RequestPrincipal) Kind() Kind           { return p.kind }
func (p *RequestPrincipal) ExpiresAt() time.Time { return p.expires }
func (p *RequestPrincipal) Facts() []Fact        { return slices.Clone(p.facts) }
func (p *RequestPrincipal) Groups(org string) []string {
	set := map[string]bool{}
	groups := []string{}
	for _, fact := range p.facts {
		for _, group := range p.catalog.mappings[mappingKey{p.profile, org, p.kind, fact}] {
			if !set[group] {
				set[group] = true
				groups = append(groups, group)
			}
		}
	}
	sort.Strings(groups)
	return groups
}
