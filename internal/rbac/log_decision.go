package rbac

import "privacy-proxy/internal/readprivacy"

type LogEventRuleMode = readprivacy.LogEventRuleMode
type LogEmitterFacts = readprivacy.LogEmitterFacts
type LogPayloadPolicy = readprivacy.LogPayloadPolicy
type LogDecision = readprivacy.LogDecision

const (
	LogEventRulesDeny      = readprivacy.LogEventRulesDeny
	LogEventRulesWildcard  = readprivacy.LogEventRulesWildcard
	LogEventRulesAllowlist = readprivacy.LogEventRulesAllowlist
	LogPayloadMasked       = readprivacy.LogPayloadMasked
	LogPayloadFull         = readprivacy.LogPayloadFull
)

func DecideLogEmitter(profile ReadProfile, facts LogEmitterFacts) LogDecision {
	return readprivacy.DecideLogEmitter(profile, facts)
}

func DecideLogEmitterAccess(profile ReadProfile, facts LogEmitterFacts) bool {
	return readprivacy.DecideLogEmitterAccess(profile, facts)
}
