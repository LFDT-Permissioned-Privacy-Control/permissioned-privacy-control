package rbac

import "privacy-proxy/internal/readprivacyabi"

type EventLogInputs = readprivacyabi.EventLogInputs

func MatchesEventParamRules(log EventLogInputs, rules []ParamRule, addrs map[string]bool, abiJSON string) bool {
	return readprivacyabi.MatchesEventParamRules(log, rules, addrs, abiJSON)
}
