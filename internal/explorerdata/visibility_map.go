package explorerdata

type VisibilityMap map[string]VisibilityLevel

func VisibilityMapFromDetailed(detailed map[string]AddressVisibility) VisibilityMap {
	m := make(VisibilityMap, len(detailed))
	for addr, v := range detailed {
		m[addr] = v.Level
	}
	return m
}
