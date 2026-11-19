package rpcengine

import "privacy-proxy/internal/policybundle"

// UsesSnapshot binds transport-only identity classification to the actual
// immutable catalog object used by the operation. A matching digest alone is
// insufficient. This supplies no principal, policy view or permission.
func (e *Engine) UsesSnapshot(s *policybundle.CatalogSnapshot) bool {
	return e != nil && s != nil && e.snapshot == s
}
func (e *MetadataEngine) UsesSnapshot(s *policybundle.CatalogSnapshot) bool {
	return e != nil && s != nil && e.snapshot == s
}
func (e *StateEngine) UsesSnapshot(s *policybundle.CatalogSnapshot) bool {
	return e != nil && s != nil && e.snapshot == s
}
func (e *HistoryEngine) UsesSnapshot(s *policybundle.CatalogSnapshot) bool {
	return e != nil && s != nil && e.snapshot == s
}
func (e *ExplorerEngine) UsesSnapshot(s *policybundle.CatalogSnapshot) bool {
	return e != nil && s != nil && e.config.Snapshot == s
}
