package ssosql

var stateUpdates = map[string][]string{
	"app":       {"active_rows", "ready_rows", "active_bytes", "all_rows"},
	"retention": {"active_rows", "ready_rows", "active_bytes", "all_rows", "last_gc_us"},
}
var rowUpdates = map[string][]string{
	"app":       {"phase", "code_hash", "code_expires_us", "grant_key_id", "grant_ciphertext", "actor_id", "profile_id", "profile_digest", "family_id", "family_generation", "family_handle_hash", "access_digest", "access_expires_us", "family_expires_us", "ready_us", "code_response_digest", "code_response_bytes", "consumed_us", "token_response_digest", "token_response_bytes", "retain_until_us", "context_ciphertext"},
	"retention": {"phase", "context_ciphertext", "grant_ciphertext"},
}
