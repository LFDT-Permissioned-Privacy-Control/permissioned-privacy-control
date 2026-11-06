// Package rpcmethoddata owns built-in RPC catalog data. Runtime snapshots are
// detached from the legacy RBAC package's mutable registration maps.
package rpcmethoddata

import "strings"

var readMethods = map[string]bool{
	// Chain/Network info
	"eth_chainId":        true,
	"eth_blockNumber":    true,
	"net_version":        true,
	"net_listening":      true,
	"net_peerCount":      true,
	"web3_clientVersion": true,
	"web3_sha3":          true,
	"eth_syncing":        true,
	"eth_accounts":       true,

	// Account/Balance queries
	"eth_getBalance":          true,
	"eth_getCode":             true,
	"eth_getStorageAt":        true,
	"eth_getTransactionCount": true,

	// Block queries
	"eth_getBlockByHash":                   true,
	"eth_getBlockByNumber":                 true,
	"eth_getBlockTransactionCountByHash":   true,
	"eth_getBlockTransactionCountByNumber": true,

	// Transaction queries
	"eth_getTransactionByHash":                true,
	"eth_getTransactionReceipt":               true,
	"eth_getTransactionByBlockHashAndIndex":   true,
	"eth_getTransactionByBlockNumberAndIndex": true,

	// Contract calls (read-only)
	"eth_call":        true,
	"eth_estimateGas": true,

	// Gas price queries
	"eth_gasPrice":             true,
	"eth_maxPriorityFeePerGas": true,
	"eth_feeHistory":           true,

	// Logs
	"eth_getLogs": true,

	// Filter methods (used for event polling)
	"eth_newFilter":                   true,
	"eth_newBlockFilter":              true,
	"eth_newPendingTransactionFilter": true,
	"eth_getFilterChanges":            true,
	"eth_getFilterLogs":               true,
	"eth_uninstallFilter":             true,
}

var writeMethods = map[string]bool{
	"eth_sendTransaction":    true,
	"eth_sendRawTransaction": true,
	"eth_sign":               true,
	"eth_signTransaction":    true,
	"personal_sign":          true,
	"eth_signTypedData":      true,
	"eth_signTypedData_v4":   true,
}

var traceMethods = map[string]bool{
	"debug_traceTransaction": true,
	"debug_traceCall":        true,
}

var exactOnlyMethods = []string{
	"eth_getProof",
	"eth_createAccessList",
	"eth_getBlockReceipts",
}

var blockedMethods = map[string]bool{
	// Debug namespace - information disclosure, DoS risk
	"debug_accountrange":                true,
	"debug_backtraceat":                 true,
	"debug_blockprofile":                true,
	"debug_chaindbcompact":              true,
	"debug_chaindbproperty":             true,
	"debug_cpuprofile":                  true,
	"debug_dbancient":                   true,
	"debug_dbancients":                  true,
	"debug_dbget":                       true,
	"debug_dumpblock":                   true,
	"debug_freeosmemory":                true,
	"debug_freezeclient":                true,
	"debug_gcstats":                     true,
	"debug_getbadblocks":                true,
	"debug_getheaderrlp":                true,
	"debug_getmodifiedaccountsbyhash":   true,
	"debug_getmodifiedaccountsbynumber": true,
	"debug_gotrace":                     true,
	"debug_intermediateroots":           true,
	"debug_memstats":                    true,
	"debug_mutexprofile":                true,
	"debug_preimage":                    true,
	"debug_printblock":                  true,
	"debug_seedhash":                    true,
	"debug_setblockprofilerate":         true,
	"debug_setgcpercent":                true,
	"debug_sethead":                     true,
	"debug_setmutexprofilefraction":     true,
	"debug_stacks":                      true,
	"debug_standardtracebadblocktofile": true,
	"debug_standardtraceblocktofile":    true,
	"debug_startcpuprofile":             true,
	"debug_startgotrace":                true,
	"debug_stopcpuprofile":              true,
	"debug_stopgotrace":                 true,
	"debug_storagerangeat":              true,
	"debug_subscribe":                   true,
	"debug_tracebadblock":               true,
	"debug_traceblock":                  true,
	"debug_traceblockbyhash":            true,
	"debug_traceblockbynumber":          true,
	"debug_traceblockfromfile":          true,
	"debug_tracechain":                  true,
	"debug_unsubscribe":                 true,
	"debug_verbosity":                   true,
	"debug_vmodule":                     true,
	"debug_writeblockprofile":           true,
	"debug_writememprofile":             true,
	"debug_writemutexprofile":           true,

	// Admin namespace - node administration
	"admin_addpeer":           true,
	"admin_addtrustedpeer":    true,
	"admin_clearhistory":      true,
	"admin_datadir":           true,
	"admin_exportchain":       true,
	"admin_importchain":       true,
	"admin_nodeinfo":          true,
	"admin_peers":             true,
	"admin_removepeer":        true,
	"admin_removetrustedpeer": true,
	"admin_sleep":             true,
	"admin_sleepblocks":       true,
	"admin_starthttp":         true,
	"admin_startrpc":          true,
	"admin_startws":           true,
	"admin_stophttp":          true,
	"admin_stoprpc":           true,
	"admin_stopws":            true,

	// Personal namespace - key exposure risk
	"personal_deriveaccount":    true,
	"personal_ecrecover":        true,
	"personal_importrawkey":     true,
	"personal_initializewallet": true,
	"personal_listaccounts":     true,
	"personal_listwallets":      true,
	"personal_lockaccount":      true,
	"personal_newaccount":       true,
	"personal_openwallet":       true,
	"personal_sendtransaction":  true,
	"personal_sign":             true,
	"personal_signtransaction":  true,
	"personal_unlockaccount":    true,
	"personal_unpair":           true,

	// Miner namespace - MEV risk, node control
	"miner_gethashrate":         true,
	"miner_setetherbase":        true,
	"miner_setextra":            true,
	"miner_setgaslimit":         true,
	"miner_setgasprice":         true,
	"miner_setrecommitinterval": true,
	"miner_start":               true,
	"miner_stop":                true,

	// Txpool namespace - MEV risk, information disclosure
	"txpool_content":     true,
	"txpool_contentfrom": true,
	"txpool_inspect":     true,
	"txpool_status":      true,

	// NOTE: eth_getStorageAt is NOT globally blocked — it uses tiered access control
	// in CheckAccess: admin-claim users get all slots, non-admin users get only
	// well-known infrastructure slots (EIP-1967, EIP-2535). See storage_slots.go.

	// Bundled simulation methods are unsupported (RD-1305). Single-call
	// simulation options are checked separately by DetectStateOverride.
	"eth_simulatev1":  true,
	"eth_simulate":    true,
	"eth_multicallv1": true,
	"eth_callmany":    true,
	"eth_callbundle":  true,

	// Node signing methods are unavailable through the proxied RPC endpoint.
	"eth_sign":             true,
	"eth_signtransaction":  true,
	"eth_signtypeddata":    true,
	"eth_signtypeddata_v4": true,

	// NOTE: eth_sendRawTransaction is handled specially - it's allowed ONLY when
	// runtime tracing is enabled. The proxy decodes the RLP transaction, extracts
	// from/to/data/value, and runs runtime tracing to validate all call targets.
	// See jsonrpc_processor.go for the implementation.
	// When runtime tracing is disabled, this method is blocked by CheckAccess.

	// Clique namespace - consensus manipulation
	"clique_discard":           true,
	"clique_getsigners":        true,
	"clique_getsignersathash":  true,
	"clique_getsnapshot":       true,
	"clique_getsnapshotathash": true,
	"clique_proposals":         true,
	"clique_propose":           true,
	"clique_status":            true,

	// Les namespace - light client control
	"les_addbalance":         true,
	"les_clientinfo":         true,
	"les_latestcheckpoint":   true,
	"les_priorityclientinfo": true,
	"les_serverinfo":         true,
	"les_setclientparams":    true,
	"les_setdefaultparams":   true,

	// WebSocket subscriptions - not supported, use polling instead
	// eth_subscribe could bypass eth_getLogs filtering for real-time events
	"eth_subscribe":   true,
	"eth_unsubscribe": true,

	// Stateful filter API - same bypass risk as eth_subscribe.
	// These create server-side filter state that can't be per-user scoped.
	// Use eth_getLogs (which is properly filtered) instead.
	"eth_newfilter":                   true,
	"eth_newblockfilter":              true,
	"eth_newpendingtransactionfilter": true,
	"eth_getfilterlogs":               true,
	"eth_getfilterchanges":            true,
	"eth_uninstallfilter":             true,
}

var blockedPrefixes = []string{
	// Node-side approval preparation returns private execution facts. It is
	// called only by the internal preflight client, never by an RPC caller,
	// including a caller whose group grants all methods.
	"ops_",
	"debug_",
	"admin_",
	"personal_",
	"miner_",
	"txpool_",
	"clique_",
	"les_",
}

var blockExemptions = map[string]bool{
	"debug_tracetransaction": true,
	"debug_tracecall":        true,
}

// BlockedWith preserves the exact legacy matching order for detached registries.
func BlockedWith(method string, exact map[string]bool, prefixes []string, exemptions map[string]bool) bool {
	method = strings.ToLower(strings.TrimSpace(method))

	// Check exact match in map (O(1) lookup)
	if exact[method] {
		return true
	}

	// Check exemptions before prefix blocking
	if exemptions[method] {
		return false
	}

	// Check prefix matches for future-proofing
	for _, prefix := range prefixes {
		if strings.HasPrefix(method, prefix) {
			return true
		}
	}

	return false
}
