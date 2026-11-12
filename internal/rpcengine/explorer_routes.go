package rpcengine

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"privacy-proxy/internal/activitymethoddata"
	"privacy-proxy/internal/explorerquery"
)

type explorerRequest struct {
	operation                                           activitymethoddata.Operation
	query                                               explorerquery.Query
	collection                                          bool
	limit                                               int
	cursor, category, tokenType, interval, organization string
	digest                                              [32]byte
}

var errExplorerRequest = errors.New("invalid Explorer request")

func explorerNumber(s string) (uint64, error) {
	n, e := strconv.ParseUint(s, 10, 63)
	if e != nil || strconv.FormatUint(n, 10) != s {
		return 0, errExplorerRequest
	}
	return n, nil
}
func parseExplorerRequest(path, rawQuery string) (explorerRequest, error) {
	r := explorerRequest{limit: 100}
	const prefix = "/api/v2/explorer"
	if !strings.HasPrefix(path, prefix+"/") || strings.Contains(path, "//") {
		return r, errExplorerRequest
	}
	relative := strings.TrimPrefix(path, prefix)
	segments := strings.Split(strings.TrimPrefix(relative, "/"), "/")
	params := map[string]string{}
	found := false
	for _, op := range activitymethoddata.Operations() {
		parts := strings.Split(strings.TrimPrefix(op.Route, "/"), "/")
		if len(parts) != len(segments) {
			continue
		}
		candidate := map[string]string{}
		matches := true
		for i, part := range parts {
			if strings.HasPrefix(part, ":") {
				candidate[part[1:]] = segments[i]
			} else if part != segments[i] {
				matches = false
				break
			}
		}
		if matches {
			r.operation = op
			params = candidate
			found = true
			break
		}
	}
	if !found {
		return r, errExplorerRequest
	}
	for name, value := range params {
		switch name {
		case "address":
			if !explorerquery.ValidAddress(value) {
				return r, errExplorerRequest
			}
			r.query.Address = value
		case "hash":
			if !explorerquery.ValidHash(value) {
				return r, errExplorerRequest
			}
			r.query.Hash = value
		case "number":
			n, e := explorerNumber(value)
			if e != nil {
				return r, e
			}
			r.query.Block = &n
		}
	}
	label := r.operation.Label
	switch label {
	case "explorer.blocks", "explorer.block_hash", "explorer.block_number":
		r.query.Family = explorerquery.Blocks
	case "explorer.transaction_transfers", "explorer.address_transfers", "explorer.token_transfers", "explorer.transfers":
		r.query.Family = explorerquery.Transfers
	case "explorer.transaction_logs", "explorer.address_logs", "explorer.logs":
		r.query.Family = explorerquery.Logs
	case "explorer.transaction_internal", "explorer.address_internal", "explorer.block_internal":
		r.query.Family = explorerquery.Internals
	case "explorer.tokens", "explorer.token":
		r.query.Family = explorerquery.Tokens
	case "explorer.address_balances":
		r.query.Family = explorerquery.Balances
	case "explorer.token_holders":
		r.query.Family = explorerquery.Holders
		r.query.Token = r.query.Address
		r.query.Address = ""
	case "explorer.address_contract":
		r.query.Family = explorerquery.Contracts
	case "explorer.address_stats", "explorer.accounts":
		r.query.Family = explorerquery.Addresses
	case "explorer.sync_status", "explorer.catchup":
		r.query.Family = explorerquery.Sync
	case "explorer.search_suggestions":
		r.query.Family = explorerquery.Search
	case "explorer.indexer_progress":
		r.query.Family = explorerquery.Progress
	default:
		r.query.Family = explorerquery.Transactions
	}
	if label == "explorer.token_transfers" {
		r.query.Token = r.query.Address
		r.query.Address = ""
	}
	switch label {
	case "explorer.chain_id", "explorer.head", "explorer.stats", "explorer.block_hash", "explorer.block_number", "explorer.transaction", "explorer.address_stats", "explorer.address_balance", "explorer.address_code", "explorer.address_contract", "explorer.address_is_contract", "explorer.token", "explorer.sync_status", "explorer.indexer_progress", "explorer.catchup":
	default:
		r.collection = true
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil || len(rawQuery) > 16<<10 {
		return r, errExplorerRequest
	}
	allowed := map[string]bool{}
	if r.collection {
		allowed["limit"] = true
		allowed["cursor"] = true
	}
	if r.query.Family == explorerquery.Transactions {
		allowed["category"] = true
	}
	if r.query.Family == explorerquery.Logs {
		for _, name := range []string{"address", "topic0", "from", "to"} {
			allowed[name] = true
		}
	}
	if r.query.Family == explorerquery.Tokens {
		allowed["type"] = true
	}
	if label == "explorer.search_suggestions" {
		allowed["q"] = true
		r.limit = 10
	}
	if label == "explorer.tx_history" {
		allowed["interval"] = true
		r.limit = 30
		r.interval = "day"
	}
	for name, list := range values {
		if !allowed[name] || len(list) != 1 || list[0] == "" {
			return r, errExplorerRequest
		}
		value := list[0]
		switch name {
		case "limit":
			n, e := explorerNumber(value)
			max := uint64(1000)
			if label == "explorer.search_suggestions" {
				max = 20
			}
			if label == "explorer.tx_history" {
				max = 365
			}
			if e != nil || n < 1 || n > max {
				return r, errExplorerRequest
			}
			r.limit = int(n)
		case "cursor":
			if len(value) > 8192 {
				return r, errExplorerRequest
			}
			r.cursor = value
		case "category":
			switch value {
			case "coin_transfer", "contract_creation", "contract_call", "token_transfer":
				r.category = value
			default:
				return r, errExplorerRequest
			}
		case "address":
			if r.query.Address != "" || !explorerquery.ValidAddress(value) {
				return r, errExplorerRequest
			}
			r.query.Address = value
		case "topic0":
			if !explorerquery.ValidHash(value) {
				return r, errExplorerRequest
			}
			r.query.Topic0 = value
		case "from", "to":
			n, e := explorerNumber(value)
			if e != nil {
				return r, e
			}
			if name == "from" {
				r.query.From = &n
			} else {
				r.query.Through = &n
			}
		case "type":
			switch value {
			case "ERC20", "ERC721", "ERC1155":
				r.tokenType = value
			default:
				return r, errExplorerRequest
			}
		case "q":
			value = strings.TrimSpace(value)
			if len(value) < 1 || len(value) > 128 || !utf8.ValidString(value) || strings.ContainsRune(value, 0) {
				return r, errExplorerRequest
			}
			r.query.Search = value
		case "interval":
			switch value {
			case "hour", "day", "week":
				r.interval = value
			default:
				return r, errExplorerRequest
			}
		}
	}
	if label == "explorer.search_suggestions" && r.query.Search == "" {
		return r, errExplorerRequest
	}
	r.query.RawLimit = min(256, max(4, r.limit*4))
	digest, _ := json.Marshal(struct {
		Route                         string
		Query                         explorerquery.Query
		Limit                         int
		Category, TokenType, Interval string
	}{r.operation.Route, r.query, r.limit, r.category, r.tokenType, r.interval})
	r.digest = sha256.Sum256(digest)
	return r, nil
}
