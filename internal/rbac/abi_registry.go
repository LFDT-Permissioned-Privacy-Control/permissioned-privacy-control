package rbac

import "strings"

// Built-in ABI registry for standard token types. These ABIs contain the events
// and core view/mutate functions needed for event signature extraction and
// parameter validation. When a contract has no custom ABI uploaded but is known
// to be a standard token type, these built-in ABIs serve as a fallback.

// builtInABIs maps canonical (uppercase) token type names to their ABI JSON.
// Lookups via GetBuiltInABI are case-insensitive — admins can write
// "ERC20" / "erc20" / "Erc20" and any of them resolve.
var builtInABIs = map[string]string{
	"ERC20":  erc20ABI,
	"ERC721": erc721ABI,
}

// GetBuiltInABI returns the built-in ABI JSON for a known token type.
// Recognized types: "ERC20", "ERC721" (case-insensitive). Returns "" for
// unknown types, in which case ResolveContractABI treats the contract as
// having no resolvable ABI and the RD-875 fail-closed gate fires.
func GetBuiltInABI(tokenType string) string {
	return builtInABIs[strings.ToUpper(strings.TrimSpace(tokenType))]
}

// ResolveContractABI returns the best available ABI for a contract: the
// custom-uploaded ABI first, then the built-in registry ABI keyed by the
// contract's metadata `token_type` field. Returns "" when neither is
// available — the caller should treat that as "no resolvable ABI" (RD-875:
// log/event redaction must fail closed in this case because non-indexed
// address parameters in event data cannot be decoded without an ABI, so
// private addresses would leak through verbatim).
//
// This is the single source of truth for "what ABI applies to this
// contract"; both the RPC-side filter (storeABIProvider) and the explorer
// redactor must agree on the answer to keep the access/visibility symmetry
// invariant (TestAccessVisibilitySymmetry).
func ResolveContractABI(c *Contract) string {
	if c == nil {
		return ""
	}
	if c.ABI != "" {
		return c.ABI
	}
	if c.Metadata != nil {
		if tokenType, ok := c.Metadata["token_type"].(string); ok {
			return GetBuiltInABI(tokenType)
		}
	}
	return ""
}

// erc20ABI is a standard ERC-20 ABI covering the Transfer and Approval events
// plus the core view and mutate functions needed for param-type validation.
const erc20ABI = `[
	{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "from", "type": "address"},
			{"indexed": true, "name": "to", "type": "address"},
			{"indexed": false, "name": "value", "type": "uint256"}
		],
		"name": "Transfer",
		"type": "event"
	},
	{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "owner", "type": "address"},
			{"indexed": true, "name": "spender", "type": "address"},
			{"indexed": false, "name": "value", "type": "uint256"}
		],
		"name": "Approval",
		"type": "event"
	},
	{
		"inputs": [],
		"name": "name",
		"outputs": [{"name": "", "type": "string"}],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "symbol",
		"outputs": [{"name": "", "type": "string"}],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "decimals",
		"outputs": [{"name": "", "type": "uint8"}],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "totalSupply",
		"outputs": [{"name": "", "type": "uint256"}],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [{"name": "account", "type": "address"}],
		"name": "balanceOf",
		"outputs": [{"name": "", "type": "uint256"}],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{"name": "to", "type": "address"},
			{"name": "amount", "type": "uint256"}
		],
		"name": "transfer",
		"outputs": [{"name": "", "type": "bool"}],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{"name": "spender", "type": "address"},
			{"name": "amount", "type": "uint256"}
		],
		"name": "approve",
		"outputs": [{"name": "", "type": "bool"}],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{"name": "owner", "type": "address"},
			{"name": "spender", "type": "address"}
		],
		"name": "allowance",
		"outputs": [{"name": "", "type": "uint256"}],
		"stateMutability": "view",
		"type": "function"
	}
]`

// erc721ABI is a standard ERC-721 ABI covering Transfer, Approval, and
// ApprovalForAll events.
const erc721ABI = `[
	{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "from", "type": "address"},
			{"indexed": true, "name": "to", "type": "address"},
			{"indexed": true, "name": "tokenId", "type": "uint256"}
		],
		"name": "Transfer",
		"type": "event"
	},
	{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "owner", "type": "address"},
			{"indexed": true, "name": "approved", "type": "address"},
			{"indexed": true, "name": "tokenId", "type": "uint256"}
		],
		"name": "Approval",
		"type": "event"
	},
	{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "owner", "type": "address"},
			{"indexed": true, "name": "operator", "type": "address"},
			{"indexed": false, "name": "approved", "type": "bool"}
		],
		"name": "ApprovalForAll",
		"type": "event"
	},
	{
		"inputs": [{"name": "tokenId", "type": "uint256"}],
		"name": "ownerOf",
		"outputs": [{"name": "", "type": "address"}],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [{"name": "owner", "type": "address"}],
		"name": "balanceOf",
		"outputs": [{"name": "", "type": "uint256"}],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{"name": "from", "type": "address"},
			{"name": "to", "type": "address"},
			{"name": "tokenId", "type": "uint256"}
		],
		"name": "transferFrom",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{"name": "to", "type": "address"},
			{"name": "tokenId", "type": "uint256"}
		],
		"name": "approve",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{"name": "operator", "type": "address"},
			{"name": "approved", "type": "bool"}
		],
		"name": "setApprovalForAll",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [{"name": "tokenId", "type": "uint256"}],
		"name": "getApproved",
		"outputs": [{"name": "", "type": "address"}],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{"name": "owner", "type": "address"},
			{"name": "operator", "type": "address"}
		],
		"name": "isApprovedForAll",
		"outputs": [{"name": "", "type": "bool"}],
		"stateMutability": "view",
		"type": "function"
	}
]`
