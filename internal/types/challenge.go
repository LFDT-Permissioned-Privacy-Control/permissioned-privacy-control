package types

import "time"

// LinkChallenge represents a pending ETH address linking challenge.
// Extracted to a shared package so both server and redis can reference it.
type LinkChallenge struct {
	DID       string    `json:"did"`
	Nonce     string    `json:"nonce"`
	Address   string    `json:"address,omitempty"` // Optional: pre-specified address
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"created_at"`
}
