package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
)

// generateVerifierDID generates a unique DID for a verifier
// Format: did:privado:verifier:<random-hex>
// For production, you may want to use a more structured approach
// or generate it via Privado ID Issuer Node API
func generateVerifierDID() string {
	// Generate 32 random bytes (256 bits) for uniqueness
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		slog.Error("failed to generate random bytes", "error", err)
		os.Exit(1)
	}

	// Convert to hex and format as DID
	randomHex := hex.EncodeToString(bytes)
	return fmt.Sprintf("did:privado:verifier:%s", randomHex)
}

func main() {
	verifierDID := generateVerifierDID()

	fmt.Println("Generated Verifier DID:")
	fmt.Println(verifierDID)
	fmt.Println()
	fmt.Println("Add this to your environment variables:")
	fmt.Printf("export VERIFIER_ID=%s\n", verifierDID)
	fmt.Println()
	fmt.Println("Or add to your .env file:")
	fmt.Printf("VERIFIER_ID=%s\n", verifierDID)

	// Optionally write to .env file if it exists
	if _, err := os.Stat(".env"); err == nil {
		fmt.Println()
		fmt.Println("Note: .env file exists. You may want to add VERIFIER_ID manually.")
	}
}
