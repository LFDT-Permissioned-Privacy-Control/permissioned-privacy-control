package main

import (
	"context"
	"fmt"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	baseURL := env("PRIVACY_URL", "http://localhost:8080")
	adminToken := os.Getenv("PRIVACY_ADMIN_TOKEN")

	client, err := newHTTPClient(baseURL, adminToken)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid PRIVACY_URL: %v\n", err)
		os.Exit(1)
	}
	confirms := NewConfirmationEngine()

	s := mcp.NewServer(&mcp.Implementation{
		Name:    "privacy-proxy",
		Version: "0.1.0",
	}, nil)

	registerSystemTools(s, client)
	registerOrgTools(s, client, confirms)
	registerGroupTools(s, client, confirms)
	registerUserTools(s, client, confirms)
	registerContractTools(s, client, confirms)
	registerSessionTools(s, client, confirms)
	registerDisclosureTools(s, client, confirms)
	registerComplianceTools(s, client, confirms)
	registerExplorerTools(s, client)
	registerAccessLogs(s, client)
	registerAuditLogs(s, client)
	registerCacheStats(s, client)

	if err := s.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		fmt.Fprintf(os.Stderr, "MCP server error: %v\n", err)
		os.Exit(1)
	}
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
