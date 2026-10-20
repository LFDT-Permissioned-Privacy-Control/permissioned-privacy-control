package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

func runList(cmd *flag.FlagSet, args []string) {
	// Define flags
	orgID := cmd.String("org-id", "", "Organization ID (required)")
	configPath := cmd.String("config", "", "Path to privacy.toml config file")
	apiURL := cmd.String("api-url", "", "Open Privacy Suite API URL")
	token := cmd.String("token", "", "Authentication token")
	status := cmd.String("status", "", "Filter by status (pending, verified, expired)")
	verbose := cmd.Bool("verbose", false, "Show verbose output including addresses")

	if err := cmd.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	// Load configuration
	cfg, err := LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	// Merge flags with config
	cfg.MergeWithFlags(*apiURL, "", *orgID, *token)

	// Validate required fields
	if cfg.Proxy.APIURL == "" {
		fmt.Fprintln(os.Stderr, "Error: api_url is required")
		os.Exit(1)
	}
	if cfg.Org.ID == "" {
		fmt.Fprintln(os.Stderr, "Error: --org-id is required")
		fmt.Fprintln(os.Stderr, "\nUsage: privacy-cli list --org-id <id> [options]")
		cmd.PrintDefaults()
		os.Exit(1)
	}

	// Create client
	client, err := NewProxyClient(cfg.Proxy.APIURL, cfg.Auth.Token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Fetch deployments
	fmt.Printf("Fetching deployments for organization %s...\n\n", cfg.Org.ID)
	result, err := client.ListDeployments(cfg.Org.ID, *status)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching deployments: %v\n", err)
		os.Exit(1)
	}

	if len(result.Deployments) == 0 {
		statusMsg := ""
		if *status != "" {
			statusMsg = fmt.Sprintf(" with status '%s'", *status)
		}
		fmt.Printf("No deployments found%s.\n", statusMsg)
		return
	}

	fmt.Printf("Found %d deployment(s):\n\n", result.Total)

	for _, d := range result.Deployments {
		printDeployment(d, *verbose)
	}
}

func printDeployment(d Deployment, verbose bool) {
	statusIndicator := getStatusIndicator(d.Status)
	fmt.Printf("%s %s\n", statusIndicator, d.ID)
	fmt.Printf("   Status:  %s\n", d.Status)
	fmt.Printf("   Created: %s\n", d.CreatedAt)

	if d.ExpiresAt != "" {
		fmt.Printf("   Expires: %s\n", d.ExpiresAt)
	}
	if d.VerifiedAt != "" {
		fmt.Printf("   Verified: %s\n", d.VerifiedAt)
	}

	if verbose && len(d.Addresses) > 0 {
		fmt.Println("   Addresses:")
		for name, addr := range d.Addresses {
			fmt.Printf("     - %s: %s\n", name, addr)
		}
	}

	fmt.Println()
}

func getStatusIndicator(status string) string {
	switch strings.ToLower(status) {
	case "pending":
		return "[PENDING]"
	case "verified":
		return "[VERIFIED]"
	case "expired":
		return "[EXPIRED]"
	case "failed":
		return "[FAILED]"
	default:
		return "[" + strings.ToUpper(status) + "]"
	}
}
