package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

func runPrepare(cmd *flag.FlagSet, args []string) {
	// Define flags
	broadcastFile := cmd.String("broadcast-file", "", "Path to Foundry broadcast JSON file (required)")
	configPath := cmd.String("config", "", "Path to privacy.toml config file")
	apiURL := cmd.String("api-url", "", "Open Privacy Suite API URL")
	orgID := cmd.String("org-id", "", "Organization ID")
	token := cmd.String("token", "", "Authentication token")
	dryRun := cmd.Bool("dry-run", false, "Show what would be registered without calling API")
	verbose := cmd.Bool("verbose", false, "Show verbose output")

	if err := cmd.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	if *broadcastFile == "" {
		fmt.Fprintln(os.Stderr, "Error: --broadcast-file is required")
		fmt.Fprintln(os.Stderr, "\nUsage: privacy-cli prepare --broadcast-file <path> [options]")
		cmd.PrintDefaults()
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

	// Validate config (unless dry-run)
	if !*dryRun {
		if err := cfg.Validate(); err != nil {
			fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
			os.Exit(1)
		}
	}

	// Parse broadcast file
	fmt.Println("Analyzing Foundry broadcast file...")
	broadcast, err := ParseBroadcastFile(*broadcastFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing broadcast file: %v\n", err)
		os.Exit(1)
	}

	// Extract deployments
	deployments, err := ExtractDeployments(broadcast)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error extracting deployments: %v\n", err)
		os.Exit(1)
	}

	if len(deployments) == 0 {
		fmt.Println("No contract deployments found in broadcast file.")
		os.Exit(0)
	}

	fmt.Printf("\nFound %d contract deployments:\n", len(deployments))
	for _, d := range deployments {
		deps := "no address dependencies"
		if len(d.Dependencies) > 0 {
			deps = fmt.Sprintf("depends on: %s", strings.Join(d.Dependencies, ", "))
		}
		fmt.Printf("  - %s at %s (%s)\n", d.Name, d.Address, deps)
	}

	// Prepare contract registration info from broadcast addresses
	fmt.Println("\nContract addresses from broadcast:")
	prepareContracts := make([]ContractPrepareInfo, 0, len(deployments))

	for _, d := range deployments {
		fmt.Printf("  - %s: %s\n", d.Name, d.Address)

		if *verbose {
			fmt.Printf("    Bytecode hash: %s\n", d.BytecodeHash)
		}

		prepareContracts = append(prepareContracts, ContractPrepareInfo{
			Name:         d.Name,
			BytecodeHash: d.BytecodeHash,
		})
	}

	// If dry-run, stop here
	if *dryRun {
		fmt.Println("\n[Dry run] Would register the above contracts with Open Privacy Suite")
		fmt.Printf("API URL: %s\n", cfg.Proxy.APIURL)
		fmt.Printf("Org ID: %s\n", cfg.Org.ID)
		return
	}

	// Register with proxy
	fmt.Println("\nRegistering with Open Privacy Suite...")
	client, err := NewProxyClient(cfg.Proxy.APIURL, cfg.Auth.Token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	req := &PrepareRequest{
		Contracts: prepareContracts,
	}

	resp, err := client.PrepareDeployment(cfg.Org.ID, req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error registering deployment: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\nRegistered with Open Privacy Suite")
	fmt.Printf("  Deployment ID: %s\n", resp.DeploymentID)
	fmt.Printf("  Expires at: %s\n", resp.ExpiresAt)

	if len(resp.Addresses) > 0 {
		fmt.Println("\nRegistered addresses:")
		for name, addr := range resp.Addresses {
			fmt.Printf("  - %s: %s\n", name, addr)
		}
	}

	fmt.Println("\nNext steps:")
	fmt.Println("  1. Deploy your contracts using Foundry:")
	fmt.Printf("     forge script <your-script> --rpc-url %s --broadcast\n", cfg.Proxy.RPCURL)
	fmt.Println("  2. Verify the deployment:")
	fmt.Printf("     privacy-cli verify --deployment-id %s\n", resp.DeploymentID)
}
