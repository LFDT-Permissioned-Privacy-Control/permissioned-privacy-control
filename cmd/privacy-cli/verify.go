package main

import (
	"flag"
	"fmt"
	"os"
)

func runVerify(cmd *flag.FlagSet, args []string) {
	// Define flags
	deploymentID := cmd.String("deployment-id", "", "Deployment ID to verify (required)")
	configPath := cmd.String("config", "", "Path to privacy.toml config file")
	apiURL := cmd.String("api-url", "", "Open Privacy Suite API URL")
	token := cmd.String("token", "", "Authentication token")
	verbose := cmd.Bool("verbose", false, "Show verbose output")

	if err := cmd.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	if *deploymentID == "" {
		fmt.Fprintln(os.Stderr, "Error: --deployment-id is required")
		fmt.Fprintln(os.Stderr, "\nUsage: privacy-cli verify --deployment-id <id> [options]")
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
	cfg.MergeWithFlags(*apiURL, "", "", *token)

	// Validate API URL
	if cfg.Proxy.APIURL == "" {
		fmt.Fprintln(os.Stderr, "Error: api_url is required")
		os.Exit(1)
	}

	// Create client
	client, err := NewProxyClient(cfg.Proxy.APIURL, cfg.Auth.Token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// First, get the deployment info
	fmt.Printf("Fetching deployment %s...\n", *deploymentID)
	deployment, err := client.GetDeployment(*deploymentID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching deployment: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nDeployment: %s\n", deployment.ID)
	fmt.Printf("  Status: %s\n", deployment.Status)
	fmt.Printf("  Created: %s\n", deployment.CreatedAt)
	fmt.Printf("  Expires: %s\n", deployment.ExpiresAt)

	if *verbose && len(deployment.Addresses) > 0 {
		fmt.Println("\n  Registered addresses:")
		for name, addr := range deployment.Addresses {
			fmt.Printf("    - %s: %s\n", name, addr)
		}
	}

	// Verify the deployment
	fmt.Println("\nVerifying deployment...")
	result, err := client.VerifyDeployment(*deploymentID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error verifying deployment: %v\n", err)
		os.Exit(1)
	}

	// Print results
	fmt.Println("\nVerification Results:")
	fmt.Println("=====================")

	allVerified := true
	for _, contract := range result.Contracts {
		status := "VERIFIED"
		if !contract.Verified {
			status = "FAILED"
			allVerified = false
		}

		fmt.Printf("\n%s: %s\n", contract.Name, status)
		fmt.Printf("  Expected: %s\n", contract.ExpectedAddress)
		if contract.ActualAddress != "" {
			fmt.Printf("  Actual:   %s\n", contract.ActualAddress)
		}
		fmt.Printf("  Bytecode: %s\n", boolToStatus(contract.BytecodeMatch))

		if contract.Error != "" {
			fmt.Printf("  Error: %s\n", contract.Error)
		}
	}

	if len(result.Errors) > 0 {
		fmt.Println("\nErrors:")
		for _, err := range result.Errors {
			fmt.Printf("  - %s\n", err)
		}
	}

	fmt.Println()
	if allVerified && result.Verified {
		fmt.Println("All contracts verified successfully!")
	} else {
		fmt.Println("Verification failed. See errors above.")
		os.Exit(1)
	}
}

func boolToStatus(b bool) string {
	if b {
		return "Match"
	}
	return "MISMATCH"
}
