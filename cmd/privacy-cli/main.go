// Package main provides the privacy-cli command-line tool for integrating
// Foundry deployments with the Open Privacy Suite service.
package main

import (
	"flag"
	"fmt"
	"os"
)

const Version = "0.1.0"

func main() {
	// Define subcommands
	prepareCmd := flag.NewFlagSet("prepare", flag.ExitOnError)
	verifyCmd := flag.NewFlagSet("verify", flag.ExitOnError)
	listCmd := flag.NewFlagSet("list", flag.ExitOnError)

	// Check for subcommand
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "prepare":
		runPrepare(prepareCmd, os.Args[2:])
	case "verify":
		runVerify(verifyCmd, os.Args[2:])
	case "list":
		runList(listCmd, os.Args[2:])
	case "audit":
		runAudit(os.Args[2:])
	case "reencrypt-rpc-keys":
		runReencryptRPCKeys(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Printf("privacy-cli version %s\n", Version)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Print(`privacy-cli - Open Privacy Suite CLI for Foundry integration

Usage:
  privacy-cli <command> [options]

Commands:
  prepare           Analyze Foundry broadcast and register addresses with Open Privacy Suite
  verify            Verify deployment matches registration
  list              List pending deployments for an organization
  audit verify      Walk an audit hash chain and report integrity (RD-858)
  reencrypt-rpc-keys  Re-encrypt group RPC API keys after rotating RPC_API_KEY_ENCRYPTION_KEY (RD-1164)

Options:
  -h, --help        Show this help message
  -v, --version     Show version

Examples:
  # Analyze broadcast and register addresses
  privacy-cli prepare --broadcast-file broadcast/Deploy.s.sol/31337/run-latest.json

  # Verify deployment matches registration
  privacy-cli verify --deployment-id dep_xyz789

  # List pending deployments
  privacy-cli list --org-id org_abc123

Configuration:
  Create a privacy.toml file in your project root:

  [proxy]
  api_url = "http://localhost:8080/api/v1"
  rpc_url = "http://localhost:8080/rpc"

  [org]
  id = "org_abc123"

  [auth]
  token = "${PRIVACY_PROXY_TOKEN}"
`)
}
