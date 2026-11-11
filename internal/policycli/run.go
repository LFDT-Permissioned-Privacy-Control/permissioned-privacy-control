// Package policycli implements local policy tooling. It does not connect to a
// deployment, resolve secrets, approve a proposal or change an active policy.
package policycli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policyprofiles"
)

const help = `OPS policy files
  ops-v2 policy profiles
  ops-v2 policy abi --file ABI.json
  ops-v2 policy prepare --source DIR --output NEW_DIR --profile ID
  ops-v2 policy check --bundle DIR --expected-digest sha256:HEX --environment ENV --chain-id ID --profile ID
  ops-v2 policy inspect --bundle DIR --expected-digest sha256:HEX --environment ENV --chain-id ID --profile ID

Results and errors are JSON. Profiles are compiled support, not Git approval or
runtime readiness. Preparation writes a new proposal directory; it never updates
an existing or active directory. Use the same source release as the deployment.
History preparation/check/inspect additionally requires --consumer history with
the creation-observed profile. Use that same trusted selection at server load;
the approved manifest explicitly declares runtime.history-read/v1.
`

type Report struct {
	Action         string                      `json:"action"`
	Approved       bool                        `json:"approved"`
	Profile        policyprofiles.Description  `json:"profile"`
	ManifestDigest policybundle.Digest         `json:"manifestDigest"`
	Requirements   policybundle.Requirements   `json:"requirements"`
	Metadata       policybundle.BundleMetadata `json:"metadata"`
}

// Run is the policy command entrypoint, shared by executable and functional
// tests. Every successful result describes local validation, never activation.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || (len(args) == 1 && (args[0] == "--help" || args[0] == "-h")) {
		fmt.Fprint(stdout, help)
		return 0
	}
	if len(args) < 2 || args[0] != "policy" {
		return reportError(stderr, "usage", errors.New("expected policy command; use --help"), 2)
	}
	if args[1] == "profiles" {
		if len(args) != 2 {
			return reportError(stderr, "usage", errors.New("profiles takes no arguments"), 2)
		}
		if err := json.NewEncoder(stdout).Encode(policyprofiles.Supported()); err != nil {
			return reportError(stderr, "output", err, 1)
		}
		return 0
	}
	if args[1] == "abi" {
		return inspectABI(ctx, args[2:], stdout, stderr)
	}
	command := args[1]
	if command != "prepare" && command != "check" && command != "inspect" {
		return reportError(stderr, "usage", errors.New("unknown policy command; use --help"), 2)
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	profile := flags.String("profile", "", "explicit compiled profile ID")
	consumer := flags.String("consumer", "", "explicit compiled consumer: history or delivery (creation-observed only)")
	var source, output, bundle, digest, environment, chain string
	if command == "prepare" {
		flags.StringVar(&source, "source", "", "flat draft source directory")
		flags.StringVar(&output, "output", "", "new artifact directory")
	} else {
		flags.StringVar(&bundle, "bundle", "", "selected artifact directory")
		flags.StringVar(&digest, "expected-digest", "", "independently selected manifest digest")
		flags.StringVar(&environment, "environment", "", "expected environment")
		flags.StringVar(&chain, "chain-id", "", "expected chain ID")
	}
	if err := flags.Parse(args[2:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, help)
			return 0
		}
		return reportError(stderr, "usage", err, 2)
	}
	if flags.NArg() != 0 || *profile == "" {
		return reportError(stderr, "usage", errors.New("an explicit profile and named flags are required"), 2)
	}
	var options policybundle.Options
	var description policyprofiles.Description
	var err error
	switch *consumer {
	case "":
		options, description, err = policyprofiles.Options(*profile)
	case "history":
		options, description, err = policyprofiles.HistoryOptions(*profile)
	case "delivery":
		options, description, err = policyprofiles.DeliveryOptions(*profile)
	default:
		return reportError(stderr, "usage", errors.New("unknown compiled consumer"), 2)
	}
	if err != nil {
		return reportError(stderr, "profile", err, 2)
	}
	if command == "prepare" {
		if source == "" || output == "" {
			return reportError(stderr, "usage", errors.New("source and new output directory are required"), 2)
		}
		artifact, err := policybundle.PrepareDirectory(ctx, policybundle.DraftSelection{Directory: source}, options)
		if err != nil {
			return reportError(stderr, "prepare", err, 1)
		}
		if err := writePrepared(ctx, output, artifact); err != nil {
			return reportError(stderr, "write", err, 1)
		}
		// Reload the completed exact output through the public pinned loader.
		// This is not a second validator and cannot substitute for Git approval.
		var manifest policybundle.Manifest
		if err := json.Unmarshal(artifact.ManifestBytes(), &manifest); err != nil {
			return reportError(stderr, "manifest", err, 1)
		}
		selection := policybundle.Selection{Directory: output, ExpectedManifestDigest: artifact.ManifestDigest(), ExpectedEnvironment: manifest.Environment, ExpectedChainID: manifest.ChainID}
		snapshot, err := policybundle.LoadDirectory(ctx, selection, options)
		if err != nil {
			return reportError(stderr, "check-prepared", err, 1)
		}
		return report(stdout, stderr, Report{Action: command, Profile: description, ManifestDigest: artifact.ManifestDigest(), Requirements: snapshot.Requirements(), Metadata: snapshot.Metadata()})
	}
	selection := policybundle.Selection{Directory: bundle, ExpectedManifestDigest: policybundle.Digest(digest), ExpectedEnvironment: environment, ExpectedChainID: chain}
	snapshot, err := policybundle.LoadDirectory(ctx, selection, options)
	if err != nil {
		return reportError(stderr, command, err, 1)
	}
	return report(stdout, stderr, Report{Action: command, Profile: description, ManifestDigest: snapshot.Metadata().ManifestDigest, Requirements: snapshot.Requirements(), Metadata: snapshot.Metadata()})
}

func report(stdout, stderr io.Writer, result Report) int {
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		return reportError(stderr, "output", err, 1)
	}
	return 0
}

func reportError(output io.Writer, stage string, err error, code int) int {
	// JSON encoding escapes terminal controls and never prints source buffers or
	// environment-resolved credentials. Source validators supply bounded errors.
	_ = json.NewEncoder(output).Encode(struct {
		Stage string `json:"stage"`
		Error string `json:"error"`
	}{stage, err.Error()})
	return code
}

func writePrepared(ctx context.Context, directory string, artifact *policybundle.PreparedArtifact) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Mkdir(directory, 0700); err != nil {
		return fmt.Errorf("new output directory required: %w", err)
	}
	// A handled error or interruption may leave an unreported partial NEW
	// directory. Existing paths are never modified; no active pointer is changed.
	for _, file := range artifact.Files() {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := writeExclusive(filepath.Join(directory, file.Path), file.Bytes); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := writeExclusive(filepath.Join(directory, "manifest.json"), artifact.ManifestBytes()); err != nil {
		return err
	}
	root, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.Sync(); err != nil {
		return err
	}
	return ctx.Err()
}

func writeExclusive(name string, raw []byte) error {
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(raw)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}
