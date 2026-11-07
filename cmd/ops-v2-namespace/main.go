// Command ops-v2-namespace performs explicit offline historical-fact operations.
// It has no HTTP handler or current permission/ownership activation path.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/common"
	a "privacy-proxy/internal/admission"
	"privacy-proxy/internal/creationfacts"
	h "privacy-proxy/internal/historynamespace"
	"privacy-proxy/internal/operational/admissionsql"
	"privacy-proxy/internal/rpcexecution"
)

var environmentName = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "explicit namespace command required")
		return 2
	}
	command := args[0]
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dsnEnv := fs.String("dsn-env", "", "explicit offline owner DSN environment name")
	readerRole := fs.String("reader-role", "", "dedicated pre-existing blank reader role")
	environment := fs.String("environment", "", "selected environment")
	chain := fs.String("chain-id", "", "canonical uint64 decimal chain ID")
	genesis := fs.String("genesis-hash", "", "canonical genesis hash")
	deployment := fs.String("deployment-id", "", "stable deployment ID")
	generation := fs.String("generation", "", "expected namespace admission generation")
	revision := fs.Int64("revision", 0, "exact current namespace source revision")
	newGeneration := fs.String("new-generation", "", "current global generation for begin-recovery")
	entryNumber := fs.Uint64("entry-number", 0, "approved immutable model entry block")
	entryHash := fs.String("entry-hash", "", "approved immutable model entry hash")
	entryTime := fs.Uint64("entry-timestamp", 0, "approved model entry timestamp")
	endTime := fs.Uint64("end-timestamp-exclusive", 0, "finite supported model end timestamp")
	maxLife := fs.Int64("max-lifetimes", 1000000, "lower-only retained lifetime ceiling")
	maxTransfers := fs.Int64("max-transfers", 1000000, "lower-only retained transfer ceiling")
	maxCohorts := fs.Int64("max-cohorts", 10000, "lower-only retained cohort ceiling")
	maxDenies := fs.Int64("max-revoked-cohorts", 10000, "lower-only permanent deny ceiling")
	maxAddress := fs.Int("max-lifetimes-per-address", 32, "lower-only per-address ceiling")
	maxSegment := fs.Int("max-transfers-per-segment", 64, "lower-only per-segment ceiling")
	artifactPath := fs.String("artifact", "", "pinned approved regular JSON file")
	approvedSHA := fs.String("approved-sha256", "", "exact approved raw artifact sha256: digest")
	url := fs.String("reference-url", "", "explicit selected nonsecret checkpoint RPC URL")
	credentialRef := fs.String("reference-credential-ref", "", "nonsecret credential reference")
	credentialHeader := fs.String("reference-credential-header", "", "bound credential header")
	credentialEnv := fs.String("reference-credential-env", "", "explicit credential value environment name")
	cohortList := fs.String("cohort-ids", "", "comma-separated exact UUIDs, at most256")
	reason := fs.String("reason", "", "source-compromise or restore-gap")
	completeDigest := fs.String("completeness-digest", "", "operator archive completeness acknowledgement digest")
	drained := fs.Bool("acknowledge-drained", false, "all source readers/writers have stopped")
	neverInitialized := fs.Bool("acknowledge-never-initialized", false, "no earlier supplemental archive existed or was lost")
	complete := fs.Bool("acknowledge-complete", false, "all original/orphan/deny archive facts restored")
	timeoutSeconds := fs.Int64("recovery-timeout-seconds", 600, "finalize only, numeric1..1800 before duration conversion")
	if err := fs.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			fmt.Fprintln(stdout, "ops-v2-namespace migrate|bootstrap|status|import|revoke|begin-recovery|finalize; explicit --dsn-env, binding, generation/revision and command-specific acknowledgement options")
			return 0
		}
		fmt.Fprintln(stderr, "invalid namespace arguments")
		return 2
	}
	base := []string{"dsn-env", "environment", "chain-id", "genesis-hash", "deployment-id"}
	allowed := map[string][]string{
		"migrate":        {"dsn-env", "reader-role", "acknowledge-drained"},
		"status":         base,
		"bootstrap":      append(append([]string{}, base...), "generation", "entry-number", "entry-hash", "entry-timestamp", "end-timestamp-exclusive", "max-lifetimes", "max-transfers", "max-cohorts", "max-revoked-cohorts", "max-lifetimes-per-address", "max-transfers-per-segment", "acknowledge-drained", "acknowledge-never-initialized"),
		"import":         append(append([]string{}, base...), "generation", "revision", "artifact", "approved-sha256", "reference-url", "reference-credential-ref", "reference-credential-header", "reference-credential-env", "acknowledge-drained"),
		"revoke":         append(append([]string{}, base...), "generation", "revision", "cohort-ids", "reason", "acknowledge-drained"),
		"begin-recovery": append(append([]string{}, base...), "generation", "revision", "new-generation", "acknowledge-drained"),
		"finalize":       append(append([]string{}, base...), "generation", "revision", "completeness-digest", "acknowledge-drained", "acknowledge-complete", "recovery-timeout-seconds"),
	}
	commandFlags, known := allowed[command]
	badFlag := !known || fs.NArg() != 0 || !environmentName.MatchString(*dsnEnv)
	fs.Visit(func(f *flag.Flag) {
		found := false
		for _, name := range commandFlags {
			found = found || name == f.Name
		}
		badFlag = badFlag || !found
	})
	if badFlag {
		fmt.Fprintln(stderr, "unknown command, unused flag, or invalid explicit DSN environment name")
		return 2
	}
	if command != "status" && !*drained {
		fmt.Fprintln(stderr, "explicit drained-process acknowledgement required")
		return 2
	}
	if command == "import" || command == "revoke" || command == "begin-recovery" || command == "finalize" {
		if !h.UUID(*generation) || *revision < 1 {
			fmt.Fprintln(stderr, "exact canonical source generation and positive revision required")
			return 2
		}
	}
	if command == "finalize" {
		if _, err := h.OfflineTimeout(*timeoutSeconds); err != nil {
			fmt.Fprintln(stderr, "recovery timeout seconds must be 1..1800")
			return 2
		}
	}
	dsn := os.Getenv(*dsnEnv)
	if dsn == "" {
		fmt.Fprintln(stderr, "namespace owner DSN environment variable is empty")
		return 2
	}
	fail := func(err error) int {
		if err == nil {
			return 0
		}
		fmt.Fprintln(stderr, "namespace operation failed; check explicit input, original archive, role, binding and source state")
		return 1
	}
	write := func(value any) int {
		if json.NewEncoder(stdout).Encode(map[string]any{"scope": "attested-archive-metadata-only", "result": value}) != nil {
			return 1
		}
		return 0
	}
	if command == "migrate" {
		if code := fail(admissionsql.MigrateNamespace(ctx, dsn, *readerRole, *drained)); code != 0 {
			return code
		}
		return write(map[string]any{"schema": "ops_history_namespace_v1", "schemaVersion": 1})
	}
	binding := a.NetworkBinding{Environment: *environment, ChainID: *chain, GenesisHash: *genesis, DeploymentID: *deployment}
	key, err := binding.Key()
	if err != nil {
		fmt.Fprintln(stderr, "invalid namespace network binding")
		return 2
	}
	expected := admissionsql.NamespaceExpectedState{Generation: *generation, Revision: *revision}
	switch command {
	case "status":
		m, err := admissionsql.ReadNamespaceOwnerMetadata(ctx, dsn, binding)
		if code := fail(err); code != 0 {
			return code
		}
		return write(m)
	case "bootstrap":
		var hash h.Hash
		if json.Unmarshal([]byte(strconv.Quote(*entryHash)), &hash) != nil {
			fmt.Fprintln(stderr, "invalid canonical model entry hash")
			return 2
		}
		era := h.ModelEra{EntryNumber: *entryNumber, EntryHash: hash, EntryTimestamp: *entryTime, EndTimestampExclusive: *endTime}
		limits := h.CapacityLimits{Lifetimes: *maxLife, Transfers: *maxTransfers, Cohorts: *maxCohorts, RevokedCohorts: *maxDenies, LifetimesPerAddress: *maxAddress, TransfersPerSegment: *maxSegment}
		err = admissionsql.BootstrapNamespace(ctx, dsn, binding, *generation, era, limits, *drained, *neverInitialized)
	case "begin-recovery":
		err = admissionsql.BeginNamespaceRecovery(ctx, dsn, binding, expected, *newGeneration, *drained)
	case "revoke":
		if len(*cohortList) == 0 || len(*cohortList) > 256*37 {
			fmt.Fprintln(stderr, "bounded explicit cohort UUID selection required")
			return 2
		}
		err = admissionsql.RevokeNamespaceCohorts(ctx, dsn, binding, expected, strings.Split(*cohortList, ","), *reason, *drained)
	case "finalize":
		digest, parseErr := a.ParseDigest(*completeDigest)
		if parseErr != nil {
			fmt.Fprintln(stderr, "invalid archive completeness digest")
			return 2
		}
		err = admissionsql.FinalizeNamespaceRecovery(ctx, dsn, binding, expected, h.Digest(digest), *drained, *complete, *timeoutSeconds)
	case "import":
		approved, parseErr := a.ParseDigest(*approvedSHA)
		if parseErr != nil {
			fmt.Fprintln(stderr, "invalid approved raw artifact digest")
			return 2
		}
		artifact, parseErr := h.ReadApprovedArtifact(*artifactPath, h.Digest(approved))
		if parseErr != nil {
			return fail(parseErr)
		}
		if artifact.NetworkKey() != h.Digest(key) {
			fmt.Fprintln(stderr, "artifact does not match the selected network")
			return 2
		}
		point, addresses, needsProof := artifact.CheckpointRequest()
		var proof *rpcexecution.NamespaceCheckpointProof
		if needsProof {
			credential := rpcexecution.Credential{Header: *credentialHeader}
			if *credentialRef != "" {
				if !environmentName.MatchString(*credentialEnv) {
					fmt.Fprintln(stderr, "explicit credential environment name required")
					return 2
				}
				credential.Value = os.Getenv(*credentialEnv)
			} else if *credentialEnv != "" || *credentialHeader != "" {
				fmt.Fprintln(stderr, "unused credential options")
				return 2
			}
			era := artifact.Era()
			source := creationfacts.Source{Network: creationfacts.Network{Key: creationfacts.Digest(key), Environment: binding.Environment, ChainID: binding.ChainID, Genesis: common.HexToHash(binding.GenesisHash), Deployment: binding.DeploymentID}, URL: *url, CredentialRef: *credentialRef, CredentialHeader: *credentialHeader, Profile: rpcexecution.IncludedProfileID, PragueStart: era.EntryTimestamp, PragueEnd: era.EndTimestampExclusive}
			transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 3 * time.Second, DisableCompression: true, MaxConnsPerHost: 2, MaxIdleConnsPerHost: 2}
			defer transport.CloseIdleConnections()
			client, clientErr := rpcexecution.NewNamespaceCheckpointClient(transport, source, credential, era, rpcexecution.DefaultNamespaceCheckpointLimits())
			if clientErr != nil {
				return fail(clientErr)
			}
			proof, err = client.Qualify(ctx, point.Number, addresses)
			if err != nil {
				return fail(err)
			}
		} else if *url != "" || *credentialRef != "" || *credentialHeader != "" || *credentialEnv != "" {
			fmt.Fprintln(stderr, "unused checkpoint proof options")
			return 2
		}
		result, importErr := admissionsql.ImportNamespace(ctx, dsn, binding, expected, *artifactPath, h.Digest(approved), proof, *drained)
		if code := fail(importErr); code != 0 {
			return code
		}
		return write(result)
	}
	if code := fail(err); code != 0 {
		return code
	}
	m, err := admissionsql.ReadNamespaceOwnerMetadata(ctx, dsn, binding)
	if code := fail(err); code != 0 {
		return code
	}
	return write(m)
}
