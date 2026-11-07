// Command ops-creation-observer owns explicit operational header-readiness and
// offline schema/recovery work. It exposes no HTTP or mutable policy endpoint.
package main

import (
	"bytes"
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
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
	a "privacy-proxy/internal/admission"
	"privacy-proxy/internal/creationcapture"
	f "privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/creationobserver"
	"privacy-proxy/internal/operational/admissionsql"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/strictjson"
)

var envName = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}
func readDocument(path string, max int64, target any) error {
	l, err := os.Lstat(path)
	if err != nil || !l.Mode().IsRegular() || l.Size() > max {
		return f.ErrInvalid
	}
	file, err := os.Open(path)
	if err != nil {
		return f.ErrInvalid
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil || int64(len(raw)) > max {
		return f.ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	value, err := strictjson.ReadValue(d, 0, 12)
	if err != nil {
		return f.ErrInvalid
	}
	if _, err := d.Token(); err != io.EOF {
		return f.ErrInvalid
	}
	return strictjson.ExactDecode(value, target)
}
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "explicit observer command required")
		return 2
	}
	command := args[0]
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dsnEnv := fs.String("dsn-env", "", "explicit owner or worker DSN environment name")
	app := fs.String("app-role", "", "existing app role")
	reader := fs.String("reader-role", "", "existing reader role")
	retention := fs.String("retention-role", "", "existing retention role")
	observer := fs.String("observer-role", "", "existing observer role")
	facts := fs.String("facts-role", "", "existing facts reader role")
	environment := fs.String("environment", "", "selected environment")
	chain := fs.String("chain-id", "", "canonical chain ID")
	genesis := fs.String("genesis-hash", "", "canonical genesis hash")
	deployment := fs.String("deployment-id", "", "stable deployment ID")
	generation := fs.String("generation", "", "expected admission generation UUID")
	coverage := fs.String("coverage-digest", "", "expected operational completeness digest")
	referenceURL := fs.String("reference-url", "", "selected reference RPC URL")
	credentialRef := fs.String("reference-credential-ref", "", "nonsecret reference credential name")
	credentialHeader := fs.String("reference-credential-header", "", "reference credential header name")
	credentialEnv := fs.String("reference-credential-env", "", "explicit environment variable containing credential value")
	pragueStart := fs.Uint64("prague-start", 0, "finite inclusive Prague timestamp")
	pragueEnd := fs.Uint64("prague-end", 0, "finite exclusive Prague timestamp")
	sourcesPath := fs.String("sources-file", "", "bounded closed JSON array of exact nonsecret ingress Source descriptors; [] is read-only")
	assertion := fs.String("caught-up-assertion", "", "explicit operator-managed-canonical-head/v1 TCB acknowledgement")
	floorHeight := fs.String("floor-height", "", "canonical decimal bootstrap checkpoint height")
	floorHash := fs.String("floor-hash", "", "expected bootstrap checkpoint hash")
	observerEpoch := fs.String("observer-epoch", "", "exact current observer recovery UUID")
	epochsPath := fs.String("epochs-file", "", "closed <=32KiB {captureEpochs:[UUID...]} object")
	reason := fs.String("reason", "", "closed operational trust revocation reason")
	drained := fs.Bool("acknowledge-drained", false, "all old writers/readers/workers have stopped")
	complete := fs.Bool("acknowledge-complete", false, "complete operational and permanent deny history attestation")
	trust := fs.Bool("acknowledge-capture-trust-resolved", false, "complete affected epoch selection and unaffected retained trust attestation")
	timeout := fs.Duration("recovery-timeout", 10*time.Minute, "finalize only, positive and <=30m")
	if err := fs.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			fmt.Fprintln(stdout, "ops-creation-observer migrate|bootstrap|status|run|revoke-capture-epochs|finalize-observer; explicit --dsn-env and network/epoch/source options required; run is header-readiness only")
			return 0
		}
		fmt.Fprintln(stderr, "invalid observer arguments")
		return 2
	}
	badTimeout := *timeout <= 0 || *timeout > admissionsql.MaxRecoveryTimeout
	fs.Visit(func(flag *flag.Flag) {
		if flag.Name == "recovery-timeout" && command != "finalize-observer" {
			badTimeout = true
		}
	})
	if fs.NArg() != 0 || !envName.MatchString(*dsnEnv) || badTimeout {
		fmt.Fprintln(stderr, "invalid explicit observer options or recovery timeout")
		return 2
	}
	dsn := os.Getenv(*dsnEnv)
	if dsn == "" {
		fmt.Fprintln(stderr, "observer DSN environment variable is empty")
		return 2
	}
	fail := func(err error) int {
		if err != nil {
			fmt.Fprintln(stderr, "observer operation failed; check selected binding, coverage, roles, trust and canonical node readiness")
			return 1
		}
		return 0
	}
	write := func(v any) int {
		if json.NewEncoder(stdout).Encode(v) != nil {
			return 1
		}
		return 0
	}
	if command == "migrate" {
		if !*drained {
			fmt.Fprintln(stderr, "migration requires explicit drained-process acknowledgement")
			return 2
		}
		if code := fail(admissionsql.MigrateCreationObserver(ctx, dsn, *app, *reader, *retention, *observer, *facts)); code != 0 {
			return code
		}
		info, err := admissionsql.InstalledSchema(ctx, dsn)
		if code := fail(err); code != 0 {
			return code
		}
		return write(info)
	}
	binding := a.NetworkBinding{Environment: *environment, ChainID: *chain, GenesisHash: *genesis, DeploymentID: *deployment}
	key, err := binding.Key()
	if err != nil {
		fmt.Fprintln(stderr, "invalid observer network binding")
		return 2
	}
	if command == "status" {
		state, err := admissionsql.CreationObserverStatus(ctx, dsn, binding)
		if code := fail(err); code != 0 {
			return code
		}
		return write(state)
	}
	if command == "revoke-capture-epochs" {
		var selection struct {
			CaptureEpochs []string `json:"captureEpochs"`
		}
		if readDocument(*epochsPath, 32<<10, &selection) != nil || len(selection.CaptureEpochs) < 1 || len(selection.CaptureEpochs) > 256 {
			fmt.Fprintln(stderr, "invalid bounded capture epoch selection")
			return 2
		}
		if code := fail(admissionsql.RevokeCaptureEpochs(ctx, dsn, binding, *generation, *observerEpoch, *reason, selection.CaptureEpochs, *drained)); code != 0 {
			return code
		}
		return write(map[string]any{"revocationSelectionAccepted": true})
	}
	digest, err := a.ParseDigest(*coverage)
	if err != nil || !a.ValidUUID(*generation) {
		fmt.Fprintln(stderr, "invalid explicit recovery state")
		return 2
	}
	expected := a.ExpectedState{Generation: *generation, Coverage: digest}
	if command == "finalize-observer" {
		if !*drained {
			fmt.Fprintln(stderr, "finalization requires explicit drained-process acknowledgement")
			return 2
		}
		if code := fail(admissionsql.FinalizeCreationObserverRecovery(ctx, dsn, binding, expected, *observerEpoch, *complete, *trust, *timeout)); code != 0 {
			return code
		}
		return write(map[string]any{"generation": *generation, "observerReady": false, "captureReady": false, "quarantine": "awaiting-canonical"})
	}
	if command != "run" && command != "bootstrap" {
		fmt.Fprintln(stderr, "unknown observer command")
		return 2
	}
	network := f.Network{Key: f.Digest(key), Environment: binding.Environment, ChainID: binding.ChainID, Genesis: common.HexToHash(binding.GenesisHash), Deployment: binding.DeploymentID}
	ref := f.Source{Network: network, URL: *referenceURL, CredentialRef: *credentialRef, CredentialHeader: *credentialHeader, Profile: "reth-prague-included-creations/v1", PragueStart: *pragueStart, PragueEnd: *pragueEnd}
	var sources []f.Source
	if *assertion != f.CaughtUpAssertion || !ref.Valid() || readDocument(*sourcesPath, 1<<20, &sources) != nil {
		fmt.Fprintln(stderr, "invalid explicit reference/source/assertion")
		return 2
	}
	set, err := f.SourceSet(sources)
	if err != nil {
		fmt.Fprintln(stderr, "invalid ingress source set")
		return 2
	}
	for _, s := range sources {
		if s.Network != network || s.Profile == ref.Profile {
			fmt.Fprintln(stderr, "source set does not match selected ingress/network")
			return 2
		}
	}
	credential := rpcexecution.Credential{Header: *credentialHeader}
	if *credentialRef != "" {
		if !envName.MatchString(*credentialEnv) {
			fmt.Fprintln(stderr, "explicit credential environment name required")
			return 2
		}
		credential.Value = os.Getenv(*credentialEnv)
	} else if *credentialEnv != "" {
		fmt.Fprintln(stderr, "unexpected credential environment name")
		return 2
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	transport.TLSHandshakeTimeout = 3 * time.Second
	transport.ResponseHeaderTimeout = 3 * time.Second
	transport.MaxResponseHeaderBytes = 16 << 10
	transport.MaxConnsPerHost = 2
	transport.DisableCompression = true
	defer transport.CloseIdleConnections()
	client, err := rpcexecution.NewHeaderClient(transport, ref, credential, rpcexecution.DefaultHeaderLimits())
	if err != nil {
		fmt.Fprintln(stderr, "invalid selected reference credential/binding")
		return 2
	}
	state := f.State{Generation: *generation, Coverage: f.Digest(digest)}
	if command == "bootstrap" {
		n, err := strconv.ParseUint(*floorHeight, 10, 63)
		hash, hashErr := a.ParseDigest("sha256:" + trimHex(*floorHash))
		if !*drained || err != nil || strconv.FormatUint(n, 10) != *floorHeight || hashErr != nil || hash == (a.Digest{}) {
			fmt.Fprintln(stderr, "invalid explicit canonical floor or drained acknowledgement")
			return 2
		}
		batch, err := client.Read(ctx, []rpcexecution.HeaderQuery{{NumberOrTag: "0x" + strconv.FormatUint(n, 16)}})
		if code := fail(err); code != 0 {
			return code
		}
		headers := batch.Headers()
		if len(headers) != 1 || headers[0].Hash != common.Hash(hash) {
			return fail(f.ErrInvalid)
		}
		metadata := creationcapture.Metadata{Network: network, State: state, Reference: ref.Digest(), SourceSet: set}
		if code := fail(admissionsql.BootstrapCreationObserver(ctx, dsn, binding, expected, metadata, headers[0])); code != 0 {
			return code
		}
		return write(map[string]any{"observerReady": false, "captureReady": false, "floor": headers[0]})
	}
	store, err := admissionsql.OpenObserver(ctx, dsn)
	if code := fail(err); code != 0 {
		return code
	}
	defer store.Close()
	worker, err := creationobserver.NewHeaderWorker(creationobserver.HeaderOptions{Network: network, State: state, Owner: uuid.NewString(), SourceSet: set, Reference: ref, CaughtUpAssertion: *assertion, Client: client, Store: store})
	if code := fail(err); code != 0 {
		return code
	}
	err = worker.Run(ctx)
	if ctx.Err() != nil {
		return 0
	}
	return fail(err)
}
func trimHex(raw string) string {
	if len(raw) == 66 && raw[:2] == "0x" {
		return raw[2:]
	}
	return ""
}
