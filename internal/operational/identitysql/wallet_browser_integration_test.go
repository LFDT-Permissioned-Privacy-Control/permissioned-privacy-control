package identitysql_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	d "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/networkidentity"
	"privacy-proxy/internal/operational/identitysql"
	"privacy-proxy/internal/operational/walletsql"
	"privacy-proxy/internal/wallethttp"
)

// Both built UIs cross the real broker, restricted app session store and native
// wallet service/SQL. The injected provider produces real EIP191 signatures;
// it does not supply a wallet ownership verdict to the server.
func TestActualBuiltWalletAzureCentralAndExplorer(t *testing.T) {
	if os.Getenv("OPS_BROWSER_INTEGRATION") != "1" || os.Getenv("OPS_E2B_EXPLORER_ROOT") == "" {
		t.Skip("owned cross-repository built wallet flags required")
	}
	root, opsBuild, appBuild := e2bBuild(t)
	x := newSSOAzureFixture(t, true)
	app := reserveAppOrigin(t)
	sso := attachSSOAt(t, x, []string{d.Org, d.OtherOrg}, false, app+"/api/auth/callback")
	centralMount(t, x, opsBuild)
	metadata := x.db.snapshot.Metadata()
	network := networkidentity.Binding{Environment: metadata.Environment, ChainID: metadata.ChainID, GenesisHash: "0x" + strings.Repeat("1", 64), DeploymentID: "owned-wallet-browser"}
	wallet := d.ActualWalletFixture(t, t.Context(), x.db.ownerDSN, x.db.snapshot, network, x.db.clock)
	// Reproduce an existing deployment's old default PUBLIC function grant, then
	// run the real owner permission phase twice. No checker is weakened.
	if _, err := wallet.Owner.Exec(t.Context(), `GRANT EXECUTE ON FUNCTION ops_wallet_v2.wallet_link_monotonic() TO PUBLIC`); err != nil {
		t.Fatal(err)
	}
	var executable bool
	if err := wallet.Owner.QueryRow(t.Context(), `SELECT has_function_privilege('state_wallet_app','ops_wallet_v2.wallet_link_monotonic()','EXECUTE')`).Scan(&executable); err != nil || !executable {
		t.Fatal("original PUBLIC function control", err)
	}
	for i := 0; i < 2; i++ {
		if err := walletsql.Migrate(t.Context(), x.db.ownerDSN, "state_wallet_app", "state_wallet_reader", "state_wallet_retention"); err != nil {
			t.Fatal("idempotent actual owner migration", err)
		}
	}
	if err := wallet.Owner.QueryRow(t.Context(), `SELECT has_function_privilege('state_wallet_app','ops_wallet_v2.wallet_link_monotonic()','EXECUTE')`).Scan(&executable); err != nil || executable {
		t.Fatal("unnecessary function execution remained", err)
	}
	brokerStore, err := identitysql.OpenPrivateV2(t.Context(), x.db.appDSN, x.db.scope, x.db.clock)
	if err != nil {
		t.Fatal("actual broker store startup after wallet ACL", err)
	}
	brokerStore.Close()
	handler, e := wallethttp.New(wallet.Service)
	if e != nil {
		t.Fatal(e)
	}
	for _, mux := range x.muxes {
		links := http.NewServeMux()
		handler.RegisterLinks(links)
		mux.Handle("/api/v2/eth/", links)
		mux.HandleFunc("/__test/wallet-identity", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" || r.Header.Get("Origin") != x.origin {
				w.WriteHeader(403)
				return
			}
			var command struct{ AuthorizationURL, Subject string }
			if json.NewDecoder(http.MaxBytesReader(w, r.Body, 20<<10)).Decode(&command) != nil {
				w.WriteHeader(400)
				return
			}
			u, err := url.Parse(command.AuthorizationURL)
			if err != nil || u.Host != "login.microsoftonline.com" || u.Query().Get("nonce") == "" || command.Subject != d.Subject && command.Subject != d.AdminSubject {
				w.WriteHeader(400)
				return
			}
			x.db.entra.SetNonce(u.Query().Get("nonce"))
			x.db.entra.SetSubject(command.Subject)
			w.WriteHeader(204)
		})
	}
	_, stop := e2bApp(t, x, appBuild, app, sso)
	defer stop()
	node := os.Getenv("OPS_TEST_NODE")
	if node == "" {
		node = "node"
	}
	command := exec.CommandContext(t.Context(), node, filepath.Join(root, "e2e/playwright/v2-wallet-browser.mjs"), x.origin, app, time.Unix(x.db.clock().Unix(), 0).UTC().Format(time.RFC3339))
	command.Dir = root
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("actual wallet browser failed: %s", output)
	}
	t.Log(strings.TrimSpace(string(output)))
	var rows, active int
	var proof bool
	if err := wallet.Owner.QueryRow(t.Context(), `SELECT count(*),count(*)FILTER(WHERE NOT revoked),coalesce(bool_and(proof_kind='eip191_v2' AND octet_length(signature)=65),false) FROM ops_wallet_v2.wallet_links WHERE namespace=$1`, wallet.Namespace[:]).Scan(&rows, &active, &proof); err != nil || rows != 2 || active != 1 || !proof {
		t.Fatal("actual SQL proof/revocation or held-signature outcome", rows, active, proof, err)
	}
	var outstanding int
	if err := wallet.Owner.QueryRow(t.Context(), `SELECT count(*) FROM ops_wallet_v2.wallet_challenges WHERE namespace=$1`, wallet.Namespace[:]).Scan(&outstanding); err != nil || outstanding != 2 {
		t.Fatal("held signatures were consumed or action retried", outstanding, err)
	}
	if _, err := wallet.Owner.Exec(t.Context(), `UPDATE ops_wallet_v2.wallet_links SET message=message||decode('00','hex') WHERE namespace=$1`, wallet.Namespace[:]); err == nil {
		t.Fatal("immutable proof trigger stopped enforcing")
	}
	if _, err := wallet.Owner.Exec(t.Context(), `UPDATE ops_wallet_v2.wallet_links SET revoked=false,revoked_at=NULL WHERE namespace=$1 AND revoked`, wallet.Namespace[:]); err == nil {
		t.Fatal("monotonic revocation trigger stopped enforcing")
	}
}
