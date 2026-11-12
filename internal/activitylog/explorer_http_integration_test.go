package activitylog_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"privacy-proxy/internal/activitymethoddata"
	a "privacy-proxy/internal/admission"
	f "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/explorerquery"
	"privacy-proxy/internal/historyfacts"
	"privacy-proxy/internal/networkidentity"
	"privacy-proxy/internal/operational/admissionsql"
	"privacy-proxy/internal/operational/explorerindex"
	"privacy-proxy/internal/operational/rpcactivity"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/rpcengine"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/rpchistorypolicy"
	"privacy-proxy/internal/rpcmetadatapolicy"
	"privacy-proxy/internal/rpcstatepolicy"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestExplorerActualWalletShareIndexNodeAndOneRecorderHTTP(t *testing.T) {
	d := rawPostgres(t)
	ctx := t.Context()
	for _, role := range []string{"history_observer", "history_facts"} {
		if _, err := d.owner.Exec(ctx, `CREATE ROLE `+role+` LOGIN NOINHERIT PASSWORD 'raw-test-only'`); err != nil {
			t.Fatal(err)
		}
	}
	if err := admissionsql.MigrateCreationObserver(ctx, d.ownerDSN, "raw_app", "raw_reader", "raw_retention", "history_observer", "history_facts"); err != nil {
		t.Fatal(err)
	}
	target := common.HexToAddress("0x123456")
	txs := []*types.Transaction{f.HistoryTransaction(t, 1, 0, target), f.HistoryTransaction(t, 2, 1, target)}
	node := f.NewHistoryNode(t, txs, [][]*types.Log{{}, {}})
	network := node.Network()
	var instant atomic.Int64
	instant.Store(f.Now)
	clock := func() time.Time { return time.Unix(instant.Load(), 0) }
	src := f.DefaultStateFixture(t)
	src.HistoryConsumer = true
	contract := f.ReadContract(target.Hex())
	src.Contracts[f.Org] = []policybundle.Contract{contract}
	snapshot := f.StateSnapshot(t, src)
	tok := f.Token(t, snapshot, f.Subject, "Auditor")
	if _, err := d.owner.Exec(ctx, `CREATE DATABASE history_wallet_test`); err != nil {
		t.Fatal(err)
	}
	walletURL, _ := url.Parse(d.ownerDSN)
	walletURL.Path = "/history_wallet_test"
	wallet := f.ActualWalletFixture(t, ctx, walletURL.String(), snapshot, network, clock)
	wallet.Link(t, ctx, tok, f.HistoryKey(1))
	state := a.ExpectedState{Generation: uuid.NewString(), Coverage: admissionsql.EmptyCoverage()}
	nb := a.NetworkBinding{Environment: network.Environment, ChainID: network.ChainID, GenesisHash: network.GenesisHash, DeploymentID: network.DeploymentID}
	if err := admissionsql.BootstrapEmpty(ctx, d.ownerDSN, nb, state.Generation); err != nil {
		t.Fatal(err)
	}
	app, err := admissionsql.Open(ctx, d.appDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Close)
	readerURL, _ := url.Parse(d.ownerDSN)
	readerURL.User = url.UserPassword("raw_reader", "raw-test-only")
	readerStore, err := admissionsql.OpenReader(ctx, readerURL.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(readerStore.Close)
	shareBinding := historyfacts.ShareBinding{Network: network, State: state, SchemaProfile: historyfacts.ShareSchemaProfile}
	shares, err := admissionsql.NewShareReader(readerStore, shareBinding)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := nb.Key()
	recipients, digest, _ := a.NormalizeRecipients([]string{f.Actor(f.Subject)})
	scope := a.Scope{Network: key, Hash: txs[1].Hash(), Actor: f.Actor(f.AdminSubject), Organization: f.Org, State: state}
	share := a.Share{Network: key, Hash: scope.Hash, Actor: scope.Actor, Organization: scope.Organization, Recipients: recipients, RecipientDigest: digest, DeclaredAt: clock(), Witness: a.Witness{AnchorHash: node.Hash(), AnchorNumber: 1, AnchorTimestamp: uint64(f.Now), ManifestDigest: a.Digest{2}, WalletVersion: a.Digest{3}, WalletEvidenceAt: clock()}}
	receipt, err := app.WithRawTransaction(ctx, scope, func(tx a.RawTx) (a.CommitKind, error) { return a.CommitAllow, tx.PutShare(share) })
	if err != nil || !receipt.Committed {
		t.Fatal("actual immutable share commit", err)
	}
	policyRaw, _ := json.Marshal(rpchistorypolicy.Source{APIVersion: rpchistorypolicy.APIVersion, Kind: rpchistorypolicy.Kind, BundleManifestDigest: string(snapshot.Metadata().ManifestDigest), AnonymousMethods: []string{}})
	policy, err := rpchistorypolicy.Compile(policyRaw, rpchistorypolicy.Digest(sha256.Sum256(policyRaw)))
	if err != nil {
		t.Fatal(err)
	}
	limits := rpcexecution.DefaultHistoryReadLimits()
	client := func(org string) *rpcexecution.HistoryReadClient {
		c, err := rpcexecution.NewHistoryReadClient(node.Transport(), node.Source(org), rpcexecution.Credential{}, limits)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	history, err := rpcengine.NewHistory(rpcengine.HistoryConfig{Snapshot: snapshot, Policy: policy, Network: network, Default: client(""), Clients: map[rpcengine.HistoryBindingKey]*rpcexecution.HistoryReadClient{{OrganizationID: f.Org}: client(f.Org), {OrganizationID: f.OtherOrg}: client(f.OtherOrg)}, Wallets: wallet.Resolver, WalletBinding: wallet.Binding, WalletState: wallet.State, Shares: shares, ShareExpected: shareBinding, QueryLimits: limits, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	metadataRaw, _ := json.Marshal(rpcmetadatapolicy.Source{APIVersion: rpcmetadatapolicy.APIVersion, Kind: rpcmetadatapolicy.Kind, BundleManifestDigest: string(snapshot.Metadata().ManifestDigest), AnonymousMethods: []string{}})
	metadataPolicy, err := rpcmetadatapolicy.Compile(metadataRaw, rpcmetadatapolicy.Digest(sha256.Sum256(metadataRaw)))
	if err != nil {
		t.Fatal(err)
	}
	metaClient, err := rpcexecution.NewMetadataClient(node.Transport(), rpcexecution.MetadataSource{Network: network, URL: node.Source("").URL, AllowUnauthenticated: true}, rpcexecution.Credential{}, rpcexecution.DefaultMetadataLimits())
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := rpcengine.NewMetadata(rpcengine.MetadataConfig{Snapshot: snapshot, Policy: metadataPolicy, Network: network, Default: metaClient, Clients: map[rpcengine.MetadataBindingKey]*rpcexecution.MetadataClient{{OrganizationID: f.Org}: metaClient, {OrganizationID: f.OtherOrg}: metaClient}, QueryLimits: rpcexecution.DefaultMetadataLimits(), Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	activity := setupActivityDatabase(t, network)
	stateRaw, _ := json.Marshal(rpcstatepolicy.Source{APIVersion: rpcstatepolicy.APIVersion, Kind: rpcstatepolicy.Kind, BundleManifestDigest: string(snapshot.Metadata().ManifestDigest), AnonymousMethods: []string{}, PreRegisteredAddresses: []rpcstatepolicy.PreRegisteredAddress{}})
	statePolicy, err := rpcstatepolicy.Compile(stateRaw, rpcstatepolicy.Digest(sha256.Sum256(stateRaw)))
	if err != nil {
		t.Fatal(err)
	}
	stateClient, err := rpcexecution.NewStateClient(node.Transport(), rpcexecution.MetadataSource{Network: network, URL: node.Source("").URL, AllowUnauthenticated: true}, rpcexecution.Credential{}, rpcexecution.DefaultStateLimits())
	if err != nil {
		t.Fatal(err)
	}
	stateEngine, err := rpcengine.NewState(rpcengine.StateConfig{Snapshot: snapshot, Policy: statePolicy, Network: network, Default: stateClient, Clients: map[rpcengine.StateBindingKey]*rpcexecution.StateClient{{OrganizationID: f.Org}: stateClient, {OrganizationID: f.OtherOrg}: stateClient}, QueryLimits: rpcexecution.DefaultStateLimits(), Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	index, indexOwner, binding := actualExplorerIndex(t, d.owner, d.ownerDSN, network)
	if _, err = indexOwner.Exec(ctx, `UPDATE blocks SET hash=$1 WHERE number=1`, strings.ToLower(node.Hash().Hex())); err != nil {
		t.Fatal(err)
	}
	for i, tx := range txs {
		sender, err := types.Sender(types.LatestSignerForChainID(tx.ChainId()), tx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = indexOwner.Exec(ctx, `INSERT INTO transactions(hash,block_number,tx_index,from_address,to_address,value,gas_used,gas_price,status,input_data,nonce)VALUES($1,1,$2,$3,$4,$5,21000,1,1,$6,$7)`, strings.ToLower(tx.Hash().Hex()), i, strings.ToLower(sender.Hex()), strings.ToLower(target.Hex()), tx.Value().String(), "0x"+common.Bytes2Hex(tx.Data()), int64(tx.Nonce()))
		if err != nil {
			t.Fatal(err)
		}
	}
	explorer, err := rpcengine.NewExplorer(rpcengine.ExplorerConfig{Snapshot: snapshot, History: history, State: stateEngine, Metadata: metadata, Index: index, IndexExpected: binding, CursorKey: bytes.Repeat([]byte{13}, 32), PseudonymKey: bytes.Repeat([]byte{14}, 32)})
	if err != nil {
		t.Fatal("concrete Explorer constructor", err)
	}
	methods := append(history.OperationBinding().Methods, metadata.OperationBinding().Methods...)
	methods = append(methods, stateEngine.OperationBinding().Methods...)
	methods = append(methods, activitymethoddata.ExplorerLabels()...)
	entered, release := make(chan struct{}), make(chan struct{})
	var sealCount atomic.Int32
	recorder := rpcRecorder(t, activity, clock, func(uint64) error {
		if sealCount.Add(1) == 1 {
			close(entered)
			<-release
		}
		return nil
	}, methods...)
	service, err := rpcactivity.New(rpcactivity.Config{History: history, State: stateEngine, Metadata: metadata, Explorer: explorer, Recorder: recorder, Network: network})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := service.ExplorerHandler(f.Org)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	type result struct {
		status int
		body   []byte
		err    error
	}
	get := func(path string) <-chan result {
		done := make(chan result, 1)
		go func() {
			req, _ := http.NewRequestWithContext(t.Context(), "GET", server.URL+path, nil)
			req.Header.Set("Authorization", "Bearer "+tok)
			response, err := server.Client().Do(req)
			if err != nil {
				done <- result{err: err}
				return
			}
			defer response.Body.Close()
			raw, err := io.ReadAll(response.Body)
			done <- result{response.StatusCode, raw, err}
		}()
		return done
	}
	pending := get("/api/v2/explorer/transactions?limit=1")
	await(t, entered)
	select {
	case r := <-pending:
		t.Fatal("Explorer bytes before synced Append", r)
	default:
	}
	busy := <-get("/api/v2/explorer/chain-id")
	if busy.status != 503 {
		t.Fatal("REST escaped same N limiter", busy.status, string(busy.body))
	}
	close(release)
	first := <-pending
	if first.err != nil || first.status != 200 {
		t.Fatal("actual Explorer flow", first.err, first.status, string(first.body))
	}
	var page struct {
		Items []struct {
			Hash  string
			Value *string
		}
		Page struct {
			Next        string
			HasMore     *bool
			ScanLimited bool
		}
	}
	if json.Unmarshal(first.body, &page) != nil || len(page.Items) != 1 || page.Items[0].Hash != strings.ToLower(txs[1].Hash().Hex()) || page.Items[0].Value == nil || *page.Items[0].Value != "7" || page.Page.Next == "" {
		t.Fatal("lossless genuine listed row and continuation", string(first.body))
	}
	next := <-get("/api/v2/explorer/transactions?limit=1&cursor=" + url.QueryEscape(page.Page.Next))
	if next.status != 200 || !bytes.Contains(next.body, []byte(strings.ToLower(txs[0].Hash().Hex()))) {
		t.Fatal("actual current wallet row next", next.status, string(next.body))
	}
	// The same cursor is bound to the original JWT and the captured upper.
	node.Reorg(true)
	changed := <-get("/api/v2/explorer/transactions?limit=1&cursor=" + url.QueryEscape(page.Page.Next))
	if changed.status == 200 {
		t.Fatal("reorg published protected indexed row", string(changed.body))
	}
	node.Reorg(false)
}

func actualExplorerIndex(t *testing.T, root *pgx.Conn, ownerDSN string, network networkidentity.Binding) (*explorerindex.Reader, *pgx.Conn, explorerquery.Binding) {
	t.Helper()
	ctx := t.Context()
	if _, err := root.Exec(ctx, `CREATE DATABASE explorer_http_test`); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(ownerDSN)
	u.Path = "/explorer_http_test"
	owner, err := pgx.Connect(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close(context.Background()) })
	schema, err := os.ReadFile("../operational/explorerindex/testdata/existing-indexer.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = owner.Exec(ctx, string(schema)); err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{`CREATE ROLE explorer_http_reader LOGIN NOINHERIT PASSWORD 'public-test-only'`, `REVOKE CREATE ON SCHEMA public FROM PUBLIC`, `GRANT USAGE ON SCHEMA public TO explorer_http_reader`} {
		if _, err = owner.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile("../operational/explorerindex/schema-columns.json")
	if err != nil {
		t.Fatal(err)
	}
	var catalog struct {
		Tables []struct {
			Name    string
			Columns []struct {
				Name   string
				Select bool
			}
		}
	}
	if json.Unmarshal(raw, &catalog) != nil {
		t.Fatal("fixture catalog")
	}
	for _, table := range catalog.Tables {
		columns := []string{}
		for _, c := range table.Columns {
			if c.Select {
				columns = append(columns, pgx.Identifier{c.Name}.Sanitize())
			}
		}
		if _, err = owner.Exec(ctx, "GRANT SELECT("+strings.Join(columns, ",")+") ON public."+pgx.Identifier{table.Name}.Sanitize()+" TO explorer_http_reader"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = owner.Exec(ctx, `INSERT INTO blocks(number,hash,parent_hash,timestamp,gas_used,gas_limit,transaction_count)VALUES(1,$1,$2,$3,42000,30000000,2)`, network.GenesisHash, network.GenesisHash, f.Now); err != nil {
		t.Fatal(err)
	}
	// Caller replaces the selected actual upper with its node hash before querying.
	u.User = url.UserPassword("explorer_http_reader", "public-test-only")
	reference, err := explorerindex.ConnectionReference(u.String())
	if err != nil {
		t.Fatal(err)
	}
	binding := explorerquery.Binding{Network: network, SourceReference: reference, SchemaDigest: explorerindex.SchemaDigest(), ConfiguredEpoch: uuid.NewString()}
	reader, err := explorerindex.OpenReader(ctx, u.String(), binding, explorerindex.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reader.Close)
	return reader, owner, binding
}
