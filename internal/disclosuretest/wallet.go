package disclosuretest

// This finite fixture borrows an owned test PostgreSQL server. No production
// command imports disclosuretest. Links cross the actual operational proof
// service and restricted SQL reader; the fixture supplies no ownership verdict.
import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/networkidentity"
	"privacy-proxy/internal/operational/walletsql"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/walletadapter"
	"privacy-proxy/internal/walletops"
	"privacy-proxy/internal/walletproof"
)

type WalletFixture struct {
	Binding   walletops.ServiceBinding
	State     walletops.ExpectedState
	Namespace walletops.Namespace
	Resolver  *walletadapter.Resolver
	Service   *walletops.Service
	Owner     *pgx.Conn
}

func ActualWalletFixture(t testing.TB, ctx context.Context, dsn string, snapshot *policybundle.CatalogSnapshot, network networkidentity.Binding, clock identity.Clock) *WalletFixture {
	t.Helper()
	owner, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close(context.Background()) })
	for _, role := range []string{"state_wallet_app", "state_wallet_reader", "state_wallet_retention"} {
		if _, err := owner.Exec(ctx, `CREATE ROLE `+role+` LOGIN NOINHERIT PASSWORD 'state-wallet-test-only'`); err != nil {
			t.Fatal(err)
		}
	}
	if err := walletsql.Migrate(ctx, dsn, "state_wallet_app", "state_wallet_reader", "state_wallet_retention"); err != nil {
		t.Fatal(err)
	}
	b := walletops.ServiceBinding{ServiceOrigin: "https://ops.test", Environment: network.Environment, ChainID: network.ChainID, GenesisHash: network.GenesisHash, DeploymentID: network.DeploymentID}
	state := walletops.ExpectedState{Generation: uuid.NewString(), Coverage: walletsql.EmptyCoverage()}
	ns, err := b.Namespace()
	if err != nil {
		t.Fatal(err)
	}
	if err := walletsql.BootstrapEmpty(ctx, dsn, b, state.Generation); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(dsn)
	u.User = url.UserPassword("state_wallet_app", "state-wallet-test-only")
	app, err := walletsql.Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Close)
	u.User = url.UserPassword("state_wallet_reader", "state-wallet-test-only")
	reader, err := walletsql.OpenReader(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reader.Close)
	resolver, err := walletadapter.New(reader, ns, state, clock)
	if err != nil {
		t.Fatal(err)
	}
	service, err := walletops.New(walletops.Config{Snapshot: snapshot, Clock: clock, Binding: b, State: state, Store: app})
	if err != nil {
		t.Fatal(err)
	}
	return &WalletFixture{b, state, ns, resolver, service, owner}
}
func (f *WalletFixture) Link(t testing.TB, ctx context.Context, token string, key *ecdsa.PrivateKey) common.Address {
	t.Helper()
	address := crypto.PubkeyToAddress(key.PublicKey)
	response, err := f.Service.Issue(ctx, token, walletops.ChallengeRequest{Address: address.Hex()})
	if err != nil {
		t.Fatal("actual issue", err)
	}
	var body bytes.Buffer
	if _, err := response.WriteTo(&body); err != nil {
		t.Fatal(err)
	}
	var challenge walletops.ChallengeResult
	if json.Unmarshal(body.Bytes(), &challenge) != nil {
		t.Fatal("actual challenge")
	}
	signature, err := crypto.Sign(walletproof.HashMessage(challenge.Message), key)
	if err != nil {
		t.Fatal(err)
	}
	response, err = f.Service.Verify(ctx, token, walletops.VerifyRequest{Address: address.Hex(), Nonce: challenge.Nonce, Signature: "0x" + hex.EncodeToString(signature)})
	if err != nil {
		t.Fatal("actual verify", err)
	}
	body.Reset()
	if _, err := response.WriteTo(&body); err != nil {
		t.Fatal(err)
	}
	return address
}
