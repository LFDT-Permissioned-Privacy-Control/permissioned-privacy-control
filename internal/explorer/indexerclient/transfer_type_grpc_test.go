package indexerclient

// Actual producer migrations and real TCP gRPC prove that the vendored V1
// service/enum/page schema interoperates with the authoritative Indexer.
import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"math"
	"net"
	"net/url"
	"os"
	"os/exec"
	pb "privacy-proxy/gen/go/chain_indexer/v1"
	"privacy-proxy/internal/explorer"
	"privacy-proxy/internal/indexertest"
	"privacy-proxy/internal/networkidentity"
	"strings"
	"testing"
	"time"
)

func TestActualLegacyTypedTransfersAuthoritativeGRPC(t *testing.T) {
	indexertest.Require(t)
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	name := "ops-v1-transfer-test-" + uuid.NewString()[:8]
	out, e := exec.CommandContext(ctx, "docker", "run", "--rm", "--pull", "never", "--detach", "--publish", "127.0.0.1::5432", "--env", "POSTGRES_PASSWORD=typed-test-only", "--env", "POSTGRES_DB=typed", "--name", name, "postgres:16-alpine").CombinedOutput()
	if e != nil {
		t.Fatalf("owned fixture: %v %s", e, out)
	}
	t.Cleanup(func() {
		c, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		_ = exec.CommandContext(c, "docker", "rm", "--force", name).Run()
	})
	out, e = exec.CommandContext(ctx, "docker", "port", name, "5432/tcp").Output()
	if e != nil {
		t.Fatal(e)
	}
	dsn := "postgres://postgres:typed-test-only@" + strings.TrimSpace(string(out)) + "/typed?sslmode=disable"
	var owner *pgx.Conn
	for ctx.Err() == nil {
		config, err := pgx.ParseConfig(dsn)
		if err != nil {
			t.Fatal(err)
		}
		config.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
		owner, e = pgx.ConnectConfig(ctx, config)
		if e == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if e != nil {
		t.Fatal(e)
	}
	defer owner.Close(context.Background())
	network := networkidentity.Binding{Environment: "test", ChainID: "31337", GenesisHash: fmt.Sprintf("0x%064x", 100), DeploymentID: "legacy-filter"}
	indexertest.Schema(t, owner, network)
	_, e = owner.Exec(ctx, `INSERT INTO blocks(number,hash,parent_hash,timestamp,gas_used,gas_limit,transaction_count) VALUES(0,$1,$2,1,0,30000000,0),(1,$3,$1,5,0,30000000,1);UPDATE sync_status SET last_indexed_block=1`, network.GenesisHash, fmt.Sprintf("0x%064x", 0), fmt.Sprintf("0x%064x", 101))
	if e != nil {
		t.Fatal(e)
	}
	_, e = owner.Exec(ctx, `INSERT INTO token_transfers(tx_hash,log_index,token_address,from_address,to_address,value,block_number,token_type) SELECT '0x'||lpad('1234',64,'0'),n,'0x1111111111111111111111111111111111111111','0x1111111111111111111111111111111111111111','0x2222222222222222222222222222222222222222',1,1,CASE WHEN n%2=0 THEN 'ERC20' ELSE 'ERC721' END FROM generate_series(0,9)n`)
	if e != nil {
		t.Fatal(e)
	}
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	target := listener.Addr().String()
	_ = listener.Close()
	cmd := exec.Command(os.Getenv("OPS_TEST_INDEXED_READ_SERVER"))
	cmd.Env = append(os.Environ(), "INDEXER_FIXTURE_DSN="+dsn, "INDEXER_FIXTURE_LISTEN_ADDR="+target)
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	conn, e := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithDefaultCallOptions(grpc.WaitForReady(true)))
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	backend := &Backend{client: pb.NewIndexerServiceClient(conn)}
	for _, kind := range []string{"ERC20", "ERC721"} {
		var got []int
		for _, offset := range []int{0, 2, 4} {
			rows, total, e := backend.GetAllTransfersByType(ctx, 2, offset, kind)
			if e != nil || total != 5 {
				t.Fatal(kind, total, e)
			}
			for _, row := range rows {
				if row.TokenType != kind {
					t.Fatal("wrong standard", row)
				}
				got = append(got, row.LogIndex)
			}
		}
		if len(got) != 5 || got[0] <= got[4] {
			t.Fatal("typed rows missing beyond first page", got)
		}
	}
	for _, input := range []struct {
		l, o int
		k    string
	}{{2, 1, "ERC20"}, {2, 0, "ERC777"}, {0, 0, "ERC20"}, {1, math.MaxInt, "ERC20"}, {1, math.MaxInt32, "ERC20"}} {
		if _, _, e = backend.GetAllTransfersByType(ctx, input.l, input.o, input.k); e != explorer.ErrTransferTypeUnsupported {
			t.Fatal("unsupported page/type not rejected", input, e)
		}
	}
	// The source owns the credential; the consumer serving path gets only RPC.
	if u, _ := url.Parse(dsn); u.Path != "/typed" {
		t.Fatal("unexpected fixture database")
	}
}
