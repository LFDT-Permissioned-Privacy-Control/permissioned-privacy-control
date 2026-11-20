package explorerindex_test

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"privacy-proxy/internal/admissionsharedata"
	q "privacy-proxy/internal/explorerquery"
	"privacy-proxy/internal/indexertest"
	"privacy-proxy/internal/networkidentity"
	x "privacy-proxy/internal/operational/explorerindex"
)

func actualReader(t *testing.T) (*x.Reader, *pgx.Conn, networkidentity.Binding) {
	t.Helper()
	indexertest.Require(t)
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	name := "ops-typed-indexer-test-" + uuid.NewString()[:8]
	out, e := exec.CommandContext(ctx, "docker", "run", "--rm", "--pull", "never", "--detach", "--publish", "127.0.0.1::5432", "--env", "POSTGRES_PASSWORD=typed-test-only", "--env", "POSTGRES_DB=typed", "--name", name, "postgres:16-alpine").CombinedOutput()
	if e != nil {
		t.Fatalf("ownedtestpostgres: %v %s", e, out)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		_ = exec.CommandContext(cleanup, "docker", "rm", "--force", name).Run()
	})
	out, e = exec.CommandContext(ctx, "docker", "port", name, "5432/tcp").Output()
	if e != nil {
		t.Fatal(e)
	}
	dsn := "postgres://postgres:typed-test-only@" + strings.TrimSpace(string(out)) + "/typed?sslmode=disable"
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	var owner *pgx.Conn
	for ctx.Err() == nil {
		owner, e = pgx.ConnectConfig(ctx, config.Copy())
		if e == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if e != nil {
		t.Fatal("postgresnotready")
	}
	t.Cleanup(func() { _ = owner.Close(context.Background()) })
	network := networkidentity.Binding{Environment: "test", ChainID: "31337", GenesisHash: fmt.Sprintf("0x%064x", 100), DeploymentID: "typed-client-tests"}
	indexertest.Schema(t, owner, network)
	_, e = owner.Exec(t.Context(), `INSERT INTO blocks(number,hash,parent_hash,timestamp,gas_used,gas_limit,transaction_count) VALUES(0,$1,$2,1,0,30000000,0),(1,$3,$1,5,0,30000000,0),(2,$4,$3,10,63000,30000000,3);UPDATE sync_status SET last_indexed_block=2`, network.GenesisHash, fmt.Sprintf("0x%064x", 0), fmt.Sprintf("0x%064x", 101), fmt.Sprintf("0x%064x", 102))
	if e != nil {
		t.Fatal(e)
	}
	_, e = owner.Exec(t.Context(), `INSERT INTO transactions(hash,block_number,block_timestamp,tx_index,from_address,to_address,value,gas_used,gas_price,status,input_data) SELECT '0x'||lpad(to_hex(1000+n),64,'0'),2,10,n,'0x1111111111111111111111111111111111111111','0x2222222222222222222222222222222222222222',1,21000,1,1,'0x' FROM generate_series(0,2)n`)
	if e != nil {
		t.Fatal(e)
	}
	// The producer owns this SQL credential; OPS receives its gRPC endpoint only.
	parsed, _ := url.Parse(dsn)
	parsed.User = url.UserPassword("postgres", "typed-test-only")
	reader, _ := indexertest.Open(t, parsed.String(), network)
	return reader, owner, network
}
func typedQuery(t *testing.T, f q.Family) q.Query {
	t.Helper()
	fence, e := admissionsharedata.NewFence(t.Context(), 5*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	return q.Query{Family: f, RawLimit: 1, Fence: fence}
}
func TestActualTokenSearchTraversesMatchingPages(t *testing.T) {
	reader, owner, _ := actualReader(t)
	_, e := owner.Exec(t.Context(), `INSERT INTO tokens(address,symbol,name,decimals,token_type,block_number) VALUES
	('0x1111111111111111111111111111111111111111','ALP','Alpha Bank',18,'ERC20',2),
	('0x2222222222222222222222222222222222222222','BET','Beta Bank',18,'ERC20',2),
	('0x3333333333333333333333333333333333333333','AL2','Alpha Credit',18,'ERC20',2)`)
	if e != nil {
		t.Fatal(e)
	}
	query := typedQuery(t, q.Tokens)
	query.Search = "Alpha"
	var got []string
	for page := 0; page < 5; page++ {
		pass, e := reader.ReadCohort(t.Context(), query)
		if e != nil {
			t.Fatal(e)
		}
		data := pass.Data()
		pass.Close()
		for _, row := range data.Rows {
			got = append(got, row.Position.Hash)
		}
		if data.Next == nil {
			break
		}
		query.Upper, query.After, query.DatasetEpoch = data.Upper, data.Next, data.DatasetEpoch
		floor := data.RunFloor
		query.RunFloor = &floor
	}
	if len(got) != 2 || got[0] == got[1] || strings.Contains(strings.Join(got, ","), "2222222222222222222222222222222222222222") {
		t.Fatalf("search skipped/repeated/unfiltered token: %v", got)
	}
}
func TestActualTypedV2ClientSnapshotKeysCurrentnessProtectedAndChildFallback(t *testing.T) {
	reader, owner, _ := actualReader(t)
	t.Run("pinned_snapshot_unique_keys_and_epoch_delivery", func(t *testing.T) {
		query := typedQuery(t, q.Transactions)
		first, e := reader.ReadCohort(t.Context(), query)
		if e != nil {
			t.Fatal(e)
		}
		defer first.Close()
		d := first.Data()
		if len(d.Rows) != 1 || d.Next == nil || d.DatasetEpoch == "" || d.Upper.Number != 2 || d.RunFloor != 0 {
			t.Fatalf("invalidfirstsnapshot:%+v", d)
		}
		_, e = owner.Exec(t.Context(), `INSERT INTO blocks(number,hash,parent_hash,timestamp,gas_used,gas_limit,transaction_count)VALUES(3,$1,$2,15,1,30000000,1);INSERT INTO transactions(hash,block_number,block_timestamp,tx_index,from_address,value,gas_used,gas_price,status,input_data)VALUES($3,3,15,0,'0x1111111111111111111111111111111111111111',1,1,1,1,'0x');UPDATE sync_status SET last_indexed_block=3`, fmt.Sprintf("0x%064x", 103), fmt.Sprintf("0x%064x", 102), fmt.Sprintf("0x%064x", 2000))
		if e != nil {
			t.Fatal(e)
		}
		query.Upper = d.Upper
		query.DatasetEpoch = d.DatasetEpoch
		floor := d.RunFloor
		query.RunFloor = &floor
		pos := d.Rows[0].Position
		query.After = &pos
		second, e := reader.ReadCohort(t.Context(), query)
		if e != nil {
			t.Fatal(e)
		}
		defer second.Close()
		if second.Data().Rows[0].Position.Block != 2 || second.Data().Rows[0].Position == pos {
			t.Fatal("resumereturnednewheadorrepeatedkey")
		}
		if e = reader.Recheck(t.Context(), first); e != nil {
			t.Fatal(e)
		}
		_, e = owner.Exec(t.Context(), `UPDATE indexer_dataset_metadata SET dataset_epoch=$1 WHERE id=1`, uuid.NewString())
		if e != nil {
			t.Fatal(e)
		}
		if !errors.Is(reader.Recheck(t.Context(), first), q.ErrConflict) {
			t.Fatal("datasetreplacementnotdetected")
		}
	})
	t.Run("current_label_and_pruned_cursor_reason", func(t *testing.T) {
		_, e := owner.Exec(t.Context(), `INSERT INTO tokens(address,symbol,decimals,token_type,block_number)VALUES('0x2222222222222222222222222222222222222222','TST',18,'ERC20',2)`)
		if e != nil {
			t.Fatal(e)
		}
		pass, e := reader.ReadCohort(t.Context(), typedQuery(t, q.Tokens))
		if e != nil {
			t.Fatal(e)
		}
		defer pass.Close()
		if pass.Data().Consistency != "CURRENT" {
			t.Fatal("mutablefactslabelledsnapshot")
		}
		d := pass.Data()
		_, e = owner.Exec(t.Context(), `UPDATE prune_state SET pruned_through=1`)
		if e != nil {
			t.Fatal(e)
		}
		query := typedQuery(t, q.Blocks)
		query.Upper = d.Upper
		query.DatasetEpoch = d.DatasetEpoch
		floor := d.RunFloor
		query.RunFloor = &floor
		query.After = &q.Position{Block: 1}
		if _, e = reader.ReadCohort(t.Context(), query); !errors.Is(e, q.ErrPruned) {
			t.Fatal("prunedcursorreasonlost", e)
		}
		_, _ = owner.Exec(t.Context(), `UPDATE prune_state SET pruned_through=0`)
	})
	t.Run("protected_exact_current_destinations_rechecked", func(t *testing.T) {
		a := [20]byte{}
		b := [20]byte{}
		for i := range a {
			a[i] = 0x11
			b[i] = 0x22
		}
		read, e := reader.BeginProtected(t.Context(), q.ProtectedSelection{Expected: reader.Metadata(), Targets: [][20]byte{a}, FromNumber: 0, ThroughNumber: 3, FromTime: 0, ThroughTime: 20})
		if e != nil {
			t.Fatal(e)
		}
		defer read.Close()
		dest, e := read.ReadDestinations(t.Context())
		if e != nil || len(dest.Addresses) != 1 || dest.Addresses[0] != b {
			t.Fatal(dest, e)
		}
		pred := q.ProtectedPredicate{Intervals: []q.ProtectedInterval{{Address: b, FromNumber: 0, BeforeNumber: 4}}}
		w, e := read.ReadWitnesses(t.Context(), pred)
		if e != nil || len(w) != 1 || w[0].Address != a {
			t.Fatal(w, e)
		}
		rows, end, e := read.ReadTransactions(t.Context(), pred, q.ProtectedTransactionQuery{Limit: 100})
		if e != nil || len(rows) != 3 || !end {
			t.Fatal(len(rows), end, e)
		}
		if e = read.Recheck(t.Context()); e != nil {
			t.Fatal(e)
		}
		_, e = owner.Exec(t.Context(), `INSERT INTO transactions(hash,block_number,block_timestamp,tx_index,from_address,to_address,value,gas_used,gas_price,status,input_data)VALUES($1,2,10,8,'0x1111111111111111111111111111111111111111','0x3333333333333333333333333333333333333333',1,1,1,1,'0x')`, fmt.Sprintf("0x%064x", 3000))
		if e != nil {
			t.Fatal(e)
		}
		if !errors.Is(read.Recheck(t.Context()), q.ErrConflict) {
			t.Fatal("currentdestinationschangedwithoutconflict")
		}
	})
	t.Run("child_overflow_keeps_parent_only_lookup_and_requested_child_page_reachable", func(t *testing.T) {
		parent := fmt.Sprintf("0x%064x", 1000)
		_, e := owner.Exec(t.Context(), `INSERT INTO internal_transactions(tx_hash,block_number,trace_address,from_address,to_address,value,call_type,timestamp) SELECT $1,2,n::text,'0x1111111111111111111111111111111111111111','0x2222222222222222222222222222222222222222',1,'call',10 FROM generate_series(1,20001)n`, parent)
		if e != nil {
			t.Fatal(e)
		}
		query := typedQuery(t, q.Internals)
		query.Hash = parent
		pass, e := reader.ReadCohort(t.Context(), query)
		if e != nil {
			t.Fatal("requestedchildpageunreachableafterbundlecap", e)
		}
		defer pass.Close()
		d := pass.Data()
		if len(d.Rows) != 1 || len(d.Context) != 1 || d.Context[0].Family != q.Transactions || d.Next == nil {
			t.Fatal("parentfallbackwaspartialorcopiedunusedsiblings", len(d.Rows), len(d.Context))
		}
	})
}

func TestActualProtectedResultRowsShareOriginalLedger(t *testing.T) {
	_, owner, network := actualReader(t)
	for _, kind := range []string{"witness", "transactions", "recheck"} {
		t.Run(kind, func(t *testing.T) {
			limits := x.DefaultLimits()
			limits.MaxResultRows = 1
			if kind == "recheck" {
				limits.MaxResultRows = 2
			}
			reader, _ := indexertest.OpenWithLimits(t, owner.Config().ConnString(), network, limits)
			var target, destination [20]byte
			for i := range target {
				target[i] = 0x11
				destination[i] = 0x22
			}
			read, e := reader.BeginProtected(t.Context(), q.ProtectedSelection{Expected: reader.Metadata(), Targets: [][20]byte{target}, FromNumber: 0, ThroughNumber: 2, FromTime: 0, ThroughTime: 20})
			if e != nil {
				t.Fatal(e)
			}
			defer read.Close()
			got, e := read.ReadDestinations(t.Context())
			if e != nil || len(got.Addresses) != 1 {
				t.Fatal(got, e)
			}
			predicate := q.ProtectedPredicate{Intervals: []q.ProtectedInterval{{Address: destination, FromNumber: 0, BeforeNumber: 3}}}
			switch kind {
			case "witness":
				rows, err := read.ReadWitnesses(t.Context(), predicate)
				if !errors.Is(err, q.ErrTooBroad) || rows != nil {
					t.Fatal("witness renewed original result-row budget", rows, err)
				}
			case "transactions":
				rows, _, err := read.ReadTransactions(t.Context(), predicate, q.ProtectedTransactionQuery{Limit: 1})
				if !errors.Is(err, q.ErrTooBroad) || rows != nil {
					t.Fatal("transaction page renewed original result-row budget", rows, err)
				}
			case "recheck":
				if e = read.Recheck(t.Context()); e != nil {
					t.Fatal("second original row should fit", e)
				}
				if e = read.Recheck(t.Context()); !errors.Is(e, q.ErrTooBroad) {
					t.Fatal("CURRENT destinations recheck renewed row budget", e)
				}
			}
			if e = read.Recheck(context.Background()); e == nil {
				t.Fatal("fresh caller renewed exhausted protected purpose")
			}
		})
	}
}

func TestActualTransferKindMatchesBeforePageAdmission(t *testing.T) {
	reader, owner, _ := actualReader(t)
	_, e := owner.Exec(t.Context(), `INSERT INTO token_transfers(tx_hash,log_index,token_address,from_address,to_address,value,block_number,token_type) SELECT '0x'||lpad(to_hex(1000),64,'0'),n,'0x1111111111111111111111111111111111111111','0x1111111111111111111111111111111111111111','0x2222222222222222222222222222222222222222',1,2,CASE WHEN n%2=0 THEN 'ERC20' ELSE 'ERC721' END FROM generate_series(0,9)n`)
	if e != nil {
		t.Fatal(e)
	}
	query := typedQuery(t, q.Transfers)
	query.TokenKind = q.TokenKindERC20
	seen := map[uint32]bool{}
	for n := 0; n < 10; n++ {
		pass, e := reader.ReadCohort(t.Context(), query)
		if e != nil {
			t.Fatal(e)
		}
		d := pass.Data()
		pass.Close()
		for _, r := range d.Rows {
			if r.Position.Index%2 != 0 || seen[r.Position.Index] {
				t.Fatalf("wrong/repeated typed row: %s", r.JSON)
			}
			seen[r.Position.Index] = true
		}
		if d.Next == nil {
			break
		}
		query.Upper, query.After, query.DatasetEpoch = d.Upper, d.Next, d.DatasetEpoch
		floor := d.RunFloor
		query.RunFloor = &floor
	}
	if len(seen) != 5 {
		t.Fatalf("source filter lost later matches: %v", seen)
	}
}
