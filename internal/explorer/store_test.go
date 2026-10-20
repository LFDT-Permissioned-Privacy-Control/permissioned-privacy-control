package explorer

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestBuildTxCategories(t *testing.T) {
	tests := []struct {
		name               string
		isCoinTransfer     bool
		isContractCall     bool
		isContractCreation bool
		tokenTransferCount int
		want               []string
	}{
		{
			name: "all false zero transfers",
			want: nil,
		},
		{
			name:           "coin transfer only",
			isCoinTransfer: true,
			want:           []string{"coin_transfer"},
		},
		{
			name:               "token transfer supersedes coin transfer",
			isCoinTransfer:     true,
			tokenTransferCount: 1,
			want:               []string{"token_transfer"},
		},
		{
			name:           "contract call only",
			isContractCall: true,
			want:           []string{"contract_call"},
		},
		{
			name:               "contract creation only",
			isContractCreation: true,
			want:               []string{"contract_creation"},
		},
		{
			name:               "contract creation and coin transfer",
			isContractCreation: true,
			isCoinTransfer:     true,
			want:               []string{"contract_creation", "coin_transfer"},
		},
		{
			name:               "contract call with token transfers",
			isContractCall:     true,
			tokenTransferCount: 2,
			want:               []string{"contract_call", "token_transfer"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildTxCategories(tt.isCoinTransfer, tt.isContractCall, tt.isContractCreation, tt.tokenTransferCount)
			if len(got) != len(tt.want) {
				t.Fatalf("buildTxCategories() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("buildTxCategories()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// setupTestContainer starts a PostgreSQL testcontainer for integration tests.
// This is a local copy to avoid an import cycle with privacy-proxy/internal/db.
func setupTestContainer(t *testing.T) (string, func()) {
	t.Helper()
	ctx := context.Background()

	postgresContainer, err := postgres.RunContainer(ctx,
		testcontainers.WithImage("postgres:15-alpine"),
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpass"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("failed to start postgres container: %v (is Docker running?)", err)
	}

	connStr, err := postgresContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		postgresContainer.Terminate(ctx)
		t.Fatalf("failed to get connection string: %v", err)
	}

	cleanup := func() {
		if err := postgresContainer.Terminate(ctx); err != nil {
			t.Logf("failed to terminate container: %v", err)
		}
	}
	return connStr, cleanup
}

// setupExplorerSchema creates the minimal explorer tables needed for category tests.
func setupExplorerSchema(t *testing.T, sqlDB *sql.DB) {
	t.Helper()
	schema := `
		CREATE TABLE IF NOT EXISTS blocks (
			number BIGINT PRIMARY KEY,
			hash TEXT NOT NULL UNIQUE,
			parent_hash TEXT NOT NULL,
			timestamp BIGINT NOT NULL,
			gas_used BIGINT NOT NULL,
			gas_limit BIGINT NOT NULL,
			base_fee_per_gas BIGINT,
			transaction_count INT NOT NULL,
			size BIGINT DEFAULT 0,
			difficulty TEXT DEFAULT '0',
			total_difficulty TEXT DEFAULT '0',
			nonce TEXT DEFAULT '0x0000000000000000',
			miner TEXT,
			extra_data TEXT,
			state_root TEXT,
			transactions_root TEXT,
			receipts_root TEXT,
			created_at TIMESTAMP DEFAULT NOW()
		);

		CREATE TABLE IF NOT EXISTS transactions (
			hash TEXT PRIMARY KEY,
			block_number BIGINT NOT NULL REFERENCES blocks(number) ON DELETE CASCADE,
			tx_index INT NOT NULL,
			from_address TEXT NOT NULL,
			to_address TEXT,
			value NUMERIC(78, 0) NOT NULL,
			gas_used BIGINT NOT NULL,
			gas_price BIGINT NOT NULL,
			gas_limit BIGINT,
			max_fee_per_gas BIGINT,
			max_priority_fee_per_gas BIGINT,
			nonce BIGINT,
			tx_type SMALLINT DEFAULT 0,
			input_data TEXT,
			status SMALLINT NOT NULL,
			error TEXT,
			revert_reason TEXT,
			created_at TIMESTAMP DEFAULT NOW()
		);

		CREATE TABLE IF NOT EXISTS contracts (
			address TEXT PRIMARY KEY,
			creation_tx TEXT REFERENCES transactions(hash),
			creator_address TEXT,
			bytecode TEXT,
			abi JSONB,
			name TEXT,
			compiler_version TEXT,
			optimization_used BOOLEAN,
			source_code TEXT,
			verified BOOLEAN DEFAULT false,
			created_at TIMESTAMP DEFAULT NOW()
		);

		CREATE TABLE IF NOT EXISTS token_transfers (
			id SERIAL PRIMARY KEY,
			tx_hash TEXT NOT NULL REFERENCES transactions(hash) ON DELETE CASCADE,
			log_index INT NOT NULL,
			token_address TEXT NOT NULL,
			from_address TEXT NOT NULL,
			to_address TEXT NOT NULL,
			value NUMERIC(78, 0) NOT NULL,
			block_number BIGINT NOT NULL,
			timestamp BIGINT,
			transfer_type TEXT DEFAULT 'transfer',
			token_type TEXT DEFAULT 'ERC20',
			token_id NUMERIC(78, 0),
			is_internal BOOLEAN DEFAULT false,
			UNIQUE(tx_hash, log_index)
		);
	`
	_, err := sqlDB.ExecContext(context.Background(), schema)
	if err != nil {
		t.Fatalf("failed to create explorer schema: %v", err)
	}
}

// insertTestFixtures inserts a block with 3 transactions covering each category type.
//
// tx1: plain coin transfer (value > 0, to an EOA, no input data, no token transfers)
// tx2: ERC20 transfer via contract call (value=0, to a contract, has input_data, 1 token transfer)
// tx3: contract deployment (to_address IS NULL, value=0)
func insertTestFixtures(t *testing.T, sqlDB *sql.DB) {
	t.Helper()
	ctx := context.Background()

	// Insert a block.
	_, err := sqlDB.ExecContext(ctx, `
		INSERT INTO blocks (number, hash, parent_hash, timestamp, gas_used, gas_limit, transaction_count)
		VALUES (1, '0xblockhash1', '0xparent0', 1000, 21000, 30000000, 3)`)
	if err != nil {
		t.Fatalf("insert block: %v", err)
	}

	// tx1: coin transfer to an EOA (not in contracts table).
	_, err = sqlDB.ExecContext(ctx, `
		INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, input_data, status)
		VALUES ('0xtx1', 1, 0, '0xsender1', '0xrecipient1', 1000, 21000, 1000000000, '0x', 1)`)
	if err != nil {
		t.Fatalf("insert tx1: %v", err)
	}

	// tx2: ERC20 transfer — to_address is a contract, has input data, has a token transfer row.
	contractAddr := "0xtoken_contract"
	_, err = sqlDB.ExecContext(ctx, `
		INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, input_data, status)
		VALUES ('0xtx2', 1, 1, '0xsender2', $1, 0, 50000, 1000000000, '0xa9059cbb0000000000000000000000000000000000000001', 1)`,
		contractAddr)
	if err != nil {
		t.Fatalf("insert tx2: %v", err)
	}

	// Register the contract so the EXISTS subquery matches.
	_, err = sqlDB.ExecContext(ctx, `
		INSERT INTO contracts (address, creation_tx) VALUES ($1, '0xtx2')`, contractAddr)
	if err != nil {
		t.Fatalf("insert contract: %v", err)
	}

	// Add a token transfer for tx2.
	_, err = sqlDB.ExecContext(ctx, `
		INSERT INTO token_transfers (tx_hash, log_index, token_address, from_address, to_address, value, block_number)
		VALUES ('0xtx2', 0, $1, '0xsender2', '0xrecipient_token', 500, 1)`, contractAddr)
	if err != nil {
		t.Fatalf("insert token_transfer: %v", err)
	}

	// tx3: contract deployment (to_address IS NULL).
	_, err = sqlDB.ExecContext(ctx, `
		INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, input_data, status)
		VALUES ('0xtx3', 1, 2, '0xdeployer', NULL, 0, 100000, 1000000000, '0x6080604052', 1)`)
	if err != nil {
		t.Fatalf("insert tx3: %v", err)
	}
}

// This test exists specifically to catch the regression where populateCategories
// silently queried a non-existent tx_categories table, returning nil for all categories.

func TestGetTransactionsPaginatedWithCategories(t *testing.T) {
	dbURL, cleanup := setupTestContainer(t)
	defer cleanup()

	sqlDB, err := sql.Open("pgx", dbURL)
	if err != nil {
		t.Fatalf("open sql db: %v", err)
	}
	defer sqlDB.Close()

	setupExplorerSchema(t, sqlDB)
	insertTestFixtures(t, sqlDB)

	store, err := NewStore(dbURL)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	txs, total, err := store.GetTransactionsPaginatedWithCategories(ctx, 1, 10)
	if err != nil {
		t.Fatalf("GetTransactionsPaginatedWithCategories: %v", err)
	}

	if total != 3 {
		t.Errorf("total = %d, want 3", total)
	}
	if len(txs) != 3 {
		t.Fatalf("got %d transactions, want 3", len(txs))
	}

	// Results are ordered by block_number DESC, tx_index DESC, so: tx3, tx2, tx1.
	tx3 := txs[0]
	tx2 := txs[1]
	tx1 := txs[2]

	// tx1: coin transfer
	assertCategories(t, "tx1", tx1.TxCategories, []string{"coin_transfer"})

	// tx2: contract call + token transfer
	assertCategories(t, "tx2", tx2.TxCategories, []string{"contract_call", "token_transfer"})
	if tx2.TokenTransferCount != 1 {
		t.Errorf("tx2 TokenTransferCount = %d, want 1", tx2.TokenTransferCount)
	}

	// tx3: contract creation
	assertCategories(t, "tx3", tx3.TxCategories, []string{"contract_creation"})
}

// TestCountTransactionsFiltered verifies the visibility-aware total is a
// stable, DB-wide COUNT — and, critically, that GetTransactionsPaginatedFiltered
// reports the SAME total on every page (not a page-local len()). This guards
// the RD-1061 fix: the chain-indexer gRPC backend now sources its paginated
// total from this method, so a page-local regression here would resurface the
// "47 on page 1, 70 on page 2, phantom page 3" bug.
func TestCountTransactionsFiltered(t *testing.T) {
	dbURL, cleanup := setupTestContainer(t)
	defer cleanup()

	sqlDB, err := sql.Open("pgx", dbURL)
	if err != nil {
		t.Fatalf("open sql db: %v", err)
	}
	defer sqlDB.Close()

	setupExplorerSchema(t, sqlDB)
	insertTestFixtures(t, sqlDB) // tx1 (0xsender1), tx2 (0xsender2), tx3 (0xdeployer)

	store, err := NewStore(dbURL)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	t.Run("no filter counts all", func(t *testing.T) {
		got, err := store.CountTransactionsFiltered(ctx, nil)
		if err != nil {
			t.Fatalf("CountTransactionsFiltered: %v", err)
		}
		if got != 3 {
			t.Errorf("count = %d, want 3", got)
		}
	})

	t.Run("allowlist counts only visible participants", func(t *testing.T) {
		cases := []struct {
			name    string
			visible []string
			want    int64
		}{
			{"one sender", []string{"0xsender1"}, 1},
			{"two senders", []string{"0xsender1", "0xsender2"}, 2},
			{"none visible (fail closed)", []string{}, 0},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				filter := &VisibilityFilter{AllPrivate: true, VisibleAddresses: tc.visible}
				got, err := store.CountTransactionsFiltered(ctx, filter)
				if err != nil {
					t.Fatalf("CountTransactionsFiltered: %v", err)
				}
				if got != tc.want {
					t.Errorf("count = %d, want %d", got, tc.want)
				}
			})
		}
	})

	t.Run("paginated total is identical across pages", func(t *testing.T) {
		// 3 visible txs, pageSize 2 => 2 pages, but total must read 3 on BOTH.
		_, total1, err := store.GetTransactionsPaginatedFiltered(ctx, 1, 2, nil)
		if err != nil {
			t.Fatalf("page 1: %v", err)
		}
		page2, total2, err := store.GetTransactionsPaginatedFiltered(ctx, 2, 2, nil)
		if err != nil {
			t.Fatalf("page 2: %v", err)
		}
		if total1 != 3 || total2 != 3 {
			t.Errorf("totals = (%d, %d), want (3, 3) — total must be DB-wide, not page-local", total1, total2)
		}
		if len(page2) != 1 {
			t.Errorf("page 2 rows = %d, want 1 (remainder)", len(page2))
		}
	})
}

// This test exists specifically to catch the regression where populateCategories
// silently queried a non-existent tx_categories table, returning nil for all categories.

func TestGetTransactionWithCategories(t *testing.T) {
	dbURL, cleanup := setupTestContainer(t)
	defer cleanup()

	sqlDB, err := sql.Open("pgx", dbURL)
	if err != nil {
		t.Fatalf("open sql db: %v", err)
	}
	defer sqlDB.Close()

	setupExplorerSchema(t, sqlDB)
	insertTestFixtures(t, sqlDB)

	store, err := NewStore(dbURL)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	tx, err := store.GetTransactionWithCategories(ctx, "0xtx2")
	if err != nil {
		t.Fatalf("GetTransactionWithCategories: %v", err)
	}
	if tx == nil {
		t.Fatal("GetTransactionWithCategories returned nil for existing tx")
	}

	assertCategories(t, "tx2", tx.TxCategories, []string{"contract_call", "token_transfer"})
	if tx.TokenTransferCount != 1 {
		t.Errorf("tx2 TokenTransferCount = %d, want 1", tx.TokenTransferCount)
	}

	// Verify a non-existent tx returns nil.
	missing, err := store.GetTransactionWithCategories(ctx, "0xnonexistent")
	if err != nil {
		t.Fatalf("GetTransactionWithCategories for missing tx: %v", err)
	}
	if missing != nil {
		t.Errorf("expected nil for non-existent tx, got %+v", missing)
	}
}

func assertCategories(t *testing.T, label string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s categories = %v, want %v", label, got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("%s categories[%d] = %q, want %q", label, i, got[i], want[i])
		}
	}
}
