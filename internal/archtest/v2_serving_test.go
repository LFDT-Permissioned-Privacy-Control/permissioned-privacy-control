package archtest

import (
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"privacy-proxy/internal/explorerquery"
	"privacy-proxy/internal/operational/v2server"
)

func TestNativeV2ServingExcludesLegacyServerAndEVMPolicyBackend(t *testing.T) {
	for dep := range transitiveDeps(t, moduleRoot(t), "privacy-proxy/internal/operational/v2server") {
		for _, prefix := range []string{"privacy-proxy/internal/server", "privacy-proxy/internal/db", "privacy-proxy/internal/policybackend/evm", "github.com/ethereum/go-ethereum/core/vm", "github.com/ethereum/go-ethereum/core/state", "github.com/ethereum/go-ethereum/triedb", "github.com/redis/"} {
			if dep == prefix || strings.HasPrefix(dep, prefix+"/") || strings.HasSuffix(prefix, "/") && strings.HasPrefix(dep, prefix) {
				t.Errorf("native serving acquired legacy infrastructure: %s", dep)
			}
		}
	}
}

// RD-855: chain-data SQL belongs to the indexer. OPS may retain its separate
// operational stores, but its indexed-data transport must not acquire a SQL
// client or the legacy Explorer store/fallback through any import path.
func TestNativeIndexerConsumerUsesOnlyServiceAPI(t *testing.T) {
	root := moduleRoot(t)
	if explorerquery.APIVersion != "chain_indexer.v2" {
		t.Fatal("native indexed-data API version differs from the selected protocol")
	}
	for dep := range transitiveDeps(t, root, "privacy-proxy/internal/operational/explorerindex") {
		// uint256's value-conversion helpers import database/sql without
		// opening connections. Forbid storage drivers transitively and the
		// SQL client directly in the adapter instead of banning that helper.
		for _, prefix := range []string{"github.com/jackc/", "github.com/lib/pq", "modernc.org/sqlite", "github.com/mattn/go-sqlite3", "github.com/go-sql-driver/mysql", "privacy-proxy/internal/explorer", "privacy-proxy/internal/db", "privacy-proxy/gen/go/chain_indexer/v1"} {
			if dep == prefix || strings.HasPrefix(dep, prefix+"/") || strings.HasSuffix(prefix, "/") && strings.HasPrefix(dep, prefix) {
				t.Errorf("indexed-data consumer imports private storage/fallback: %s", dep)
			}
		}
	}
	config := reflect.TypeOf(v2server.Index{})
	for i := 0; i < config.NumField(); i++ {
		f := config.Field(i)
		if strings.Contains(strings.ToLower(f.Name), "dsn") || strings.Contains(strings.ToLower(f.Tag.Get("json")), "dsn") {
			t.Errorf("OPS index configuration exposes SQL credential: %s", f.Name)
		}
	}
	entries, err := os.ReadDir(filepath.Join(root, "internal/operational/explorerindex"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") || e.Name() == "schema-columns.json" {
			t.Errorf("OPS indexed-data consumer contains private indexer schema/SQL: %s", e.Name())
		}
		if strings.HasSuffix(e.Name(), ".go") && !strings.HasSuffix(e.Name(), "_test.go") {
			file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, "internal/operational/explorerindex", e.Name()), nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, imported := range file.Imports {
				path, err := strconv.Unquote(imported.Path.Value)
				if err != nil {
					t.Fatal(err)
				}
				if path == "database/sql" {
					t.Errorf("indexed-data adapter directly imports SQL client: %s", e.Name())
				}
			}
		}
	}
	// A database binding must be rejected, rather than silently ignored or
	// interpreted as a transport address during deployment migration.
	var old v2server.Index
	decoder := json.NewDecoder(strings.NewReader(`{"readerDSNEnv":"INDEX_DSN"}`))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&old); err == nil {
		t.Fatal("legacy indexer database binding was accepted")
	}
}
