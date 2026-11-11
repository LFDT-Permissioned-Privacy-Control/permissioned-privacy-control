package archtest

import (
	"os/exec"
	"strings"
	"testing"
)

func TestHistoryPrivacyDataAndABIBoundaries(t *testing.T) {
	root := moduleRoot(t)
	for _, pkg := range []string{"explorerdata", "readprivacyabi", "explorerprivacy"} {
		t.Run(pkg, func(t *testing.T) {
			for dep := range transitiveDeps(t, root, "privacy-proxy/internal/"+pkg) {
				if strings.HasPrefix(dep, "privacy-proxy/") {
					switch dep {
					case "privacy-proxy/internal/explorerdata", "privacy-proxy/internal/readprivacyabi", "privacy-proxy/internal/explorerprivacy", "privacy-proxy/internal/readprivacy":
					default:
						t.Errorf("pure history privacy acquired application infrastructure %s", dep)
					}
				}
				for _, prefix := range []string{"github.com/jackc/", "github.com/lib/pq", "github.com/mattn/go-sqlite", "github.com/redis/", "github.com/ethereum/go-ethereum/core/", "github.com/ethereum/go-ethereum/triedb", "github.com/ethereum/go-ethereum/accounts/abi/bind", "net/http"} {
					if strings.HasPrefix(dep, prefix) {
						t.Errorf("pure history privacy acquired storage/network/EVM execution %s", dep)
					}
				}
			}
			// geth/common -> uint256 implements sql.Scanner/driver.Valuer. Those
			// standard conversion interfaces do not open connections. The pure
			// application leaves themselves must not import SQL at all.
			direct := exec.Command("go", "list", "-f", "{{join .Imports \"\\n\"}}", "privacy-proxy/internal/"+pkg)
			direct.Dir = root
			imports, err := direct.CombinedOutput()
			if err != nil {
				t.Fatalf("direct imports: %v\n%s", err, imports)
			}
			for _, dep := range strings.Fields(string(imports)) {
				if dep == "database/sql" || dep == "database/sql/driver" {
					t.Errorf("pure application leaf imports SQL directly: %s", dep)
				}
			}
			if pkg == "explorerdata" {
				cmd := exec.Command("go", "list", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", "privacy-proxy/internal/explorerdata")
				cmd.Dir = root
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("data DTO closure: %v\n%s", err, out)
				}
				for _, dep := range strings.Fields(string(out)) {
					if dep != "privacy-proxy/internal/explorerdata" {
						t.Errorf("data DTO leaf acquired a non-standard dependency %s", dep)
					}
				}
			}
		})
	}
}
