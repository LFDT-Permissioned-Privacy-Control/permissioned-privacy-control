// Command api-inventory generates API_ENDPOINTS.md from the live gin route
// table (RD-1166): every registered route, the canonical operation it maps
// to, and per-method totals. This is the auditor-facing endpoint inventory;
// the OpenAPI document (make api-spec) is the full machine-readable spec.
//
// Run via `make api-inventory`. Output is deterministic so CI can regenerate
// and fail on drift; the rendering (and its determinism) lives in
// server.BuildInventory so it is unit-tested in the ./internal/... test job
// (RD-1190).
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"privacy-proxy/internal/server"
)

func main() {
	out := flag.String("out", "API_ENDPOINTS.md", "output markdown file")
	flag.Parse()

	all := server.RoutesForSpec(true)
	prod := server.RoutesForSpec(false)

	content, opCount := server.BuildInventory(all, prod)

	if err := os.WriteFile(*out, []byte(content), 0o644); err != nil {
		log.Fatalf("write %s: %v", *out, err)
	}
	fmt.Printf("wrote %s: %d registered routes, %d distinct operations\n", *out, len(all), opCount)
}
