package main

import (
	"slices"
	"testing"
)

// The server binary runs the migration command as `privacy-proxy migrate`
// (review finding 9); anything else starts the server.
func TestMigrateSubcommand(t *testing.T) {
	if args, ok := migrateArgs([]string{"migrate", "-audit"}); !ok || !slices.Equal(args, []string{"-audit"}) {
		t.Fatalf("migrate -audit: %v %v", args, ok)
	}
	if _, ok := migrateArgs(nil); ok {
		t.Fatal("no arguments must start the server")
	}
	if _, ok := migrateArgs([]string{"-audit"}); ok {
		t.Fatal("a bare flag must not run the migration command")
	}
}
