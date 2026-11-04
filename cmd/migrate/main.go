// Command migrate applies database migrations without starting the server:
// the main database by default, -audit for the audit database, -exec for the
// execution-tracking database. The server binary runs the same command as
// `privacy-proxy migrate`.
package main

import (
	"os"

	"privacy-proxy/internal/migratecli"
)

func main() {
	os.Exit(migratecli.Main(os.Args[1:]))
}
