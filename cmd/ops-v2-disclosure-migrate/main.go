// Command ops-v2-disclosure-migrate applies the bounded disclosure schema with
// explicit offline migrator credentials. It is not linked into the policy CLI.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"

	"privacy-proxy/internal/operational/disclosuresql"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ops-v2-disclosure-migrate", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	env := flags.String("dsn-env", "", "explicit environment variable containing migrator DSN")
	app := flags.String("app-role", "", "pre-existing application role")
	retention := flags.String("retention-role", "", "pre-existing retention role")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			fmt.Fprintln(stdout, "ops-v2-disclosure-migrate --dsn-env NAME --app-role ROLE --retention-role ROLE")
			return 0
		}
		fmt.Fprintln(stderr, "invalid migration arguments")
		return 2
	}
	if flags.NArg() != 0 || !regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`).MatchString(*env) || *app == "" || *retention == "" {
		fmt.Fprintln(stderr, "explicit DSN environment name and application/retention roles required")
		return 2
	}
	dsn := os.Getenv(*env)
	if dsn == "" {
		fmt.Fprintln(stderr, "migration DSN environment variable is empty")
		return 2
	}
	if err := disclosuresql.Migrate(context.Background(), dsn, *app, *retention); err != nil {
		fmt.Fprintln(stderr, "disclosure migration failed; check credentials, roles and schema version")
		return 1
	}
	fmt.Fprintf(stdout, "{\"schemaVersion\":1,\"sourceChecksum\":%q}\n", disclosuresql.SchemaChecksum())
	return 0
}
