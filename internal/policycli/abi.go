package policycli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"privacy-proxy/internal/policybundle"
)

func inspectABI(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("abi", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	name := flags.String("file", "", "local regular ABI JSON file")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, help)
			return 0
		}
		return reportError(stderr, "usage", err, 2)
	}
	if *name == "" || flags.NArg() != 0 {
		return reportError(stderr, "usage", errors.New("abi requires --file ABI.json"), 2)
	}
	limits := policybundle.DefaultLimits()
	raw, err := readABI(ctx, *name, limits.MaxDocumentBytes)
	if err != nil {
		return reportError(stderr, "abi", err, 1)
	}
	result, err := policybundle.InspectABI(raw, limits)
	if err != nil {
		return reportError(stderr, "abi", err, 1)
	}
	if err := ctx.Err(); err != nil {
		return reportError(stderr, "abi", err, 1)
	}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		return reportError(stderr, "output", err, 1)
	}
	return 0
}

func readABI(ctx context.Context, name string, limit int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(filepath.Dir(name))
	if err != nil {
		return nil, errors.New("cannot open ABI directory")
	}
	defer root.Close()
	base := filepath.Base(name)
	info, err := root.Lstat(base)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("ABI must be a regular file within the byte budget")
	}
	file, err := root.Open(base)
	if err != nil {
		return nil, errors.New("cannot read ABI file")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, errors.New("ABI file changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, errors.New("cannot read ABI within byte budget")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return raw, nil
}
