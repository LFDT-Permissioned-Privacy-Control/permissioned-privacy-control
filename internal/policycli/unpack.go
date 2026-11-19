package policycli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"privacy-proxy/internal/strictjson"
)

// BrowserSourcePackage is only an exact-byte transport for local source files.
// Unpacking does not compile, approve or activate policy. Each output draft
// root is independently checked with the existing policy prepare/check path.
type BrowserSourcePackage struct {
	APIVersion string              `json:"apiVersion"`
	Roots      []BrowserSourceRoot `json:"roots"`
}
type BrowserSourceRoot struct {
	ID    string              `json:"id"`
	Files []BrowserSourceFile `json:"files"`
}
type BrowserSourceFile struct {
	Path       string `json:"path"`
	DataBase64 string `json:"dataBase64"`
}

var sourceFileName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,122}\.json$`)
var sourceRootName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

func unpackSource(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("unpack", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	file := flags.String("file", "", "browser source-package file")
	output := flags.String("output", "", "new output directory")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, help)
			return 0
		}
		return reportError(stderr, "usage", err, 2)
	}
	if flags.NArg() != 0 || *file == "" || *output == "" {
		return reportError(stderr, "usage", errors.New("unpack requires --file PACKAGE.json --output NEW_DIR"), 2)
	}
	// Base64 plus JSON framing for at most64MiB decoded bytes. The transport is
	// bounded before decoding, and every source is charged before allocation.
	raw, err := readABI(ctx, *file, 90<<20)
	if err != nil {
		return reportError(stderr, "unpack", err, 1)
	}
	var packed BrowserSourcePackage
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, parseErr := strictjson.ReadValue(decoder, 0, 16)
	var trailing any
	if parseErr != nil || decoder.Decode(&trailing) != io.EOF {
		return reportError(stderr, "unpack", errors.New("invalid browser source package"), 1)
	}
	if err = strictjson.ExactDecode(value, &packed); err != nil {
		return reportError(stderr, "unpack", errors.New("invalid browser source package"), 1)
	}
	if packed.APIVersion != "ops.ui-source-package/v1" || len(packed.Roots) < 1 || len(packed.Roots) > 16 {
		return reportError(stderr, "unpack", errors.New("unsupported browser source package"), 1)
	}
	type decodedFile struct {
		root, path string
		data       []byte
	}
	decoded := []decodedFile{}
	roots := map[string]bool{}
	remaining, totalFiles := 64<<20, 0
	for _, root := range packed.Roots {
		if !sourceRootName.MatchString(root.ID) || roots[root.ID] || len(root.Files) < 1 || len(root.Files) > 1025 {
			return reportError(stderr, "unpack", errors.New("invalid or duplicate source root"), 1)
		}
		roots[root.ID] = true
		names := map[string]bool{}
		for _, file := range root.Files {
			totalFiles++
			if !sourceFileName.MatchString(file.Path) || len(file.Path) > 128 || names[file.Path] || totalFiles > 2048 ||
				len(file.DataBase64) > base64.StdEncoding.EncodedLen(1<<20) || strings.ContainsAny(file.DataBase64, "\r\n") {
				return reportError(stderr, "unpack", errors.New("invalid, duplicate or oversized source filename/data"), 1)
			}
			names[file.Path] = true
			// DecodedLen is an upper bound (up to two padding bytes). Check the
			// actual decoded size too, without allocating past the aggregate cap.
			allocation := base64.StdEncoding.DecodedLen(len(file.DataBase64))
			if allocation > (1<<20)+2 || allocation > remaining+2 {
				return reportError(stderr, "unpack", errors.New("source byte budget exceeded"), 1)
			}
			data, err := base64.StdEncoding.Strict().DecodeString(file.DataBase64)
			if err != nil || len(data) > 1<<20 || len(data) > remaining || !utf8.Valid(data) {
				return reportError(stderr, "unpack", errors.New("invalid UTF-8 source byte encoding or budget"), 1)
			}
			remaining -= len(data)
			decoded = append(decoded, decodedFile{root.ID, file.Path, data})
		}
		if !names["draft.json"] {
			return reportError(stderr, "unpack", errors.New("each source root needs draft.json"), 1)
		}
	}
	if err := ctx.Err(); err != nil {
		return reportError(stderr, "unpack", err, 1)
	}
	if err := os.Mkdir(*output, 0700); err != nil {
		return reportError(stderr, "unpack", errors.New("a new output directory is required"), 1)
	}
	for _, root := range packed.Roots {
		if err := os.Mkdir(filepath.Join(*output, root.ID), 0700); err != nil {
			return reportError(stderr, "unpack", errors.New("cannot create new source root"), 1)
		}
	}
	for _, file := range decoded {
		if err := ctx.Err(); err != nil {
			return reportError(stderr, "unpack", err, 1)
		}
		if err := writeExclusive(filepath.Join(*output, file.root, file.path), file.data); err != nil {
			return reportError(stderr, "unpack", errors.New("cannot write new source document"), 1)
		}
	}
	if err := ctx.Err(); err != nil {
		return reportError(stderr, "unpack", err, 1)
	}
	if err := json.NewEncoder(stdout).Encode(struct {
		Action    string `json:"action"`
		Validated bool   `json:"validated"`
		Approved  bool   `json:"approved"`
		RootCount int    `json:"rootCount"`
		FileCount int    `json:"fileCount"`
	}{"unpack", false, false, len(roots), len(decoded)}); err != nil {
		return reportError(stderr, "output", err, 1)
	}
	return 0
}
