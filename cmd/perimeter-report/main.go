// Command perimeter-report writes the module size report
// (docs/architecture/perimeter-report.md) from the module map
// (docs/architecture/modules.toml), or checks that the committed report is
// current. With -boundaries it also prints every perimeter rule violation
// (internal/archtest runs the same rules in CI and also checks that every
// shipped file was analyzed). With -since REF it prints which
// modules and audit scopes the changes since REF touch, the starting point
// for scoping a delta audit.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"privacy-proxy/internal/archmap"
)

func main() {
	root := flag.String("root", ".", "repository root")
	write := flag.Bool("write", false, "write the report")
	check := flag.Bool("check", false, "fail if the committed report is out of date")
	outside := flag.Bool("outside", false, "print sizes of modules outside the perimeter too (not with -write or -check)")
	boundaries := flag.Bool("boundaries", false, "also print perimeter rule violations")
	since := flag.String("since", "", "print the modules changed since this git revision instead of the report")
	flag.Parse()

	var err error
	if *since != "" {
		err = touched(*root, *since)
	} else {
		err = run(*root, *write, *check, *outside, *boundaries)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "perimeter-report:", err)
		os.Exit(1)
	}
}

func run(root string, write, check, outside, boundaries bool) error {
	m, err := archmap.Load(filepath.Join(root, archmap.ManifestPath))
	if err != nil {
		return err
	}
	sizes, err := archmap.Measure(m, root)
	if err != nil {
		return err
	}
	path := filepath.Join(root, archmap.ReportPath)
	committed := archmap.Report(m, sizes, archmap.ReportOptions{})
	switch {
	case check:
		current, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if string(current) != committed {
			return fmt.Errorf("%s is out of date; run `make perimeter-report`", archmap.ReportPath)
		}
	case write:
		if err := os.WriteFile(path, []byte(committed), 0o644); err != nil {
			return err
		}
	default:
		fmt.Print(archmap.Report(m, sizes, archmap.ReportOptions{OutsideSizes: outside}))
	}
	if !boundaries {
		return nil
	}
	violations, _, err := archmap.CheckRepository(m, root)
	if err != nil {
		return err
	}
	for _, v := range violations {
		fmt.Println(v)
	}
	if len(violations) > 0 {
		return fmt.Errorf("%d perimeter rule violation(s)", len(violations))
	}
	return nil
}

// touched classifies the files changed since a revision (deleted files and
// both sides of renames included) with the current map, and says whether the
// map itself changed.
func touched(root, since string) error {
	m, err := archmap.Load(filepath.Join(root, archmap.ManifestPath))
	if err != nil {
		return err
	}
	// Compare the audited revision with HEAD directly, not from their merge
	// base, so everything that differs from the audited code is listed.
	// --no-renames lists both paths of a moved file, so code moved out of a
	// core module still shows up under that module.
	cmd := exec.Command("git", "diff", "--name-only", "--no-renames", "-z", since, "HEAD", "--")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("git diff %s HEAD: %w", since, err)
	}
	var paths []string
	for _, p := range strings.Split(string(out), "\x00") {
		if p != "" {
			paths = append(paths, p)
		}
	}
	files, inputs, mapChanged, err := m.Changes(paths, archmap.ManifestPath)
	if err != nil {
		return err
	}
	fmt.Print(archmap.Touched(m, files, inputs, mapChanged))
	return nil
}
