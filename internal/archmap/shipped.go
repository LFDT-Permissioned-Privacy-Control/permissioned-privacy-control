package archmap

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// ShippedPackages lists the packages under the module prefix that the given
// main packages link with the given build flags, i.e. the code that ships.
func ShippedPackages(root, prefix string, buildFlags []string, mains ...string) ([]string, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	args := append([]string{"list", "-deps"}, buildFlags...)
	args = append(args, "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}")
	args = append(args, mains...)
	cmd := exec.Command("go", args...)
	cmd.Dir = absRoot
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("go list -deps: %v\n%s", err, ee.Stderr)
		}
		return nil, fmt.Errorf("go list -deps: %w", err)
	}
	var pkgs []string
	for _, line := range strings.Split(string(out), "\n") {
		if line = strings.TrimSpace(line); strings.HasPrefix(line, prefix) {
			pkgs = append(pkgs, line)
		}
	}
	sort.Strings(pkgs)
	return pkgs, nil
}

// ShippedFiles lists the non-test Go files, relative to root, of the packages
// ShippedPackages returns.
func ShippedFiles(root, prefix string, buildFlags []string, mains ...string) ([]string, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	args := append([]string{"list", "-deps"}, buildFlags...)
	args = append(args, "-f", `{{if not .Standard}}{{.ImportPath}}{{range .GoFiles}} {{$.Dir}}/{{.}}{{end}}{{range .CgoFiles}} {{$.Dir}}/{{.}}{{end}}{{end}}`)
	args = append(args, mains...)
	cmd := exec.Command("go", args...)
	cmd.Dir = absRoot
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("go list -deps: %v\n%s", err, ee.Stderr)
		}
		return nil, fmt.Errorf("go list -deps: %w", err)
	}
	var files []string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.HasPrefix(fields[0], prefix) {
			continue
		}
		for _, f := range fields[1:] {
			rel, err := filepath.Rel(absRoot, f)
			if err != nil {
				return nil, err
			}
			files = append(files, filepath.ToSlash(rel))
		}
	}
	sort.Strings(files)
	return files, nil
}
