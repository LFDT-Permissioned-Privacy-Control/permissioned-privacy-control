package archmap

import (
	"bytes"
	"fmt"
	"go/scanner"
	"go/token"
	"os"
	"path"
	"strings"
)

// nSLOC here means source lines that contain code: blank lines and lines
// holding only comments are not counted. That is the measure audit quotes are
// based on.

// CountGo counts code lines in Go source. A multi-line raw string counts every
// line it spans.
func CountGo(src []byte) (int, error) {
	fset := token.NewFileSet()
	file := fset.AddFile("", fset.Base(), len(src))
	var s scanner.Scanner
	var firstErr error
	s.Init(file, src, func(pos token.Position, msg string) {
		if firstErr == nil {
			firstErr = fmt.Errorf("%d:%d: %s", pos.Line, pos.Column, msg)
		}
	}, 0)
	lines := map[int]bool{}
	for {
		pos, tok, lit := s.Scan()
		if tok == token.EOF {
			break
		}
		// The scanner inserts a semicolon at line ends; it is not code.
		if tok == token.SEMICOLON && lit == "\n" {
			continue
		}
		start := file.Line(pos)
		end := start + strings.Count(lit, "\n")
		for l := start; l <= end; l++ {
			lines[l] = true
		}
	}
	return len(lines), firstErr
}

// CountCLike counts code lines in languages with // and /* */ comments
// (Rust, Java, Solidity, TypeScript). It does not parse string literals: a
// line starting with a comment marker inside a string, or a "/*" inside a
// string, is misread. No counted source has either.
func CountCLike(src []byte) int {
	return countLines(src, "//", false)
}

// CountRust counts code lines in Rust like CountCLike, leaving out inline
// test modules (`#[cfg(test)] mod name { ... }`): tests are not counted in
// any language. Braces are matched by counting, which is exact for
// rustfmt-formatted code without braces in string literals.
func CountRust(src []byte) int {
	lines := strings.Split(string(src), "\n")
	kept := make([]string, 0, len(lines))
	for i := 0; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) != "#[cfg(test)]" {
			kept = append(kept, lines[i])
			continue
		}
		j := i + 1
		for j < len(lines) && strings.TrimSpace(lines[j]) == "" {
			j++
		}
		next := ""
		if j < len(lines) {
			next = strings.TrimSpace(lines[j])
		}
		if !strings.HasPrefix(next, "mod ") || !strings.HasSuffix(next, "{") {
			kept = append(kept, lines[i])
			continue
		}
		depth := 0
		for ; j < len(lines); j++ {
			depth += strings.Count(lines[j], "{") - strings.Count(lines[j], "}")
			if depth == 0 {
				break
			}
		}
		i = j
	}
	return CountCLike([]byte(strings.Join(kept, "\n")))
}

// CountSQL counts code lines in SQL with -- and /* */ comments. In migrations
// it stops at tern's "---- create above / drop below ----" marker: the down
// section is development-only and never runs in production.
func CountSQL(src []byte) int {
	return countLines(src, "--", true)
}

func countLines(src []byte, lineComment string, ternMarker bool) int {
	n := 0
	inBlock := false
	for _, raw := range bytes.Split(src, []byte("\n")) {
		line := strings.TrimSpace(string(raw))
		if ternMarker && strings.HasPrefix(line, "---- create above") {
			break
		}
		code := false
		for line != "" {
			if inBlock {
				end := strings.Index(line, "*/")
				if end < 0 {
					line = ""
					break
				}
				inBlock = false
				line = strings.TrimSpace(line[end+2:])
				continue
			}
			if strings.HasPrefix(line, lineComment) {
				break
			}
			if strings.HasPrefix(line, "/*") {
				inBlock = true
				line = line[2:]
				continue
			}
			code = true
			// Code on this line; a block comment opening later on the same
			// line still has to be tracked for the following lines.
			if open := strings.LastIndex(line, "/*"); open >= 0 && !strings.Contains(line[open:], "*/") {
				inBlock = true
			}
			break
		}
		if code {
			n++
		}
	}
	return n
}

// CountFile counts the code lines of one file, choosing the counter by
// extension.
func CountFile(name string) (int, error) {
	src, err := readFile(name)
	if err != nil {
		return 0, err
	}
	switch path.Ext(name) {
	case ".go":
		return CountGo(src)
	case ".sql":
		return CountSQL(src), nil
	case ".rs":
		return CountRust(src), nil
	case ".java", ".sol", ".ts", ".tsx":
		return CountCLike(src), nil
	default:
		return 0, fmt.Errorf("%s: no line counter for this file type", name)
	}
}

// Language names the language of a source file for the report.
func Language(name string) string {
	switch path.Ext(name) {
	case ".go":
		return "Go"
	case ".rs":
		return "Rust"
	case ".java":
		return "Java"
	case ".sol":
		return "Solidity"
	case ".sql":
		return "SQL"
	case ".ts", ".tsx":
		return "TypeScript"
	default:
		return "other"
	}
}

func readFile(name string) ([]byte, error) {
	data, err := os.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	return data, nil
}
