package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestObserverCLIClosedInputAndExplicitRecovery(t *testing.T) {
	t.Setenv("OPS_TEST_OBSERVER_DSN", "postgres://public-test-only@127.0.0.1:1/none?sslmode=disable")
	for _, args := range [][]string{{"migrate"}, {"finalize-observer", "--recovery-timeout", "0"}, {"run", "--recovery-timeout", "1m"}, {"finalize-observer", "--recovery-timeout", "30m1ns"}, {"run", "--environment", "test"}, {"unknown"}} {
		args = append(args, "--dsn-env", "OPS_TEST_OBSERVER_DSN")
		var out, stderr bytes.Buffer
		if code := run(context.Background(), args, &out, &stderr); code != 2 || out.Len() != 0 || strings.Contains(stderr.String(), "postgres://") {
			t.Fatal(args, code, out.String(), stderr.String())
		}
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "selection.json")
	for _, raw := range []string{`{"captureEpochs":[],"extra":true}`, `{"captureEpochs":[],"CaptureEpochs":[]}`, `{"captureEpochs":[],"captureEpochs":[]}`, `{"captureEpochs":null}`, `{"captureEpochs":[]} {}`, strings.Repeat(" ", 32769)} {
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		var selection struct {
			CaptureEpochs []string `json:"captureEpochs"`
		}
		if readDocument(path, 32768, &selection) == nil {
			t.Fatal("invalid closed document", raw[:min(64, len(raw))])
		}
	}
}
