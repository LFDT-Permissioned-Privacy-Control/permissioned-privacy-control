package main

import (
	"bytes"
	"context"
	"testing"
)

func TestServeCLIRequiresPinnedDeploymentAndKeepsHelpOffline(t *testing.T) {
	var out bytes.Buffer
	if code := run(context.Background(), []string{"--help"}, &out); code != 0 {
		t.Fatal("help", code)
	}
	for _, args := range [][]string{nil, {"--config", "runtime.json"}, {"--unknown"}} {
		out.Reset()
		if code := run(context.Background(), args, &out); code != 2 {
			t.Fatal("unselected runtime opened", code)
		}
	}
}
