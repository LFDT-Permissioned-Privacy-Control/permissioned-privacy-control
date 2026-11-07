package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestArgumentsAndSecretsStayOffline(t *testing.T) {
	for _, args := range [][]string{{}, {"unknown", "--dsn-env", "OPS_WALLET_TEST_DSN"}, {"migrate"}, {"migrate", "--dsn-env", "bad-env"}, {"migrate", "--unknown", "do-not-echo-this"}} {
		t.Setenv("OPS_WALLET_TEST_DSN", "private DSN sentinel must never be echoed")
		var out, err bytes.Buffer
		if run(args, &out, &err) == 0 {
			t.Fatal("invalid arguments succeeded", args)
		}
		if strings.Contains(out.String()+err.String(), "sentinel") || strings.Contains(err.String(), "do-not-echo-this") {
			t.Fatal("sensitive argument echoed")
		}
	}
	var out, err bytes.Buffer
	if run([]string{"migrate", "--help"}, &out, &err) != 0 {
		t.Fatal("help failed")
	}
}
