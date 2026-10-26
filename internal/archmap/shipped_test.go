package archmap

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestShippedPackages(t *testing.T) {
	got, err := ShippedPackages("testdata/refmod", "refmod/", nil, "./app")
	require.NoError(t, err)
	require.Equal(t, []string{"refmod/app", "refmod/gate", "refmod/legacy", "refmod/store"}, got)
}

func TestShippedFiles(t *testing.T) {
	got, err := ShippedFiles("testdata/refmod", "refmod/", nil, "./app")
	require.NoError(t, err)
	require.Contains(t, got, "app/serve.go")
	require.Contains(t, got, "store/db.go")
	require.NotContains(t, got, "go.mod")
}
