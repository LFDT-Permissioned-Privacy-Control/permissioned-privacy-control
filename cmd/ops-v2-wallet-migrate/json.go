package main

import (
	"encoding/json"
	"io"
)

func writeJSON(w io.Writer, value any) int {
	if json.NewEncoder(w).Encode(value) != nil {
		return 1
	}
	return 0
}
