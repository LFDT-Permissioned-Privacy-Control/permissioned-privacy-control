package disclosurehttp

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"privacy-proxy/internal/disclosurecase"
)

func TestOversizedValidRawQueryRejectedBeforeDecoding(t *testing.T) {
	r := httptest.NewRequest("GET", "/api/v1/disclosure/cases?cursor="+strings.Repeat("%41", MaxRawQueryBytes), nil)
	if err := query(r, "cursor"); !errors.Is(err, disclosurecase.ErrInvalid) {
		t.Fatal("oversized otherwise-valid percent-encoded cursor query accepted", err)
	}
	r = httptest.NewRequest("GET", "/api/v1/disclosure/cases?cursor="+strings.Repeat("A", 4096), nil)
	if err := query(r, "cursor"); err != nil {
		t.Fatal("bounded cursor query rejected", err)
	}
}
