package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"privacy-proxy/internal/server/apispec"
)

// TestHandleOpenAPISpec pins the spec endpoint contract (RD-1166): it serves
// exactly the embedded generated document as JSON, without auth (public by
// design — the published API reference of an open-source project).
func TestHandleOpenAPISpec(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	s := &Server{}
	r.GET("/openapi.json", s.handleOpenAPISpec)

	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("content-type = %q", ct)
	}
	if w.Body.String() != string(apispec.JSON) {
		t.Error("body is not the embedded document")
	}
	var doc struct {
		OpenAPI string `json:"openapi"`
		Info    struct {
			Title string `json:"title"`
		} `json:"info"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatalf("served document is not valid JSON: %v", err)
	}
	if doc.OpenAPI == "" || doc.Info.Title == "" {
		t.Errorf("served document missing openapi/info.title: %+v", doc)
	}
}
