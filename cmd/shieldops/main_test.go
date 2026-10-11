package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestReportHandler(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.html")
	present := filepath.Join(dir, "report.html")
	if err := os.WriteFile(present, []byte("<html>report</html>"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name, path, url string
		wantCode        int
	}{
		{"report", present, "/", http.StatusOK},
		{"first scan running", missing, "/", http.StatusServiceUnavailable},
		{"health", missing, "/healthz", http.StatusOK},
		{"no other files", present, "/report.html", http.StatusNotFound},
		{"no arbitrary paths", present, "/etc/passwd", http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			reportHandler(tt.path).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.url, nil))
			if rec.Code != tt.wantCode {
				t.Errorf("GET %s = %d, want %d", tt.url, rec.Code, tt.wantCode)
			}
			if tt.url == "/" && rec.Header().Get("Content-Security-Policy") == "" {
				t.Error("report served without Content-Security-Policy")
			}
		})
	}
}
