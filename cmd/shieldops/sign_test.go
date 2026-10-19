package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bigAboo80/shieldops/internal/report"
	"github.com/bigAboo80/shieldops/internal/signing"
)

// TestSignFlow: keygen, a signed report, verify; any change breaks it.
func TestSignFlow(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := runKeygenCmd(t.Context(), []string{"-out", dir}); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	if err := runKeygenCmd(t.Context(), []string{"-out", other}); err != nil {
		t.Fatal(err)
	}
	if err := runKeygenCmd(t.Context(), []string{"-out", dir}); err == nil {
		t.Fatal("keygen overwrote the keys")
	}
	if st, err := os.Stat(filepath.Join(dir, signing.KeyFile)); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode %v, %v", st.Mode().Perm(), err)
	}
	cfg := scanConfig{signKeyFile: filepath.Join(dir, signing.KeyFile)}
	s, err := cfg.signer()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "report.html")
	if err := writeReport(path, report.Data{Lang: "ru", Generated: time.Now(), Assets: 1}, s); err != nil {
		t.Fatal(err)
	}
	html, _ := os.ReadFile(path)
	if !strings.Contains(string(html), "Ключ подписи") {
		t.Error("the report does not name its key")
	}
	pub := filepath.Join(dir, signing.PubFile)
	if err := runVerifyCmd(t.Context(), []string{"-pub", pub, path}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := runVerifyCmd(t.Context(), []string{"-pub", filepath.Join(other, signing.PubFile), path}); err == nil {
		t.Error("verify passed with another key")
	}
	html[len(html)-3] ^= 1
	os.WriteFile(path, html, 0o600)
	err = runVerifyCmd(t.Context(), []string{"-pub", pub, path, path + ".sig"})
	if err == nil || !strings.Contains(err.Error(), "changed after signing") {
		t.Errorf("verify of a changed report: %v", err)
	}
	if err := runVerifyCmd(t.Context(), []string{"-pub", pub}); err == nil {
		t.Error("verify without a report passed")
	}
}
