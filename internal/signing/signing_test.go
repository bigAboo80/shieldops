package signing_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bigAboo80/shieldops/internal/signing"
)

func keys(t *testing.T) (*signing.Signer, []byte, string) {
	t.Helper()
	dir := t.TempDir()
	keyPath, pubPath, err := signing.GenerateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := signing.LoadSigner(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	return s, pub, keyPath
}

func TestSignVerify(t *testing.T) {
	t.Parallel()
	s, pubPEM, _ := keys(t)
	other, otherPEM, _ := keys(t)
	pub, err := signing.ParsePublicPEM(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	report := []byte("<html>отчёт</html>")
	sig := s.Sign(report, time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC))
	flip := func(b []byte, i int) []byte {
		c := append([]byte(nil), b...)
		c[i] ^= 1
		return c
	}
	otherPub, _ := signing.ParsePublicPEM(otherPEM)
	tests := []struct {
		name        string
		report, sig []byte
		key         []byte
		want        error
	}{
		{"valid", report, sig, nil, nil},
		{"one byte of the report changed", flip(report, 3), sig, nil, signing.ErrModified},
		{"signed time changed", report, []byte(strings.Replace(string(sig), "2026-10-01", "2026-10-02", 1)), nil, signing.ErrBadSignature},
		{"hash replaced", report, []byte(strings.Replace(string(sig), `"sha256": "`, `"sha256": "0`, 1)), nil, signing.ErrBadSignature},
		{"one byte of the signature changed", report, tamper(t, sig), nil, signing.ErrBadSignature},
		{"garbage", report, []byte("not json"), nil, signing.ErrBadSignatureFile},
		{"another key", report, sig, otherPEM, signing.ErrOtherKey},
		{"signed by another key, checked with its own", report, other.Sign(report, time.Now()), otherPEM, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			k := pub
			if tt.key != nil {
				k = otherPub
			}
			_, err := signing.Verify(k, tt.report, tt.sig)
			if !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

// tamper flips one byte of the signature in a .sig file.
func tamper(t *testing.T, sigFile []byte) []byte {
	t.Helper()
	var sig signing.Signature
	if err := json.Unmarshal(sigFile, &sig); err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(sig.Signature)
	raw[0] ^= 1
	sig.Signature = base64.StdEncoding.EncodeToString(raw)
	b, _ := json.Marshal(sig)
	return b
}

func TestKeyFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyPath, pubPath, err := signing.GenerateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{keyPath: 0o600, pubPath: 0o644} {
		st, err := os.Stat(path)
		if err != nil || st.Mode().Perm() != want {
			t.Errorf("%s: mode %v, %v; want %v", filepath.Base(path), st.Mode().Perm(), err, want)
		}
	}
	if _, _, err := signing.GenerateKey(dir); err == nil {
		t.Error("existing keys overwritten")
	}
	key, _ := os.ReadFile(keyPath)
	s, err := signing.LoadSigner(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	// The key never shows in output or errors.
	body := strings.Join(strings.Split(string(key), "\n")[1:2], "")
	for _, out := range []string{string(s.Sign([]byte("x"), time.Now())), string(s.PublicPEM()), s.Fingerprint()} {
		if strings.Contains(out, body) {
			t.Errorf("private key in output %q", out)
		}
	}
	bad := filepath.Join(dir, "bad.key")
	os.WriteFile(bad, []byte("-----BEGIN PRIVATE KEY-----\n"+body[:20]+"\n-----END PRIVATE KEY-----\n"), 0o600)
	if _, err := signing.LoadSigner(bad); err == nil || strings.Contains(err.Error(), body[:20]) {
		t.Errorf("bad key: %v", err)
	}
	if _, err := signing.LoadSigner(pubPath); err == nil {
		t.Error("public key accepted as private")
	}
}
