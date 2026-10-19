// Package signing signs reports with Ed25519 so an auditor can tell they
// were not changed: a detached signature file next to the report holds the
// SHA-256 of the report, the time, the fingerprint of the public key and the
// signature over them. Only the standard library is used.
//
// This is not a qualified electronic signature: a legally binding one
// needs GOST cryptography and is a separate task.
package signing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Algorithm of the signatures.
const Algorithm = "ed25519"

// Key file names keygen writes.
const (
	KeyFile = "shieldops-signing.key"
	PubFile = "shieldops-signing.pub"
)

// Signature is the content of a .sig file.
type Signature struct {
	Algorithm string `json:"algorithm"`
	SHA256    string `json:"sha256"`    // of the signed file, hex
	SignedAt  string `json:"signed_at"` // RFC 3339, UTC
	Key       string `json:"key"`       // fingerprint of the public key
	Signature string `json:"signature"` // base64, over the fields above
}

// payload is what is signed: every field but the signature, so changing
// the time or the key in the file breaks it too.
func (s Signature) payload() []byte {
	b, _ := json.Marshal(struct {
		Algorithm string `json:"algorithm"`
		SHA256    string `json:"sha256"`
		SignedAt  string `json:"signed_at"`
		Key       string `json:"key"`
	}{s.Algorithm, s.SHA256, s.SignedAt, s.Key})
	return append([]byte("shieldops-signature-v1\n"), b...)
}

// Fingerprint identifies a public key: "SHA256:" and the base64 of the
// SHA-256 of its PKIX form, as ssh-keygen shows keys.
func Fingerprint(pub ed25519.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil { // an ed25519 key always marshals
		panic(err)
	}
	sum := sha256.Sum256(der)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// Signer holds a private key. The key never appears in its errors or output.
type Signer struct {
	key ed25519.PrivateKey
}

// LoadSigner reads a private key written by GenerateKey.
func LoadSigner(path string) (*Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("signing key: not a PEM private key")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("signing key: cannot parse the private key")
	}
	key, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("signing key: not an Ed25519 key")
	}
	return &Signer{key: key}, nil
}

// Public returns the public key.
func (s *Signer) Public() ed25519.PublicKey { return s.key.Public().(ed25519.PublicKey) }

// Fingerprint of the public key.
func (s *Signer) Fingerprint() string { return Fingerprint(s.Public()) }

// PublicPEM is the public key to hand to auditors.
func (s *Signer) PublicPEM() []byte { return PublicPEM(s.Public()) }

// Sign returns the .sig file of data.
func (s *Signer) Sign(data []byte, now time.Time) []byte {
	sum := sha256.Sum256(data)
	sig := Signature{Algorithm: Algorithm, SHA256: hex.EncodeToString(sum[:]), SignedAt: now.UTC().Format(time.RFC3339), Key: s.Fingerprint()}
	sig.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(s.key, sig.payload()))
	b, _ := json.MarshalIndent(sig, "", "  ")
	return append(b, '\n')
}

// SignFile writes path.sig next to path.
func (s *Signer) SignFile(path string, now time.Time) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read report to sign: %w", err)
	}
	return WriteFile(path+".sig", s.Sign(data, now), 0o600)
}

// PublicPEM encodes a public key.
func PublicPEM(pub ed25519.PublicKey) []byte {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// ParsePublicPEM decodes a public key written by GenerateKey.
func ParsePublicPEM(b []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("public key: not a PEM public key")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("public key: not an Ed25519 key")
	}
	return pub, nil
}

// Errors of Verify; their texts are meant for the auditor.
var (
	ErrBadSignatureFile = errors.New("the signature file is damaged or not a ShieldOps signature")
	ErrOtherKey         = errors.New("the report was signed with another key")
	ErrModified         = errors.New("the report does not match the signature: it was changed after signing")
	ErrBadSignature     = errors.New("the signature is invalid: the signature file was changed or forged")
)

// Verify checks data against its .sig file and the public key.
func Verify(pub ed25519.PublicKey, data, sigFile []byte) (Signature, error) {
	var sig Signature
	dec := json.NewDecoder(bytes.NewReader(sigFile))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&sig); err != nil || sig.Algorithm != Algorithm {
		return sig, ErrBadSignatureFile
	}
	raw, err := base64.StdEncoding.DecodeString(sig.Signature)
	if err != nil || len(raw) != ed25519.SignatureSize {
		return sig, ErrBadSignatureFile
	}
	if sig.Key != Fingerprint(pub) {
		return sig, ErrOtherKey
	}
	if !ed25519.Verify(pub, sig.payload(), raw) {
		return sig, ErrBadSignature
	}
	sum := sha256.Sum256(data)
	if sig.SHA256 != hex.EncodeToString(sum[:]) {
		return sig, ErrModified
	}
	return sig, nil
}

// GenerateKey writes a new key pair into dir: the private key readable by
// the owner only, the public key for everyone. Existing files are kept.
func GenerateKey(dir string) (keyPath, pubPath string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", fmt.Errorf("encode key: %w", err)
	}
	keyPath, pubPath = filepath.Join(dir, KeyFile), filepath.Join(dir, PubFile)
	for _, p := range []string{keyPath, pubPath} {
		if _, err := os.Stat(p); err == nil {
			return "", "", fmt.Errorf("%s exists: not overwriting a key", p)
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", fmt.Errorf("create key directory: %w", err)
	}
	if err := WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return "", "", err
	}
	if err := WriteFile(pubPath, PublicPEM(pub), 0o644); err != nil {
		return "", "", err
	}
	return keyPath, pubPath, nil
}

// WriteFile replaces path atomically with data and the given permissions.
func WriteFile(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return fmt.Errorf("create %s: %w", filepath.Base(path), err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod %s: %w", filepath.Base(path), err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("save %s: %w", filepath.Base(path), err)
	}
	return nil
}
