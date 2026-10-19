package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/bigAboo80/shieldops/internal/signing"
)

func init() {
	commands["keygen"] = command{"create a key pair for signing reports", runKeygenCmd}
	commands["verify"] = command{"check the signature of a report", runVerifyCmd}
}

func runKeygenCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", ".", "directory for "+signing.KeyFile+" (owner-only) and "+signing.PubFile)
	showPub := fs.Bool("show-pub", false, "print the public key of -key instead of creating a pair")
	key := fs.String("key", signing.KeyFile, "private key for -show-pub")
	fs.Parse(args)
	if *showPub {
		s, err := signing.LoadSigner(*key)
		if err != nil {
			return err
		}
		fmt.Print(string(s.PublicPEM()))
		fmt.Fprintf(os.Stderr, "fingerprint %s\n", s.Fingerprint())
		return nil
	}
	keyPath, pubPath, err := signing.GenerateKey(*out)
	if err != nil {
		return err
	}
	s, err := signing.LoadSigner(keyPath)
	if err != nil {
		return err
	}
	fmt.Printf("[✓] Private key %s (keep it secret: scan/serve -sign-key-file)\n", keyPath)
	fmt.Printf("[✓] Public key  %s (give it to auditors: shieldops verify -pub)\n", pubPath)
	fmt.Printf("    Fingerprint %s\n", s.Fingerprint())
	return nil
}

func runVerifyCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	pubPath := fs.String("pub", "", "public key of the signer ("+signing.PubFile+")")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: shieldops verify -pub <key.pub> <report> [<report>.sig]")
		fs.PrintDefaults()
	}
	fs.Parse(args)
	if *pubPath == "" || fs.NArg() < 1 || fs.NArg() > 2 {
		fs.Usage()
		return errors.New("verify needs -pub and a report")
	}
	report := fs.Arg(0)
	sigPath := report + ".sig"
	if fs.NArg() == 2 {
		sigPath = fs.Arg(1)
	}
	pemBytes, err := os.ReadFile(*pubPath)
	if err != nil {
		return fmt.Errorf("read public key: %w", err)
	}
	pub, err := signing.ParsePublicPEM(pemBytes)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(report)
	if err != nil {
		return fmt.Errorf("read report: %w", err)
	}
	sig, err := os.ReadFile(sigPath)
	if err != nil {
		return fmt.Errorf("read signature: %w", err)
	}
	s, err := signing.Verify(pub, data, sig)
	if err != nil {
		return fmt.Errorf("%s: %w", report, err)
	}
	at, _ := time.Parse(time.RFC3339, s.SignedAt)
	fmt.Printf("[✓] %s: signature valid, signed %s with key %s\n", report, at.Format("2006-01-02 15:04 MST"), s.Key)
	return nil
}
