// Command devtoken mints signed relay connection tokens for development and
// integration testing, standing in for the Auth & License Service (M2).
//
// Typical use: generate a keypair, point the relay at the public key, and mint
// a mobile + desktop token for the same pair_id.
//
//	devtoken -gen-keys -out-dir ./keys -alg ES256
//	devtoken -key ./keys/relay.key.json -role mobile  -pair pair_X -account acct_1 -device dev_m -license lic_1
//	devtoken -key ./keys/relay.key.json -role desktop -pair pair_X -account acct_1 -device dev_d -license lic_1
//
// The relay loads ./keys/relay.pub.pem via RELAY_JWT_PUBLIC_KEY_FILE.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/lley154/secure-gateway/internal/devtoken"
	"github.com/lley154/secure-gateway/internal/token"
)

// keyFile is the persisted signer material (private key PEM + metadata) so the
// same key can mint multiple tokens across invocations.
type keyFile struct {
	Alg     string `json:"alg"`
	Kid     string `json:"kid"`
	PrivPEM string `json:"priv_pem"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "devtoken:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		genKeys = flag.Bool("gen-keys", false, "generate a keypair and write pub/priv files")
		outDir  = flag.String("out-dir", "./keys", "output directory for generated keys")
		alg     = flag.String("alg", "ES256", "signing algorithm: ES256 or EdDSA")
		kid     = flag.String("kid", "dev-1", "key id")

		keyPath = flag.String("key", "", "path to a key file produced by -gen-keys (required to mint)")
		issuer  = flag.String("iss", "https://auth.example.com", "token issuer")
		aud     = flag.String("aud", "relay", "token audience")
		account = flag.String("account", "acct_dev", "account_id claim")
		pair    = flag.String("pair", "pair_dev", "pair_id claim")
		device  = flag.String("device", "", "device_id claim (defaults by role)")
		role    = flag.String("role", "mobile", "role claim: mobile or desktop")
		license = flag.String("license", "lic_dev", "license_id claim")
		ttl     = flag.Duration("ttl", 10*time.Minute, "token TTL")
	)
	flag.Parse()

	if *genKeys {
		return generate(*outDir, *alg, *kid)
	}
	if *keyPath == "" {
		return fmt.Errorf("either -gen-keys or -key is required (see -h)")
	}

	signer, err := loadSigner(*keyPath)
	if err != nil {
		return err
	}
	r := token.Role(*role)
	if !r.Valid() {
		return fmt.Errorf("invalid -role %q", *role)
	}
	dev := *device
	if dev == "" {
		dev = "dev_" + *role
	}
	tok, err := signer.Mint(devtoken.TokenParams{
		Issuer: *issuer, Audience: *aud, AccountID: *account, PairID: *pair,
		DeviceID: dev, Role: r, LicenseID: *license, TTL: *ttl,
	})
	if err != nil {
		return err
	}
	fmt.Println(tok)
	return nil
}

func generate(outDir, alg, kid string) error {
	signer, err := devtoken.NewSigner(alg, kid)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return err
	}
	pubPEM, err := signer.PublicKeyPEM()
	if err != nil {
		return err
	}
	jwksDoc, err := signer.JWKS()
	if err != nil {
		return err
	}
	// Re-mint the signer material into a portable key file. We persist the
	// generated private key by round-tripping through a fresh signer is not
	// possible (keys are random per NewSigner), so persist directly here.
	kf, err := exportKeyFile(signer, alg, kid)
	if err != nil {
		return err
	}
	writes := map[string][]byte{
		"relay.pub.pem":   pubPEM,
		"relay.jwks.json": jwksDoc,
		"relay.key.json":  kf,
	}
	for name, data := range writes {
		p := filepath.Join(outDir, name)
		mode := os.FileMode(0o644)
		if name == "relay.key.json" {
			mode = 0o600
		}
		if err := os.WriteFile(p, data, mode); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "wrote %s\n", p)
	}
	return nil
}

func exportKeyFile(s *devtoken.Signer, alg, kid string) ([]byte, error) {
	privPEM, err := s.PrivateKeyPEM()
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(keyFile{Alg: alg, Kid: kid, PrivPEM: string(privPEM)}, "", "  ")
}

func loadSigner(path string) (*devtoken.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var kf keyFile
	if err := json.Unmarshal(data, &kf); err != nil {
		return nil, fmt.Errorf("parse key file: %w", err)
	}
	return devtoken.SignerFromPEM(kf.Alg, kf.Kid, []byte(kf.PrivPEM))
}
