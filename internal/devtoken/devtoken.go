// Package devtoken mints signed connection tokens for development and tests.
//
// It exists so Go test clients and the cmd/devtoken CLI can obtain valid JWTs
// without the (not-yet-built) Auth & License Service. Signing-key handling
// lives here, deliberately separate from internal/token, so the relay binary
// never links token-minting code.
package devtoken

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/lley154/secure-gateway/internal/token"
)

// Signer mints tokens with a single asymmetric key.
type Signer struct {
	alg    string
	kid    string
	method jwt.SigningMethod
	priv   crypto.PrivateKey
	pub    crypto.PublicKey
}

// NewSigner generates a fresh keypair for the given algorithm ("ES256" or
// "EdDSA") and binds it to kid.
func NewSigner(alg, kid string) (*Signer, error) {
	s := &Signer{alg: alg, kid: kid}
	switch alg {
	case "ES256":
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		s.priv, s.pub, s.method = priv, &priv.PublicKey, jwt.SigningMethodES256
	case "EdDSA":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		s.priv, s.pub, s.method = priv, pub, jwt.SigningMethodEdDSA
	default:
		return nil, fmt.Errorf("unsupported algorithm %q (ES256 or EdDSA)", alg)
	}
	return s, nil
}

// TokenParams describe the claims to embed.
type TokenParams struct {
	Issuer    string
	Audience  string
	AccountID string
	PairID    string
	DeviceID  string
	Role      token.Role
	LicenseID string
	TTL       time.Duration
	IssuedAt  time.Time // zero => now
}

// Mint signs a connection token for the given parameters.
func (s *Signer) Mint(p TokenParams) (string, error) {
	now := p.IssuedAt
	if now.IsZero() {
		now = time.Now()
	}
	jti := make([]byte, 16)
	_, _ = rand.Read(jti)
	claims := token.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    p.Issuer,
			Audience:  jwt.ClaimStrings{p.Audience},
			Subject:   "device:" + p.DeviceID,
			ID:        base64.RawURLEncoding.EncodeToString(jti),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(p.TTL)),
		},
		AccountID: p.AccountID,
		PairID:    p.PairID,
		DeviceID:  p.DeviceID,
		Role:      p.Role,
		LicenseID: p.LicenseID,
	}
	t := jwt.NewWithClaims(s.method, claims)
	if s.kid != "" {
		t.Header["kid"] = s.kid
	}
	return t.SignedString(s.priv)
}

// PublicKeyPEM returns the PEM-encoded SubjectPublicKeyInfo for the verifier's
// static key source, with the kid as a PEM header.
func (s *Signer) PublicKeyPEM() ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(s.pub)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	if s.kid != "" {
		block.Headers = map[string]string{"kid": s.kid}
	}
	return pem.EncodeToMemory(block), nil
}

// JWKS returns a single-key JWKS document for the JWKS key source.
func (s *Signer) JWKS() ([]byte, error) {
	var jwk map[string]string
	switch pub := s.pub.(type) {
	case *ecdsa.PublicKey:
		byteLen := (pub.Curve.Params().BitSize + 7) / 8
		jwk = map[string]string{
			"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": s.kid,
			"x": base64.RawURLEncoding.EncodeToString(pub.X.FillBytes(make([]byte, byteLen))),
			"y": base64.RawURLEncoding.EncodeToString(pub.Y.FillBytes(make([]byte, byteLen))),
		}
	case ed25519.PublicKey:
		jwk = map[string]string{
			"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig", "kid": s.kid,
			"x": base64.RawURLEncoding.EncodeToString(pub),
		}
	default:
		return nil, fmt.Errorf("unsupported public key type %T", s.pub)
	}
	return json.Marshal(map[string]any{"keys": []map[string]string{jwk}})
}

// Algorithm reports the signing algorithm name.
func (s *Signer) Algorithm() string { return s.alg }

// PrivateKeyPEM returns the PEM-encoded PKCS#8 private key, for persistence by
// the devtoken CLI so the same key mints tokens across invocations.
func (s *Signer) PrivateKeyPEM() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(s.priv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// SignerFromPEM reconstructs a Signer from a previously exported PKCS#8 private
// key PEM.
func SignerFromPEM(alg, kid string, privPEM []byte) (*Signer, error) {
	block, _ := pem.Decode(privPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM private key block found")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	s := &Signer{alg: alg, kid: kid}
	switch alg {
	case "ES256":
		priv, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key file alg ES256 but key type is %T", key)
		}
		s.priv, s.pub, s.method = priv, &priv.PublicKey, jwt.SigningMethodES256
	case "EdDSA":
		priv, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key file alg EdDSA but key type is %T", key)
		}
		s.priv, s.pub, s.method = priv, priv.Public(), jwt.SigningMethodEdDSA
	default:
		return nil, fmt.Errorf("unsupported algorithm %q", alg)
	}
	return s, nil
}
