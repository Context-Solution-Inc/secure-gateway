package token

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"sync"
	"time"
)

// KeySource supplies token-verification public keys by key id (kid).
type KeySource interface {
	// PublicKey returns the public key for kid. A source backing a single key
	// may ignore kid and return that key (kid == "").
	PublicKey(ctx context.Context, kid string) (crypto.PublicKey, error)
}

// ErrUnknownKey is returned when no key matches the requested kid.
var ErrUnknownKey = errors.New("no verification key for kid")

// --- Static PEM source (dev/test; paired with cmd/devtoken) ---

// StaticSource holds public keys parsed from a PEM file. If the PEM contains a
// single key, it answers any kid (including "").
type StaticSource struct {
	byKID  map[string]crypto.PublicKey
	single crypto.PublicKey
}

// NewStaticSourceFromFile loads PEM-encoded public key(s) from path. Each block
// may carry a "kid" header to bind it to a key id.
func NewStaticSourceFromFile(path string) (*StaticSource, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key file: %w", err)
	}
	return NewStaticSource(data)
}

// NewStaticSource parses PEM-encoded public key(s) from data.
func NewStaticSource(pemData []byte) (*StaticSource, error) {
	s := &StaticSource{byKID: map[string]crypto.PublicKey{}}
	rest := pemData
	var count int
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		key, err := parsePEMPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		count++
		s.single = key
		if kid := block.Headers["kid"]; kid != "" {
			s.byKID[kid] = key
		}
	}
	if count == 0 {
		return nil, errors.New("no PEM public key blocks found")
	}
	if count > 1 {
		s.single = nil // ambiguous without kid
	}
	return s, nil
}

func (s *StaticSource) PublicKey(_ context.Context, kid string) (crypto.PublicKey, error) {
	if kid != "" {
		if k, ok := s.byKID[kid]; ok {
			return k, nil
		}
	}
	if s.single != nil {
		return s.single, nil
	}
	if k, ok := s.byKID[kid]; ok {
		return k, nil
	}
	return nil, ErrUnknownKey
}

func parsePEMPublicKey(der []byte) (crypto.PublicKey, error) {
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	switch key.(type) {
	case *ecdsa.PublicKey, ed25519.PublicKey:
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported public key type %T (asymmetric ECDSA/Ed25519 only)", key)
	}
}

// --- JWKS source (production; served by the Auth service) ---

// JWKSSource fetches a JWKS document over HTTP and caches keys by kid, with a
// minimum refresh interval to absorb key rotation (PRD §10.2: rotate <= 90d).
type JWKSSource struct {
	url     string
	client  *http.Client
	minWait time.Duration

	mu        sync.RWMutex
	keys      map[string]crypto.PublicKey
	lastFetch time.Time
}

// NewJWKSSource creates a JWKS-backed key source.
func NewJWKSSource(url string) *JWKSSource {
	return &JWKSSource{
		url:     url,
		client:  &http.Client{Timeout: 5 * time.Second},
		minWait: 5 * time.Minute,
		keys:    map[string]crypto.PublicKey{},
	}
}

func (s *JWKSSource) PublicKey(ctx context.Context, kid string) (crypto.PublicKey, error) {
	s.mu.RLock()
	k, ok := s.keys[kid]
	s.mu.RUnlock()
	if ok {
		return k, nil
	}
	// Cache miss: refresh once (rate-limited) to pick up rotated keys.
	if err := s.refresh(ctx); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if k, ok := s.keys[kid]; ok {
		return k, nil
	}
	return nil, ErrUnknownKey
}

func (s *JWKSSource) refresh(ctx context.Context) error {
	s.mu.Lock()
	if !s.lastFetch.IsZero() && time.Since(s.lastFetch) < s.minWait {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch jwks: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	keys, err := parseJWKS(body)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.keys = keys
	s.lastFetch = time.Now()
	s.mu.Unlock()
	return nil
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

func parseJWKS(data []byte) (map[string]crypto.PublicKey, error) {
	var doc jwks
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse jwks: %w", err)
	}
	out := make(map[string]crypto.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		pub, err := jwkToPublic(k)
		if err != nil {
			return nil, err
		}
		out[k.Kid] = pub
	}
	if len(out) == 0 {
		return nil, errors.New("jwks contained no keys")
	}
	return out, nil
}

func jwkToPublic(k jwk) (crypto.PublicKey, error) {
	switch k.Kty {
	case "EC": // ES256/384/512
		xb, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("jwk %q: bad x: %w", k.Kid, err)
		}
		yb, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, fmt.Errorf("jwk %q: bad y: %w", k.Kid, err)
		}
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("jwk %q: unsupported curve %q", k.Kid, k.Crv)
		}
		return &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(xb),
			Y:     new(big.Int).SetBytes(yb),
		}, nil
	case "OKP": // EdDSA (Ed25519)
		if k.Crv != "Ed25519" {
			return nil, fmt.Errorf("jwk %q: unsupported OKP curve %q", k.Kid, k.Crv)
		}
		xb, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("jwk %q: bad x: %w", k.Kid, err)
		}
		if len(xb) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("jwk %q: bad ed25519 key length %d", k.Kid, len(xb))
		}
		return ed25519.PublicKey(xb), nil
	default:
		return nil, fmt.Errorf("jwk %q: unsupported kty %q", k.Kid, k.Kty)
	}
}
