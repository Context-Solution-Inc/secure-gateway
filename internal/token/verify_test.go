package token_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/context-solutions-inc/secure-gateway/internal/devtoken"
	"github.com/context-solutions-inc/secure-gateway/internal/token"
)

const (
	testIssuer = "https://auth.test"
	testAud    = "relay"
)

func newSigner(t *testing.T, alg string) *devtoken.Signer {
	t.Helper()
	s, err := devtoken.NewSigner(alg, "kid-1")
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return s
}

func verifierFor(t *testing.T, s *devtoken.Signer, algs ...string) token.Verifier {
	t.Helper()
	pem, err := s.PublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	ks, err := token.NewStaticSource(pem)
	if err != nil {
		t.Fatal(err)
	}
	if len(algs) == 0 {
		algs = []string{s.Algorithm()}
	}
	v, err := token.NewVerifier(token.Config{
		Issuer: testIssuer, Audience: testAud, AllowedAlgs: algs,
		Leeway: 30 * time.Second, KeySource: ks,
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func goodParams() devtoken.TokenParams {
	return devtoken.TokenParams{
		Issuer: testIssuer, Audience: testAud, AccountID: "acct_1",
		PairID: "pair_1", DeviceID: "dev_1", Role: token.RoleMobile,
		LicenseID: "lic_1", TTL: 10 * time.Minute,
	}
}

func TestVerifyValid(t *testing.T) {
	for _, alg := range []string{"ES256", "EdDSA"} {
		t.Run(alg, func(t *testing.T) {
			s := newSigner(t, alg)
			v := verifierFor(t, s)
			tok, err := s.Mint(goodParams())
			if err != nil {
				t.Fatal(err)
			}
			claims, ae := v.Verify(context.Background(), tok)
			if ae != nil {
				t.Fatalf("verify failed: %v", ae)
			}
			if claims.PairID != "pair_1" || claims.Role != token.RoleMobile || claims.LicenseID != "lic_1" {
				t.Errorf("claims mismatch: %+v", claims)
			}
		})
	}
}

func TestVerifyReasons(t *testing.T) {
	tests := []struct {
		name   string
		params func(devtoken.TokenParams) devtoken.TokenParams
		want   token.Reason
		status int
	}{
		{"expired", func(p devtoken.TokenParams) devtoken.TokenParams {
			p.IssuedAt = time.Now().Add(-time.Hour)
			p.TTL = time.Minute
			return p
		}, token.ReasonExpired, http.StatusUnauthorized},
		{"wrong audience", func(p devtoken.TokenParams) devtoken.TokenParams {
			p.Audience = "other"
			return p
		}, token.ReasonWrongAudience, http.StatusForbidden},
		{"wrong issuer", func(p devtoken.TokenParams) devtoken.TokenParams {
			p.Issuer = "https://evil.test"
			return p
		}, token.ReasonWrongIssuer, http.StatusForbidden},
		{"missing pair", func(p devtoken.TokenParams) devtoken.TokenParams {
			p.PairID = ""
			return p
		}, token.ReasonMissingClaim, http.StatusForbidden},
		{"missing license", func(p devtoken.TokenParams) devtoken.TokenParams {
			p.LicenseID = ""
			return p
		}, token.ReasonMissingClaim, http.StatusForbidden},
		{"bad role", func(p devtoken.TokenParams) devtoken.TokenParams {
			p.Role = token.Role("admin")
			return p
		}, token.ReasonBadRole, http.StatusForbidden},
	}
	s := newSigner(t, "ES256")
	v := verifierFor(t, s)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok, err := s.Mint(tt.params(goodParams()))
			if err != nil {
				t.Fatal(err)
			}
			_, ae := v.Verify(context.Background(), tok)
			if ae == nil {
				t.Fatalf("expected error %q, got nil", tt.want)
			}
			if ae.Reason != tt.want {
				t.Errorf("reason = %q, want %q", ae.Reason, tt.want)
			}
			if ae.HTTPStatus != tt.status {
				t.Errorf("status = %d, want %d", ae.HTTPStatus, tt.status)
			}
		})
	}
}

func TestVerifyEmptyToken(t *testing.T) {
	s := newSigner(t, "ES256")
	v := verifierFor(t, s)
	_, ae := v.Verify(context.Background(), "")
	if ae == nil || ae.Reason != token.ReasonMissingToken {
		t.Fatalf("got %v, want missing_token", ae)
	}
}

func TestVerifyMalformed(t *testing.T) {
	s := newSigner(t, "ES256")
	v := verifierFor(t, s)
	_, ae := v.Verify(context.Background(), "not.a.jwt")
	if ae == nil || ae.Reason != token.ReasonMalformed {
		t.Fatalf("got %v, want malformed", ae)
	}
}

func TestVerifyBadSignature(t *testing.T) {
	signer := newSigner(t, "ES256")
	other := newSigner(t, "ES256") // verifier trusts a different key
	v := verifierFor(t, other)
	tok, err := signer.Mint(goodParams())
	if err != nil {
		t.Fatal(err)
	}
	_, ae := v.Verify(context.Background(), tok)
	if ae == nil {
		t.Fatal("expected signature failure")
	}
	if ae.Reason != token.ReasonBadSignature && ae.Reason != token.ReasonMalformed {
		t.Errorf("reason = %q, want bad_signature/malformed", ae.Reason)
	}
}

// A symmetric (HS256) token must be rejected even if it is otherwise well-formed:
// the parser's algorithm allow-list forbids it.
func TestVerifyRejectsSymmetricAlg(t *testing.T) {
	s := newSigner(t, "ES256")
	v := verifierFor(t, s)
	claims := jwt.MapClaims{"iss": testIssuer, "aud": testAud, "exp": time.Now().Add(time.Hour).Unix()}
	hs := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tok, err := hs.SignedString([]byte("shared-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ae := v.Verify(context.Background(), tok); ae == nil {
		t.Fatal("HS256 token must be rejected")
	}
}

func TestVerifyViaJWKS(t *testing.T) {
	s := newSigner(t, "ES256")
	jwksDoc, err := s.JWKS()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksDoc)
	}))
	defer srv.Close()

	ks := token.NewJWKSSource(srv.URL)
	v, err := token.NewVerifier(token.Config{
		Issuer: testIssuer, Audience: testAud, AllowedAlgs: []string{"ES256"},
		Leeway: 30 * time.Second, KeySource: ks,
	})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := s.Mint(goodParams())
	if err != nil {
		t.Fatal(err)
	}
	if _, ae := v.Verify(context.Background(), tok); ae != nil {
		t.Fatalf("jwks verify failed: %v", ae)
	}
}
