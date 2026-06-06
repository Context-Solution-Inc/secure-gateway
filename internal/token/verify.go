package token

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Verifier validates a raw bearer token and returns vetted Claims, or an
// *AuthError carrying a machine reason and HTTP status.
type Verifier interface {
	Verify(ctx context.Context, rawToken string) (*Claims, *AuthError)
}

// Config configures a jwtVerifier.
type Config struct {
	Issuer      string        // expected iss (required)
	Audience    string        // expected aud (required)
	AllowedAlgs []string      // asymmetric algorithms only, e.g. ES256, EdDSA
	Leeway      time.Duration // clock-skew tolerance
	KeySource   KeySource     // public key lookup by kid
}

type jwtVerifier struct {
	cfg    Config
	parser *jwt.Parser
}

// NewVerifier builds a Verifier. It rejects symmetric and "none" algorithms at
// the parser level so a forged alg cannot bypass asymmetric verification.
func NewVerifier(cfg Config) (Verifier, error) {
	if cfg.Issuer == "" || cfg.Audience == "" {
		return nil, errors.New("token verifier requires issuer and audience")
	}
	if cfg.KeySource == nil {
		return nil, errors.New("token verifier requires a key source")
	}
	if len(cfg.AllowedAlgs) == 0 {
		return nil, errors.New("token verifier requires at least one allowed algorithm")
	}
	for _, a := range cfg.AllowedAlgs {
		if !isAsymmetricAlg(a) {
			return nil, fmt.Errorf("disallowed token algorithm %q (asymmetric only)", a)
		}
	}
	parser := jwt.NewParser(
		jwt.WithValidMethods(cfg.AllowedAlgs),
		jwt.WithIssuer(cfg.Issuer),
		jwt.WithAudience(cfg.Audience),
		jwt.WithLeeway(cfg.Leeway),
		jwt.WithExpirationRequired(),
	)
	return &jwtVerifier{cfg: cfg, parser: parser}, nil
}

func isAsymmetricAlg(a string) bool {
	switch a {
	case "ES256", "ES384", "ES512", "EdDSA", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		return true
	default:
		return false
	}
}

func (v *jwtVerifier) Verify(ctx context.Context, rawToken string) (*Claims, *AuthError) {
	if rawToken == "" {
		return nil, unauthorized(ReasonMissingToken, errors.New("empty token"))
	}

	claims := &Claims{}
	keyFn := func(t *jwt.Token) (interface{}, error) {
		kid, _ := t.Header["kid"].(string)
		return v.cfg.KeySource.PublicKey(ctx, kid)
	}

	tok, err := v.parser.ParseWithClaims(rawToken, claims, keyFn)
	if err != nil {
		return nil, classify(err)
	}
	if !tok.Valid {
		return nil, unauthorized(ReasonBadSignature, errors.New("token invalid"))
	}

	if ae := validateCustomClaims(claims); ae != nil {
		return nil, ae
	}
	return claims, nil
}

// classify maps jwt validation errors to machine reasons + HTTP status.
func classify(err error) *AuthError {
	switch {
	case errors.Is(err, jwt.ErrTokenExpired):
		return unauthorized(ReasonExpired, err)
	case errors.Is(err, jwt.ErrTokenNotValidYet):
		return unauthorized(ReasonNotYetValid, err)
	case errors.Is(err, jwt.ErrTokenInvalidAudience):
		return forbidden(ReasonWrongAudience, err)
	case errors.Is(err, jwt.ErrTokenInvalidIssuer):
		return forbidden(ReasonWrongIssuer, err)
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return unauthorized(ReasonBadSignature, err)
	case errors.Is(err, ErrUnknownKey):
		return unauthorized(ReasonUnknownKey, err)
	case errors.Is(err, jwt.ErrTokenMalformed),
		errors.Is(err, jwt.ErrTokenUnverifiable):
		return unauthorized(ReasonMalformed, err)
	default:
		// Unsigned-key lookups surface as unverifiable; treat unknown as malformed
		// (credential problem) rather than leaking detail.
		return unauthorized(ReasonMalformed, err)
	}
}

func validateCustomClaims(c *Claims) *AuthError {
	if c.AccountID == "" {
		return forbidden(ReasonMissingClaim, errors.New("missing account_id"))
	}
	if c.PairID == "" {
		return forbidden(ReasonMissingClaim, errors.New("missing pair_id"))
	}
	if c.DeviceID == "" {
		return forbidden(ReasonMissingClaim, errors.New("missing device_id"))
	}
	if c.LicenseID == "" {
		return forbidden(ReasonMissingClaim, errors.New("missing license_id"))
	}
	if !c.Role.Valid() {
		return forbidden(ReasonBadRole, fmt.Errorf("invalid role %q", c.Role))
	}
	return nil
}
