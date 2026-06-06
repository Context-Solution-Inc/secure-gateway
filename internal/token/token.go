// Package token models the relay connection token (JWT) and verifies it with
// asymmetric public keys only (PRD FR-3, Appendix A). The relay never mints
// tokens; the Auth & License Service does (M2).
package token

import (
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

// Role is the device role on a pairing.
type Role string

const (
	RoleMobile  Role = "mobile"
	RoleDesktop Role = "desktop"
)

// Opposite returns the peer role, or "" if r is not a valid role.
func (r Role) Opposite() Role {
	switch r {
	case RoleMobile:
		return RoleDesktop
	case RoleDesktop:
		return RoleMobile
	default:
		return ""
	}
}

// Valid reports whether r is a recognized role.
func (r Role) Valid() bool { return r == RoleMobile || r == RoleDesktop }

// Claims maps the connection token claims (Appendix A). RegisteredClaims
// provides iss, aud, exp, iat, jti (ID), and sub.
type Claims struct {
	jwt.RegisteredClaims
	AccountID string `json:"account_id"`
	PairID    string `json:"pair_id"`
	DeviceID  string `json:"device_id"`
	Role      Role   `json:"role"`
	LicenseID string `json:"license_id"`
}

// Reason is a machine-readable connection-auth failure code returned to clients
// before the WebSocket upgrade and used as the relay_auth_failures_total label.
type Reason string

const (
	ReasonMissingToken  Reason = "missing_token"
	ReasonMalformed     Reason = "malformed_token"
	ReasonBadSignature  Reason = "bad_signature"
	ReasonExpired       Reason = "expired"
	ReasonNotYetValid   Reason = "not_yet_valid"
	ReasonWrongAudience Reason = "wrong_audience"
	ReasonWrongIssuer   Reason = "wrong_issuer"
	ReasonMissingClaim  Reason = "missing_claim"
	ReasonBadRole       Reason = "bad_role"
	ReasonUnknownKey    Reason = "unknown_key"
)

// AuthError carries a verification failure with its machine reason and the HTTP
// status the relay returns before upgrading (401 for credential problems, 403
// for policy/claim problems).
type AuthError struct {
	Reason     Reason
	HTTPStatus int
	Err        error
}

func (e *AuthError) Error() string {
	if e.Err != nil {
		return string(e.Reason) + ": " + e.Err.Error()
	}
	return string(e.Reason)
}

func (e *AuthError) Unwrap() error { return e.Err }

func authErr(reason Reason, status int, err error) *AuthError {
	return &AuthError{Reason: reason, HTTPStatus: status, Err: err}
}

// status helpers
func unauthorized(reason Reason, err error) *AuthError {
	return authErr(reason, http.StatusUnauthorized, err)
}
func forbidden(reason Reason, err error) *AuthError {
	return authErr(reason, http.StatusForbidden, err)
}
