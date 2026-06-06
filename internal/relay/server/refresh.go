package server

import (
	"context"
	"log/slog"

	"github.com/lley154/secure-gateway/internal/logging"
	"github.com/lley154/secure-gateway/internal/relay/protocol"
	"github.com/lley154/secure-gateway/internal/relay/session"
	"github.com/lley154/secure-gateway/internal/token"
)

// refresher re-validates auth_refresh tokens over the live socket (FR-3.5).
// The relay only checks the JWT; license re-checking happens at the Auth
// service when the client obtains the new token.
type refresher struct {
	verifier token.Verifier
	log      *slog.Logger
}

func (r *refresher) Refresh(ctx context.Context, s *session.Session, rawToken string) {
	if rawToken == "" {
		s.SendError(protocol.ErrUnauthorized, "empty refresh token")
		return
	}
	claims, ae := r.verifier.Verify(ctx, rawToken)
	if ae != nil {
		// Invalid refresh: surface the error but let the session live until its
		// current token expires (then it closes 4003). The bearer token string
		// is never logged.
		s.Log().Warn("auth_refresh rejected", logging.FieldReason, string(ae.Reason))
		s.SendError(protocol.ErrUnauthorized, string(ae.Reason))
		return
	}
	// The refreshed token must rebind the same identity; a token for a
	// different pair/role/device is a protocol violation (token swapping).
	if claims.PairID != s.Claims.PairID ||
		claims.Role != s.Claims.Role ||
		claims.AccountID != s.Claims.AccountID ||
		claims.DeviceID != s.Claims.DeviceID {
		s.Log().Warn("auth_refresh identity mismatch")
		s.CloseWith(protocol.CloseProtocol, "refresh identity mismatch")
		return
	}
	if claims.ExpiresAt != nil {
		s.SetExpiry(claims.ExpiresAt.Unix())
		s.Log().Debug("session token refreshed")
	}
}
