package authservice

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/lley154/secure-gateway/internal/authstore"
	"github.com/lley154/secure-gateway/internal/license"
	"github.com/lley154/secure-gateway/internal/logging"
	"github.com/lley154/secure-gateway/internal/signer"
	"github.com/lley154/secure-gateway/internal/token"
)

// maxBodyBytes bounds request bodies (webhooks and small JSON).
const maxBodyBytes = 1 << 20 // 1 MiB

// --- JSON helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func decodeJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

// --- JWKS ---

func (s *Service) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	doc, err := s.signer.JWKS()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "jwks_error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(doc)
}

// --- Accounts (admin-provisioned credential) ---

type accountReq struct {
	AccountID string `json:"account_id"`
}
type accountResp struct {
	AccountID string `json:"account_id"`
	Secret    string `json:"secret"`
}

// handleCreateAccount mints (or rotates) an account credential. Gated by the
// admin key; this is the M2 seam for the account backend (OQ5) to provision an
// auth-service secret. The secret is returned once and stored only as a hash.
func (s *Service) handleCreateAccount(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	var req accountReq
	if err := decodeJSON(r, &req); err != nil || req.AccountID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	secret := newAccountSecret(req.AccountID)
	acct := authstore.Account{ID: req.AccountID, SecretHash: hashSecret(secret), CreatedAt: s.now()}
	if err := s.store.UpsertAccount(r.Context(), acct); err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error")
		return
	}
	writeJSON(w, http.StatusOK, accountResp{AccountID: req.AccountID, Secret: secret})
}

// --- Devices ---

type deviceReq struct {
	Role      string `json:"role"`
	PublicKey string `json:"public_key,omitempty"` // base64; optional in M2 (M3 QR flow fills it)
}
type deviceResp struct {
	DeviceID string `json:"device_id"`
}

func (s *Service) handleRegisterDevice(w http.ResponseWriter, r *http.Request) {
	accountID, err := s.authenticateAccount(r.Context(), r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req deviceReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	role := token.Role(req.Role)
	if !role.Valid() {
		writeErr(w, http.StatusBadRequest, "bad_role")
		return
	}
	var pub []byte
	if req.PublicKey != "" {
		if pub, err = base64.StdEncoding.DecodeString(req.PublicKey); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_public_key")
			return
		}
	}
	dev := authstore.Device{ID: authstore.NewID("dev"), AccountID: accountID, Role: role, PublicKey: pub, CreatedAt: s.now()}
	if err := s.store.UpsertDevice(r.Context(), dev); err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error")
		return
	}
	writeJSON(w, http.StatusOK, deviceResp{DeviceID: dev.ID})
}

// --- Connection tokens ---

type tokenReq struct {
	DeviceID string `json:"device_id"`
	PairID   string `json:"pair_id"`
}
type tokenResp struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"` // seconds
}

func (s *Service) handleIssueToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	accountID, err := s.authenticateAccount(ctx, r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req tokenReq
	if err := decodeJSON(r, &req); err != nil || req.DeviceID == "" || req.PairID == "" {
		s.rejectToken(w, http.StatusBadRequest, "bad_request")
		return
	}
	pairing, err := s.store.GetPairing(ctx, req.PairID)
	if err != nil || pairing.AccountID != accountID || pairing.Status != authstore.PairingActive {
		s.rejectToken(w, http.StatusForbidden, "pairing_invalid")
		return
	}
	dev, err := s.store.GetDevice(ctx, req.DeviceID)
	if err != nil || dev.AccountID != accountID {
		s.rejectToken(w, http.StatusForbidden, "device_invalid")
		return
	}
	if !pairingHasDevice(pairing, dev) {
		s.rejectToken(w, http.StatusForbidden, "device_not_in_pairing")
		return
	}
	lic, ok := s.pairingIssuable(ctx, pairing)
	if !ok {
		s.rejectToken(w, http.StatusForbidden, "license_invalid")
		return
	}
	s.issueTokenPair(ctx, w, accountID, pairing, dev, lic)
}

type refreshReq struct {
	RefreshToken string `json:"refresh_token"`
}

func (s *Service) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req refreshReq
	if err := decodeJSON(r, &req); err != nil || req.RefreshToken == "" {
		s.rejectToken(w, http.StatusBadRequest, "bad_request")
		return
	}
	rt, err := s.store.GetRefreshToken(ctx, hashSecret(req.RefreshToken))
	if err != nil || !rt.Active(s.now()) {
		s.rejectToken(w, http.StatusUnauthorized, "refresh_invalid")
		return
	}
	pairing, err := s.store.GetPairing(ctx, rt.PairID)
	if err != nil || pairing.Status != authstore.PairingActive {
		_ = s.store.RevokeRefreshToken(ctx, rt.ID)
		s.rejectToken(w, http.StatusForbidden, "pairing_invalid")
		return
	}
	dev, err := s.store.GetDevice(ctx, rt.DeviceID)
	if err != nil {
		s.rejectToken(w, http.StatusForbidden, "device_invalid")
		return
	}
	// Re-check license validity on every refresh (FR-3.5, PRD §6.5 #1).
	lic, ok := s.pairingIssuable(ctx, pairing)
	if !ok {
		_ = s.store.RevokeRefreshToken(ctx, rt.ID)
		s.rejectToken(w, http.StatusForbidden, "license_invalid")
		return
	}
	// Rotate: the presented refresh token is single-use.
	_ = s.store.RevokeRefreshToken(ctx, rt.ID)
	s.issueTokenPair(ctx, w, rt.AccountID, pairing, dev, lic)
}

// issueTokenPair mints a connection JWT plus a fresh refresh token and writes
// the response.
func (s *Service) issueTokenPair(ctx context.Context, w http.ResponseWriter, accountID string, pairing authstore.Pairing, dev authstore.Device, lic authstore.License) {
	jwtStr, err := s.signer.Mint(signer.TokenParams{
		Issuer: s.issuer, Audience: s.audience, AccountID: accountID, PairID: pairing.PairID,
		DeviceID: dev.ID, Role: dev.Role, LicenseID: lic.ID, TTL: s.tokenTTL,
	})
	if err != nil {
		s.rejectToken(w, http.StatusInternalServerError, "sign_error")
		return
	}
	refreshSecret := authstore.NewID("rt")
	rt := authstore.RefreshToken{
		ID: hashSecret(refreshSecret), DeviceID: dev.ID, AccountID: accountID,
		PairID: pairing.PairID, ExpiresAt: s.now().Add(s.refreshTTL),
	}
	if err := s.store.PutRefreshToken(ctx, rt); err != nil {
		s.rejectToken(w, http.StatusInternalServerError, "store_error")
		return
	}
	if s.metrics != nil {
		s.metrics.TokensIssued.WithLabelValues(string(dev.Role)).Inc()
	}
	writeJSON(w, http.StatusOK, tokenResp{
		Token: jwtStr, RefreshToken: refreshSecret, ExpiresIn: int(s.tokenTTL / time.Second),
	})
}

func (s *Service) rejectToken(w http.ResponseWriter, status int, code string) {
	if s.metrics != nil {
		s.metrics.TokenRequestsRejected.WithLabelValues(code).Inc()
	}
	writeErr(w, status, code)
}

// --- Webhooks ---

func (s *Service) handleWebhook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		s.rejectWebhook(w, http.StatusBadRequest, "read_error")
		return
	}
	ev, err := s.proc.Verify(body, r.Header.Get("Stripe-Signature"))
	if err != nil {
		// Log the real cause (signature vs. tolerance) — the response stays a
		// generic bad_signature so we don't leak verification internals.
		s.log.Warn("webhook signature verification failed", logging.FieldReason, err.Error())
		s.rejectWebhook(w, http.StatusBadRequest, "bad_signature")
		return
	}
	if s.metrics != nil {
		s.metrics.WebhooksReceived.WithLabelValues(string(ev.Type)).Inc()
	}
	inserted, err := s.proc.Record(ctx, ev, body)
	if err != nil {
		s.rejectWebhook(w, http.StatusInternalServerError, "record_error")
		return
	}
	if !inserted {
		// Already processed (Stripe retry); idempotent no-op.
		writeJSON(w, http.StatusOK, map[string]bool{"duplicate": true})
		return
	}
	if err := s.proc.Process(ctx, ev); err != nil {
		// Durably recorded as failed; the retry worker will reprocess. Return 200
		// so Stripe stops retrying (we own retries).
		if s.metrics != nil {
			s.metrics.WebhookProcessingFailures.Inc()
		}
		s.log.Error("webhook processing failed", "event_id", ev.ID, "type", string(ev.Type), logging.FieldReason, err.Error())
		writeJSON(w, http.StatusOK, map[string]bool{"queued": true})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Service) rejectWebhook(w http.ResponseWriter, status int, code string) {
	if s.metrics != nil {
		s.metrics.WebhooksRejected.WithLabelValues(code).Inc()
	}
	writeErr(w, status, code)
}

// --- Health ---

func (s *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	if err := s.store.HealthCheck(r.Context()); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "store_unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// --- shared validity helpers ---

// pairingIssuable resolves the license behind a pairing and reports whether a
// token may be issued (PRD §6.5 #1).
func (s *Service) pairingIssuable(ctx context.Context, pairing authstore.Pairing) (authstore.License, bool) {
	lic, err := s.store.GetLicense(ctx, pairing.LicenseID)
	if err != nil {
		return authstore.License{}, false
	}
	return s.licenseIssuable(ctx, lic)
}

func (s *Service) licenseIssuable(ctx context.Context, lic authstore.License) (authstore.License, bool) {
	if lic.Status != authstore.LicenseActive {
		return lic, false
	}
	sub, err := s.store.GetSubscription(ctx, lic.SubscriptionID)
	if err != nil {
		return lic, false
	}
	return lic, license.Issuable(license.Evaluate(sub, s.now()))
}

// deviceForRole fetches a device and verifies it belongs to accountID with the
// expected role.
func (s *Service) deviceForRole(ctx context.Context, deviceID, accountID string, role token.Role) (authstore.Device, bool) {
	dev, err := s.store.GetDevice(ctx, deviceID)
	if err != nil || dev.AccountID != accountID || dev.Role != role {
		return authstore.Device{}, false
	}
	return dev, true
}

func pairingHasDevice(p authstore.Pairing, dev authstore.Device) bool {
	switch dev.Role {
	case token.RoleMobile:
		return p.MobileDeviceID == dev.ID
	case token.RoleDesktop:
		return p.DesktopDeviceID == dev.ID
	default:
		return false
	}
}
