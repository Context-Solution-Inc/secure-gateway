package authservice

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/lley154/secure-gateway/internal/authstore"
	"github.com/lley154/secure-gateway/internal/backplane"
	"github.com/lley154/secure-gateway/internal/logging"
	"github.com/lley154/secure-gateway/internal/token"
)

// pairingQRVersion versions the QR payload schema (FR-2.1, §8.4). A future
// client uses this to distinguish the relay-pairing QR from the legacy
// local-sync QR; the legacy fallback itself lives in the client apps, not here.
const pairingQRVersion = 1

// --- POST /v1/pairing-tokens : desktop issues a one-time pairing token (FR-2.1) ---

type pairingTokenReq struct {
	LicenseID        string `json:"license_id"`
	DesktopDeviceID  string `json:"desktop_device_id"`
	DesktopPublicKey string `json:"desktop_public_key,omitempty"` // base64; optional if already registered
}

// qrPayload is the versioned QR code content the desktop renders (FR-2.1).
type qrPayload struct {
	V               int               `json:"v"`
	PairingToken    string            `json:"pairing_token"`
	DesktopPubKey   string            `json:"desktop_pubkey"` // base64
	DesktopDeviceID string            `json:"desktop_device_id"`
	Endpoints       map[string]string `json:"endpoints"` // relay, auth
}

type pairingTokenResp struct {
	PairingToken string    `json:"pairing_token"`
	ExpiresIn    int       `json:"expires_in"` // seconds
	QR           qrPayload `json:"qr"`
}

func (s *Service) handleCreatePairingToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	accountID, err := s.authenticateAccount(ctx, r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req pairingTokenReq
	if err := decodeJSON(r, &req); err != nil || req.LicenseID == "" || req.DesktopDeviceID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	lic, err := s.store.GetLicense(ctx, req.LicenseID)
	if err != nil || lic.AccountID != accountID {
		writeErr(w, http.StatusNotFound, "license_not_found")
		return
	}
	// License must currently be valid to start pairing (PRD §6.5 #1).
	if _, ok := s.licenseIssuable(ctx, lic); !ok {
		writeErr(w, http.StatusForbidden, "license_invalid")
		return
	}
	// The desktop device must belong to the account with the desktop role.
	dev, ok := s.deviceForRole(ctx, req.DesktopDeviceID, accountID, token.RoleDesktop)
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad_devices")
		return
	}
	// Capacity: pairs in use < max_pairs (FR-2.2). Re-pairing reuses the existing
	// slot for this desktop, so only a brand-new pair is gated here. The
	// authoritative check runs again at completion.
	_, rePair, err := s.activePairingForDesktop(ctx, lic.ID, dev.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error")
		return
	}
	if !rePair {
		if ok, _, err := s.capacityAvailable(ctx, lic); err != nil {
			writeErr(w, http.StatusInternalServerError, "store_error")
			return
		} else if !ok {
			writeErr(w, http.StatusConflict, "capacity_exceeded")
			return
		}
	}
	// Store the desktop's X25519 public key if supplied (the QR needs it).
	if req.DesktopPublicKey != "" {
		pub, err := base64.StdEncoding.DecodeString(req.DesktopPublicKey)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_public_key")
			return
		}
		dev.PublicKey = pub
		if err := s.store.UpsertDevice(ctx, dev); err != nil {
			writeErr(w, http.StatusInternalServerError, "store_error")
			return
		}
	}
	if len(dev.PublicKey) == 0 {
		// No key on file and none supplied; the QR cannot carry the desktop key.
		writeErr(w, http.StatusBadRequest, "missing_public_key")
		return
	}

	secret := authstore.NewID("pt")
	now := s.now()
	pt := authstore.PairingToken{
		ID: hashSecret(secret), AccountID: accountID, LicenseID: lic.ID,
		DesktopDeviceID: dev.ID, ExpiresAt: now.Add(s.pairingTokenTTL),
	}
	if err := s.store.CreatePairingToken(ctx, pt); err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error")
		return
	}
	writeJSON(w, http.StatusOK, pairingTokenResp{
		PairingToken: secret,
		ExpiresIn:    int(s.pairingTokenTTL / time.Second),
		QR: qrPayload{
			V: pairingQRVersion, PairingToken: secret,
			DesktopPubKey:   base64.StdEncoding.EncodeToString(dev.PublicKey),
			DesktopDeviceID: dev.ID,
			Endpoints:       map[string]string{"relay": s.relayURL, "auth": s.authURL},
		},
	})
}

// --- POST /v1/pairings : mobile completes pairing with the token (FR-2.2) ---

type completePairingReq struct {
	PairingToken string `json:"pairing_token"`
	// MobileDeviceID is optional (security L2): when empty, the gateway registers
	// the mobile device from MobilePublicKey under the token's account, authorized
	// by the pairing token, so the phone never needs the account secret. The legacy
	// flow (phone pre-registers with the account secret, then passes its id) still
	// works for back-compat with older SDKs.
	MobileDeviceID  string `json:"mobile_device_id,omitempty"`
	MobilePublicKey string `json:"mobile_public_key"` // base64
}
type completePairingResp struct {
	PairID           string `json:"pair_id"`
	DesktopPublicKey string `json:"desktop_public_key"`         // base64
	MobileDeviceID   string `json:"mobile_device_id,omitempty"` // the registered/resolved mobile device id (L2)
	PairCredential   string `json:"pair_credential,omitempty"`  // per-pair credential (L2); the phone authenticates with this, not the account secret
}

func (s *Service) handleCompletePairing(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req completePairingReq
	// MobileDeviceID is optional (L2: the gateway registers the device when it is
	// absent); the public key is always required.
	if err := decodeJSON(r, &req); err != nil || req.PairingToken == "" || req.MobilePublicKey == "" {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	// The pairing token itself authorizes this call (FR-2.2); it is bound to the
	// desktop's account/license at issue time, so the mobile cannot forge them.
	pt, err := s.store.GetPairingToken(ctx, hashSecret(req.PairingToken))
	if err != nil || !pt.Active(s.now()) {
		writeErr(w, http.StatusUnauthorized, "pairing_token_invalid")
		return
	}
	lic, err := s.store.GetLicense(ctx, pt.LicenseID)
	if err != nil {
		writeErr(w, http.StatusForbidden, "license_invalid")
		return
	}
	// Re-check validity at completion: the subscription may have lapsed since the
	// token was issued (PRD §6.5 #1).
	if _, ok := s.licenseIssuable(ctx, lic); !ok {
		writeErr(w, http.StatusForbidden, "license_invalid")
		return
	}
	mobilePub, err := base64.StdEncoding.DecodeString(req.MobilePublicKey)
	if err != nil || len(mobilePub) == 0 {
		writeErr(w, http.StatusBadRequest, "bad_public_key")
		return
	}
	// Resolve the mobile device. L2: when the phone sends no device id, register it
	// here from its public key under the token's account (authorized by the pairing
	// token), so the phone never needs the account secret. The legacy path (phone
	// pre-registered with the account secret and passes its id) still validates the
	// device belongs to the token's account with the mobile role.
	var mobile authstore.Device
	if req.MobileDeviceID != "" {
		var ok bool
		if mobile, ok = s.deviceForRole(ctx, req.MobileDeviceID, pt.AccountID, token.RoleMobile); !ok {
			writeErr(w, http.StatusBadRequest, "bad_devices")
			return
		}
	} else {
		mobile, err = s.registerOrFindDevice(ctx, pt.AccountID, token.RoleMobile, mobilePub)
		if errors.Is(err, errDeviceLimit) {
			writeErr(w, http.StatusConflict, "device_limit")
			return
		} else if err != nil {
			writeErr(w, http.StatusInternalServerError, "store_error")
			return
		}
	}
	desktop, err := s.store.GetDevice(ctx, pt.DesktopDeviceID)
	if err != nil || len(desktop.PublicKey) == 0 {
		writeErr(w, http.StatusForbidden, "desktop_unavailable")
		return
	}

	// Re-pairing (FR-2.4): if an active pairing already exists for this license
	// with the same desktop, replace the device entry in place rather than
	// consuming another license slot.
	existing, rePair, err := s.activePairingForDesktop(ctx, lic.ID, pt.DesktopDeviceID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error")
		return
	}
	pairID := authstore.NewID("pair")
	var maxPairs int
	if rePair {
		pairID = existing.PairID
	} else {
		// New pairing: capacity gate (pairs in use < max_pairs, FR-2.2). This
		// advisory pre-check fails fast before the token is consumed; the
		// authoritative count+insert at CreatePairingWithinCapacity below is
		// atomic, closing the TOCTOU under concurrent completions (SG-16).
		ok, mp, err := s.capacityAvailable(ctx, lic)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "store_error")
			return
		}
		if !ok {
			writeErr(w, http.StatusConflict, "capacity_exceeded")
			return
		}
		maxPairs = mp
	}

	// Consume the token first (atomic single-use) so a replayed completion can
	// never create a second pairing or mutate state (FR-2.1).
	if err := s.store.ConsumePairingToken(ctx, pt.ID, pairID, s.now()); err != nil {
		if errors.Is(err, authstore.ErrConflict) {
			writeErr(w, http.StatusConflict, "pairing_token_used")
			return
		}
		writeErr(w, http.StatusInternalServerError, "store_error")
		return
	}

	// Persist the mobile's X25519 public key on its device record.
	mobile.PublicKey = mobilePub
	if err := s.store.UpsertDevice(ctx, mobile); err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error")
		return
	}

	if rePair {
		evicted := existing.MobileDeviceID
		if err := s.store.UpdatePairingDevices(ctx, pairID, mobile.ID, desktop.ID); err != nil {
			writeErr(w, http.StatusInternalServerError, "store_error")
			return
		}
		// Revoke the evicted mobile device's refresh tokens so it cannot mint new
		// connection tokens for this pairing after being replaced (SG-04, FR-2.4).
		// The revocation event below only cuts the live session; without this the
		// evicted device could refresh and reconnect for up to the refresh TTL.
		if evicted != "" && evicted != mobile.ID {
			if err := s.store.RevokeRefreshTokensByDevice(ctx, evicted, s.now()); err != nil {
				s.log.Error("revoke evicted device refresh tokens failed",
					logging.FieldDeviceID, evicted, logging.FieldReason, err.Error())
			}
		}
		// Cut any live session for the replaced device(s) (FR-2.4).
		s.publishRevocation(ctx, backplane.RevocationEvent{PairID: pairID})
	} else {
		p := authstore.Pairing{
			PairID: pairID, LicenseID: lic.ID, AccountID: pt.AccountID,
			MobileDeviceID: mobile.ID, DesktopDeviceID: desktop.ID,
			Status: authstore.PairingActive, CreatedAt: s.now(),
		}
		// Atomic count+insert: refuses to over-subscribe max_pairs even when two
		// completions for distinct tokens race on the same license (SG-16).
		if err := s.store.CreatePairingWithinCapacity(ctx, p, maxPairs); err != nil {
			if errors.Is(err, authstore.ErrCapacityExceeded) {
				writeErr(w, http.StatusConflict, "capacity_exceeded")
				return
			}
			writeErr(w, http.StatusInternalServerError, "store_error")
			return
		}
	}

	// Mint the per-pair credential the phone will authenticate with (security L2),
	// so the desktop's account secret no longer needs to ride the QR. Upsert by
	// pair_id, so a re-pair rotates the secret for the new mobile device in place
	// and the evicted device's credential stops working.
	credSecret := newPairCredential(pairID)
	if err := s.store.PutPairCredential(ctx, authstore.PairCredential{
		PairID: pairID, AccountID: pt.AccountID, LicenseID: lic.ID,
		MobileDeviceID: mobile.ID, SecretHash: hashSecret(credSecret), CreatedAt: s.now(),
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error")
		return
	}

	writeJSON(w, http.StatusOK, completePairingResp{
		PairID:           pairID,
		DesktopPublicKey: base64.StdEncoding.EncodeToString(desktop.PublicKey),
		MobileDeviceID:   mobile.ID,
		PairCredential:   credSecret,
	})
}

// --- POST /v1/pairing-tokens/poll : desktop learns pair_id + mobile key (Appendix C step 3) ---

type pollPairingReq struct {
	PairingToken string `json:"pairing_token"`
}
type pollPairingResp struct {
	Status          string `json:"status"` // pending | completed | expired
	PairID          string `json:"pair_id,omitempty"`
	MobilePublicKey string `json:"mobile_public_key,omitempty"` // base64
}

func (s *Service) handlePollPairingToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	accountID, err := s.authenticateAccount(ctx, r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req pollPairingReq
	if err := decodeJSON(r, &req); err != nil || req.PairingToken == "" {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	pt, err := s.store.GetPairingToken(ctx, hashSecret(req.PairingToken))
	if err != nil || pt.AccountID != accountID {
		writeErr(w, http.StatusNotFound, "pairing_token_not_found")
		return
	}
	switch {
	case !pt.ConsumedAt.IsZero():
		pairing, err := s.store.GetPairing(ctx, pt.ResultPairID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "store_error")
			return
		}
		mobile, err := s.store.GetDevice(ctx, pairing.MobileDeviceID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "store_error")
			return
		}
		writeJSON(w, http.StatusOK, pollPairingResp{
			Status: "completed", PairID: pt.ResultPairID,
			MobilePublicKey: base64.StdEncoding.EncodeToString(mobile.PublicKey),
		})
	case !s.now().Before(pt.ExpiresAt):
		writeJSON(w, http.StatusOK, pollPairingResp{Status: "expired"})
	default:
		writeJSON(w, http.StatusOK, pollPairingResp{Status: "pending"})
	}
}

// --- POST /v1/pairings/unpair : user-initiated unpairing (FR-2.5) ---

type unpairReq struct {
	PairID string `json:"pair_id"`
}

func (s *Service) handleUnpair(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	// Either side may unpair: the desktop with its account secret, the phone with
	// its per-pair credential (L2 — the phone no longer holds the account secret).
	accountID, cred, err := s.authenticateAccountOrPair(ctx, r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req unpairReq
	if err := decodeJSON(r, &req); err != nil || req.PairID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	// A pair credential may only unpair its own pairing.
	if cred != nil && cred.PairID != req.PairID {
		writeErr(w, http.StatusNotFound, "pairing_not_found")
		return
	}
	p, err := s.store.GetPairing(ctx, req.PairID)
	if err != nil || p.AccountID != accountID {
		writeErr(w, http.StatusNotFound, "pairing_not_found")
		return
	}
	if err := s.store.SetPairingStatus(ctx, p.PairID, authstore.PairingRevoked); err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error")
		return
	}
	// Revoke the per-pair credential so it cannot mint further tokens (L2, FR-2.5).
	if err := s.store.RevokePairCredential(ctx, p.PairID, s.now()); err != nil {
		s.log.Error("revoke pair credential failed",
			"pair_id", p.PairID, logging.FieldReason, err.Error())
	}
	// Free the slot and cut live sessions (FR-2.5).
	s.publishRevocation(ctx, backplane.RevocationEvent{PairID: p.PairID})
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// --- helpers ---

// capacityAvailable reports whether the license has a free pair slot
// (pairs in use < max_pairs, FR-2.2) and returns the license's max_pairs so the
// caller can pass it to the atomic CreatePairingWithinCapacity gate (SG-16).
func (s *Service) capacityAvailable(ctx context.Context, lic authstore.License) (ok bool, maxPairs int, err error) {
	sub, err := s.store.GetSubscription(ctx, lic.SubscriptionID)
	if err != nil {
		return false, 0, err
	}
	inUse, err := s.store.ActivePairCount(ctx, lic.ID)
	if err != nil {
		return false, 0, err
	}
	return inUse < sub.MaxPairs, sub.MaxPairs, nil
}

// activePairingForDesktop finds an active pairing for the license bound to the
// given desktop device, used to detect re-pairing (FR-2.4).
func (s *Service) activePairingForDesktop(ctx context.Context, licenseID, desktopDeviceID string) (authstore.Pairing, bool, error) {
	pairings, err := s.store.ListActivePairingsByLicense(ctx, licenseID)
	if err != nil {
		return authstore.Pairing{}, false, err
	}
	for _, p := range pairings {
		if p.DesktopDeviceID == desktopDeviceID {
			return p, true, nil
		}
	}
	return authstore.Pairing{}, false, nil
}

// publishRevocation announces a revocation if a backplane is configured. A
// failure is logged but does not fail the request: the pairing is already
// marked revoked in the durable store, so token issuance/refresh is refused
// regardless (PRD §6.5 #1), and the next reconcile/connect closes the session.
func (s *Service) publishRevocation(ctx context.Context, ev backplane.RevocationEvent) {
	if s.bp == nil {
		return
	}
	if err := s.bp.PublishRevocation(ctx, ev); err != nil {
		s.log.Error("publish revocation failed", "pair_id", ev.PairID, logging.FieldReason, err.Error())
	}
}
