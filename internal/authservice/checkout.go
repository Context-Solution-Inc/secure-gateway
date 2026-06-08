package authservice

import (
	"errors"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/lley154/secure-gateway/internal/authstore"
	"github.com/lley154/secure-gateway/internal/billing"
	"github.com/lley154/secure-gateway/internal/license"
)

// Desktop subscription onboarding (claim-token flow). The desktop has no account
// yet, so /checkout/start and /accounts/claim are unauthenticated (rate limited
// per-IP). A desktop-generated nonce binds the four steps together:
//
//	start  -> create Stripe Checkout Session with metadata.nonce, record a
//	          pending claim bound to the desktop's loopback redirect_uri.
//	webhook -> handleCheckoutCompleted marks the claim ready (account/license/sub).
//	return -> Stripe success_url; mint a one-time claim_code, 302 to the desktop's
//	          loopback callback carrying the code.
//	claim  -> desktop exchanges code (or nonce) for {account_id, account_secret,
//	          license_id, subscription_id} exactly once; the secret is minted here
//	          and only its hash is stored.

const minNonceLen = 22 // ~128 bits as lowercase base32

var errBadRedirect = errors.New("redirect_uri must be an http loopback URL")

// validateLoopbackRedirect ensures the desktop callback can only ever be a
// loopback address, so a minted claim_code can never be delivered to a remote
// host (open-redirect / code-exfiltration defense).
func validateLoopbackRedirect(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Host == "" {
		return errBadRedirect
	}
	host := u.Hostname()
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errBadRedirect
	}
	return nil
}

// --- POST /v1/checkout/start ---

type startCheckoutReq struct {
	Nonce       string `json:"nonce"`
	RedirectURI string `json:"redirect_uri"`
	Label       string `json:"desktop_label,omitempty"`
}
type startCheckoutResp struct {
	CheckoutURL string `json:"checkout_url"`
	ExpiresIn   int    `json:"expires_in"`
}

func (s *Service) handleStartCheckout(w http.ResponseWriter, r *http.Request) {
	if s.checkoutPriceID == "" {
		writeErr(w, http.StatusServiceUnavailable, "checkout_unavailable")
		return
	}
	var req startCheckoutReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	if len(req.Nonce) < minNonceLen || strings.ContainsAny(req.Nonce, " \t\r\n/?#") {
		writeErr(w, http.StatusBadRequest, "bad_nonce")
		return
	}
	if err := validateLoopbackRedirect(req.RedirectURI); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_redirect")
		return
	}
	// Stripe substitutes {CHECKOUT_SESSION_ID} into the success URL; keep it
	// literal (do not url-encode the braces).
	successURL := strings.TrimRight(s.authURL, "/") +
		"/v1/checkout/return?nonce=" + url.QueryEscape(req.Nonce) + "&session_id={CHECKOUT_SESSION_ID}"
	cancelURL := appendQuery(req.RedirectURI, "status", "canceled")

	checkoutURL, sessionID, err := s.proc.CreateCheckoutSession(r.Context(), billing.CheckoutSessionParams{
		PriceID:    s.checkoutPriceID,
		SuccessURL: successURL,
		CancelURL:  cancelURL,
		Metadata:   map[string]string{"nonce": req.Nonce},
	})
	if err != nil {
		if errors.Is(err, billing.ErrStripeNotConfigured) {
			writeErr(w, http.StatusServiceUnavailable, "checkout_unavailable")
			return
		}
		s.log.Error("create checkout session", "err", err.Error())
		writeErr(w, http.StatusBadGateway, "stripe_error")
		return
	}
	now := s.now()
	claim := authstore.CheckoutClaim{
		Nonce:           req.Nonce,
		StripeSessionID: sessionID,
		RedirectURI:     req.RedirectURI,
		Status:          authstore.ClaimPending,
		CreatedAt:       now,
		ExpiresAt:       now.Add(s.claimTTL),
	}
	if err := s.store.CreateCheckoutClaim(r.Context(), claim); err != nil {
		if errors.Is(err, authstore.ErrConflict) {
			writeErr(w, http.StatusConflict, "nonce_in_use")
			return
		}
		writeErr(w, http.StatusInternalServerError, "store_error")
		return
	}
	writeJSON(w, http.StatusOK, startCheckoutResp{CheckoutURL: checkoutURL, ExpiresIn: int(s.claimTTL.Seconds())})
}

// --- GET /v1/checkout/return (Stripe success_url; browser) ---

var pendingPage = template.Must(template.New("pending").Parse(`<!doctype html>
<meta http-equiv="refresh" content="2">
<title>Finishing your subscription…</title>
<body style="font-family:sans-serif;text-align:center;margin-top:4em">
<h2>Activating your subscription…</h2>
<p>This page will refresh automatically. You can return to the app shortly.</p>
</body>`))

func (s *Service) handleCheckoutReturn(w http.ResponseWriter, r *http.Request) {
	nonce := r.URL.Query().Get("nonce")
	sessionID := r.URL.Query().Get("session_id")
	claim, err := s.store.GetCheckoutClaim(r.Context(), nonce)
	if err != nil {
		http.Error(w, "unknown or expired checkout", http.StatusNotFound)
		return
	}
	if !claim.Active(s.now()) {
		http.Error(w, "checkout expired", http.StatusGone)
		return
	}
	// Bind the session id Stripe redirected with to the one we recorded at start
	// (CSRF / cross-session defense).
	if sessionID != "" && claim.StripeSessionID != "" && sessionID != claim.StripeSessionID {
		http.Error(w, "session mismatch", http.StatusBadRequest)
		return
	}
	if claim.Status == authstore.ClaimPending {
		// Webhook hasn't landed yet; show a self-refreshing interstitial.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = pendingPage.Execute(w, nil)
		return
	}
	// Ready: mint a one-time claim code, store its hash, redirect to the desktop.
	claimCode := authstore.NewID("clm")
	if err := s.store.SetCheckoutClaimCode(r.Context(), nonce, hashSecret(claimCode)); err != nil {
		http.Error(w, "could not finalize checkout", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, appendQuery(claim.RedirectURI, "claim_code", claimCode), http.StatusFound)
}

// --- POST /v1/accounts/claim ---

type claimReq struct {
	ClaimCode string `json:"claim_code,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
}
type claimResp struct {
	AccountID      string `json:"account_id"`
	AccountSecret  string `json:"account_secret"`
	LicenseID      string `json:"license_id"`
	SubscriptionID string `json:"subscription_id"`
}

func (s *Service) handleClaimAccount(w http.ResponseWriter, r *http.Request) {
	var req claimReq
	if err := decodeJSON(r, &req); err != nil || (req.ClaimCode == "" && req.Nonce == "") {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	var claim authstore.CheckoutClaim
	var err error
	if req.ClaimCode != "" {
		claim, err = s.store.GetCheckoutClaimByCode(r.Context(), hashSecret(req.ClaimCode))
	} else {
		claim, err = s.store.GetCheckoutClaim(r.Context(), req.Nonce)
	}
	if err != nil {
		writeErr(w, http.StatusNotFound, "claim_not_found")
		return
	}
	if claim.Status == authstore.ClaimConsumed {
		writeErr(w, http.StatusConflict, "claim_consumed")
		return
	}
	if s.now().After(claim.ExpiresAt) {
		writeErr(w, http.StatusGone, "claim_expired")
		return
	}
	if claim.Status == authstore.ClaimPending {
		// Webhook race: desktop polls until ready.
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "pending"})
		return
	}
	consumed, err := s.store.ConsumeCheckoutClaim(r.Context(), claim.Nonce, s.now())
	if err != nil {
		if errors.Is(err, authstore.ErrConflict) {
			writeErr(w, http.StatusConflict, "claim_consumed")
			return
		}
		writeErr(w, http.StatusInternalServerError, "store_error")
		return
	}
	// Mint the account secret now and persist only its hash, preserving the
	// webhook's customer link (UpsertAccount merges empty fields).
	secret := newAccountSecret(consumed.AccountID)
	if err := s.store.UpsertAccount(r.Context(), authstore.Account{ID: consumed.AccountID, SecretHash: hashSecret(secret)}); err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error")
		return
	}
	writeJSON(w, http.StatusOK, claimResp{
		AccountID:      consumed.AccountID,
		AccountSecret:  secret,
		LicenseID:      consumed.LicenseID,
		SubscriptionID: consumed.SubscriptionID,
	})
}

// --- GET /v1/subscription (account-secret auth; launch-time validation) ---

type subscriptionResp struct {
	Status           string `json:"status"` // license behavior: valid|grace|revoked|suspended
	SubscriptionID   string `json:"subscription_id"`
	CurrentPeriodEnd int64  `json:"current_period_end"`
	MaxPairs         int    `json:"max_pairs"`
	LicenseID        string `json:"license_id"`
}

func (s *Service) handleGetSubscription(w http.ResponseWriter, r *http.Request) {
	accountID, err := s.authenticateAccount(r.Context(), r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	lics, err := s.store.ListLicensesByAccount(r.Context(), accountID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error")
		return
	}
	for _, lic := range lics {
		sub, err := s.store.GetSubscription(r.Context(), lic.SubscriptionID)
		if err != nil {
			continue
		}
		behavior := license.Evaluate(sub, s.now())
		writeJSON(w, http.StatusOK, subscriptionResp{
			Status:           behavior.String(),
			SubscriptionID:   sub.ID,
			CurrentPeriodEnd: sub.CurrentPeriodEnd.Unix(),
			MaxPairs:         sub.MaxPairs,
			LicenseID:        lic.ID,
		})
		return
	}
	writeErr(w, http.StatusNotFound, "no_subscription")
}

// appendQuery adds a single query parameter to a URL, preserving any existing
// ones. On parse failure it returns the input unchanged.
func appendQuery(raw, key, value string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String()
}
