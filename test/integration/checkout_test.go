package integration

import (
	"io"
	"net/http"
	"net/url"
	"testing"

	stripe "github.com/stripe/stripe-go/v82"

	"github.com/lley154/secure-gateway/internal/billing/fake"
)

// TestDesktopCheckoutClaimFlow exercises the full desktop subscription
// onboarding (claim-token) flow end to end against the hermetic auth service:
// start -> (pending claim) -> webhook ready -> return 302 with claim_code ->
// claim once -> authenticate with the minted secret -> double-claim rejected.
func TestDesktopCheckoutClaimFlow(t *testing.T) {
	a := newAuthHarness(t)

	const (
		nonce    = "nonce_abcdefghijklmnopqrstuv" // ≥ minNonceLen
		redirect = "http://127.0.0.1:53999/subscribe/callback"
		customer = "cus_checkout"
		subID    = "sub_checkout"
	)

	// 1. Start checkout. The session must record metadata.nonce and a loopback
	//    cancel URL; the success URL points back at the auth service.
	status, body := a.do(t, http.MethodPost, "/v1/checkout/start", "", map[string]string{
		"nonce": nonce, "redirect_uri": redirect,
	})
	if status != http.StatusOK {
		t.Fatalf("checkout/start: status %d body %s", status, body)
	}
	var started struct {
		CheckoutURL string `json:"checkout_url"`
		ExpiresIn   int    `json:"expires_in"`
	}
	mustUnmarshal(t, body, &started)
	if started.CheckoutURL == "" || started.ExpiresIn <= 0 {
		t.Fatalf("checkout/start response: %+v", started)
	}
	sessions := a.api.Sessions()
	if len(sessions) != 1 || sessions[0].Metadata["nonce"] != nonce || sessions[0].PriceID != testPriceID {
		t.Fatalf("recorded session mismatch: %+v", sessions)
	}
	sessionID := sessions[0].ID

	// 2. Before the webhook lands, claiming reports pending (202).
	if status, _ := a.do(t, http.MethodPost, "/v1/accounts/claim", "", map[string]string{"nonce": nonce}); status != http.StatusAccepted {
		t.Fatalf("claim while pending: want 202, got %d", status)
	}

	// 3. The webhook provisions the account/license/subscription and marks the
	//    claim ready. The session id in the event must match the recorded one.
	a.api.Set(fake.Subscription(subID, customer, stripe.SubscriptionStatusActive, 1))
	if code := a.sendWebhook(t, stripe.EventTypeCheckoutSessionCompleted,
		fake.CheckoutCompletedWithNonce(sessionID, customer, subID, nonce)); code != http.StatusOK {
		t.Fatalf("checkout.session.completed webhook: status %d", code)
	}

	// 4. The browser hits the success URL; expect a 302 to the loopback callback
	//    carrying a one-time claim_code. Do not follow the redirect.
	loc := a.getNoRedirect(t, "/v1/checkout/return?nonce="+url.QueryEscape(nonce)+"&session_id="+sessionID)
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse redirect %q: %v", loc, err)
	}
	claimCode := u.Query().Get("claim_code")
	if claimCode == "" || u.Host != "127.0.0.1:53999" {
		t.Fatalf("redirect missing claim_code or wrong host: %s", loc)
	}

	// 5. Claim the credential exactly once.
	status, body = a.do(t, http.MethodPost, "/v1/accounts/claim", "", map[string]string{"claim_code": claimCode})
	if status != http.StatusOK {
		t.Fatalf("claim: status %d body %s", status, body)
	}
	var claimed struct {
		AccountID      string `json:"account_id"`
		AccountSecret  string `json:"account_secret"`
		LicenseID      string `json:"license_id"`
		SubscriptionID string `json:"subscription_id"`
	}
	mustUnmarshal(t, body, &claimed)
	if claimed.AccountSecret == "" || claimed.LicenseID == "" || claimed.SubscriptionID != subID {
		t.Fatalf("claim response: %+v", claimed)
	}

	// 6. The minted secret authenticates the launch-time status check.
	status, body = a.do(t, http.MethodGet, "/v1/subscription", claimed.AccountSecret, nil)
	if status != http.StatusOK {
		t.Fatalf("subscription: status %d body %s", status, body)
	}
	var sub struct {
		Status         string `json:"status"`
		SubscriptionID string `json:"subscription_id"`
		MaxPairs       int    `json:"max_pairs"`
	}
	mustUnmarshal(t, body, &sub)
	if sub.Status != "valid" || sub.SubscriptionID != subID || sub.MaxPairs != 1 {
		t.Fatalf("subscription status: %+v", sub)
	}

	// 7. A second claim is rejected (single-use).
	if status, _ := a.do(t, http.MethodPost, "/v1/accounts/claim", "", map[string]string{"claim_code": claimCode}); status != http.StatusConflict {
		t.Fatalf("double claim: want 409, got %d", status)
	}
}

// TestCheckoutStartRejectsNonLoopbackRedirect guards the open-redirect defense.
func TestCheckoutStartRejectsNonLoopbackRedirect(t *testing.T) {
	a := newAuthHarness(t)
	cases := []string{
		"https://evil.example.com/callback", // remote host
		"http://192.168.1.5/callback",       // private but not loopback
		"ftp://127.0.0.1/callback",          // wrong scheme
	}
	for _, redirect := range cases {
		status, _ := a.do(t, http.MethodPost, "/v1/checkout/start", "", map[string]string{
			"nonce": "nonce_abcdefghijklmnopqrstuv", "redirect_uri": redirect,
		})
		if status != http.StatusBadRequest {
			t.Fatalf("redirect %q: want 400, got %d", redirect, status)
		}
	}
}

// getNoRedirect issues a GET that does not follow redirects and returns the
// Location header (fails the test if the status is not 302).
func (a *authHarness) getNoRedirect(t *testing.T, path string) string {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequest(http.MethodGet, a.authSrv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("%s: want 302, got %d", path, resp.StatusCode)
	}
	return resp.Header.Get("Location")
}
