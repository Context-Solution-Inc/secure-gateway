package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	stripe "github.com/stripe/stripe-go/v82"

	"github.com/lley154/secure-gateway/internal/authmetrics"
	"github.com/lley154/secure-gateway/internal/authservice"
	"github.com/lley154/secure-gateway/internal/authstore/memory"
	"github.com/lley154/secure-gateway/internal/backplane"
	bpmem "github.com/lley154/secure-gateway/internal/backplane/memory"
	"github.com/lley154/secure-gateway/internal/billing"
	"github.com/lley154/secure-gateway/internal/billing/fake"
	"github.com/lley154/secure-gateway/internal/config"
	"github.com/lley154/secure-gateway/internal/e2ee"
	"github.com/lley154/secure-gateway/internal/logging"
	"github.com/lley154/secure-gateway/internal/metrics"
	"github.com/lley154/secure-gateway/internal/relay/hub"
	"github.com/lley154/secure-gateway/internal/relay/server"
	"github.com/lley154/secure-gateway/internal/signer"
	"github.com/lley154/secure-gateway/internal/token"
	"github.com/lley154/secure-gateway/test/testclient"
)

const (
	testWebhookSecret = "whsec_integration_secret"
	testAdminKey      = "admin_integration_key"
)

// authHarness runs the Auth & License Service and a relay in-process, sharing a
// backplane, with the relay verifying tokens via the auth service's JWKS
// endpoint — the full M2 token + revocation path.
type authHarness struct {
	store   *memory.Store
	bp      backplane.Backplane
	api     *fake.API
	wh      *fake.Webhook
	proc    *billing.Processor
	authSrv *httptest.Server

	hub      *hub.Hub
	relaySrv *httptest.Server
	wsURL    string
}

func newAuthHarness(t *testing.T, serverOpts ...func(*authservice.ServerConfig)) *authHarness {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	log := logging.New(io.Discard, "error", "json")

	sgn, err := signer.NewSigner("ES256", "auth-test-kid")
	if err != nil {
		t.Fatal(err)
	}
	store := memory.New()
	bp := bpmem.New(60*time.Second, 64)
	api := fake.NewAPI()
	proc := billing.NewProcessor(billing.Config{
		Store: store, Backplane: bp, API: api, Logger: log,
		Grace: 168 * time.Hour, WebhookSecret: testWebhookSecret,
	})

	svc := authservice.NewService(authservice.Deps{
		Store: store, Signer: sgn, Processor: proc, Backplane: bp, Metrics: authmetrics.New(), Logger: log,
		Issuer: testIssuer, Audience: testAud, TokenTTL: 10 * time.Minute, RefreshTTL: 720 * time.Hour,
		Grace: 168 * time.Hour, AdminKey: testAdminKey,
		RelayURL: "wss://relay.test/v1/connect", AuthURL: "https://auth.test",
	})
	srvCfg := authservice.ServerConfig{ListenAddr: "127.0.0.1:0", TLSMinVersion: "1.2", ShutdownDrain: time.Second}
	for _, opt := range serverOpts {
		opt(&srvCfg)
	}
	authSrv, err := authservice.NewServer(svc, srvCfg)
	if err != nil {
		t.Fatal(err)
	}
	authHTTP := httptest.NewServer(authSrv.Handler())
	t.Cleanup(authHTTP.Close)

	// Relay verifies tokens via the auth service's JWKS endpoint.
	ks := token.NewJWKSSource(authHTTP.URL + "/.well-known/jwks.json")
	verifier, err := token.NewVerifier(token.Config{
		Issuer: testIssuer, Audience: testAud, AllowedAlgs: []string{"ES256"},
		Leeway: 30 * time.Second, KeySource: ks,
	})
	if err != nil {
		t.Fatal(err)
	}
	m := metrics.New()
	h := hub.New("auth-test-relay", bp, m, log)
	go func() { _ = h.Run(ctx) }()

	cfg := &config.Config{ListenAddr: "127.0.0.1:0", TLSMinVersion: "1.2", Backplane: config.BackplaneMemory, ShutdownDrain: 5 * time.Second}
	relaySrv, err := server.New(cfg, log, m, server.Deps{Verifier: verifier, Hub: h, SessionOptions: defaultSessionOptions()})
	if err != nil {
		t.Fatal(err)
	}
	relayHTTP := httptest.NewServer(relaySrv.Handler())
	t.Cleanup(relayHTTP.Close)

	return &authHarness{
		store: store, bp: bp, api: api, wh: fake.NewWebhook(testWebhookSecret), proc: proc, authSrv: authHTTP,
		hub: h, relaySrv: relayHTTP, wsURL: "ws" + strings.TrimPrefix(relayHTTP.URL, "http") + "/v1/connect",
	}
}

// --- HTTP helpers against the auth service ---

func (a *authHarness) do(t *testing.T, method, path, bearer string, body any) (int, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, a.authSrv.URL+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func (a *authHarness) createAccount(t *testing.T, accountID string) string {
	t.Helper()
	status, body := a.do(t, http.MethodPost, "/v1/accounts", testAdminKey, map[string]string{"account_id": accountID})
	if status != http.StatusOK {
		t.Fatalf("createAccount: status %d body %s", status, body)
	}
	var r struct {
		Secret string `json:"secret"`
	}
	mustUnmarshal(t, body, &r)
	return r.Secret
}

func (a *authHarness) registerDevice(t *testing.T, secret, role string) string {
	t.Helper()
	status, body := a.do(t, http.MethodPost, "/v1/devices", secret, map[string]string{"role": role})
	if status != http.StatusOK {
		t.Fatalf("registerDevice(%s): status %d body %s", role, status, body)
	}
	var r struct {
		DeviceID string `json:"device_id"`
	}
	mustUnmarshal(t, body, &r)
	return r.DeviceID
}

// qrPair runs the full M3 QR pairing flow: the desktop issues a one-time pairing
// token (account-authed), then the mobile redeems it (token-authed) presenting
// its X25519 public key. It returns the pair_id plus both keypairs so callers can
// build E2EE sessions over the resulting pair.
func (a *authHarness) qrPair(t *testing.T, secret, licenseID, mobileID, desktopID string) (string, e2ee.KeyPair, e2ee.KeyPair) {
	t.Helper()
	mobileKP, err := e2ee.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	desktopKP, err := e2ee.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// 1. Desktop issues a pairing token, supplying its public key for the QR.
	status, body := a.do(t, http.MethodPost, "/v1/pairing-tokens", secret, map[string]string{
		"license_id": licenseID, "desktop_device_id": desktopID,
		"desktop_public_key": base64.StdEncoding.EncodeToString(desktopKP.Public[:]),
	})
	if status != http.StatusOK {
		t.Fatalf("pairing-tokens: status %d body %s", status, body)
	}
	var issued struct {
		PairingToken string `json:"pairing_token"`
	}
	mustUnmarshal(t, body, &issued)

	// 2. Mobile completes pairing with the token + its public key (no bearer).
	status, body = a.do(t, http.MethodPost, "/v1/pairings", "", map[string]string{
		"pairing_token": issued.PairingToken, "mobile_device_id": mobileID,
		"mobile_public_key": base64.StdEncoding.EncodeToString(mobileKP.Public[:]),
	})
	if status != http.StatusOK {
		t.Fatalf("complete pairing: status %d body %s", status, body)
	}
	var done struct {
		PairID string `json:"pair_id"`
	}
	mustUnmarshal(t, body, &done)
	return done.PairID, mobileKP, desktopKP
}

type tokenResult struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

func (a *authHarness) issueToken(t *testing.T, secret, deviceID, pairID string) (int, tokenResult) {
	t.Helper()
	status, body := a.do(t, http.MethodPost, "/v1/token", secret, map[string]string{"device_id": deviceID, "pair_id": pairID})
	var r tokenResult
	if status == http.StatusOK {
		mustUnmarshal(t, body, &r)
	}
	return status, r
}

func (a *authHarness) refreshToken(t *testing.T, refresh string) (int, tokenResult) {
	t.Helper()
	status, body := a.do(t, http.MethodPost, "/v1/token/refresh", "", map[string]string{"refresh_token": refresh})
	var r tokenResult
	if status == http.StatusOK {
		mustUnmarshal(t, body, &r)
	}
	return status, r
}

// sendWebhook delivers a signed webhook to the auth service.
func (a *authHarness) sendWebhook(t *testing.T, eventType stripe.EventType, object json.RawMessage) int {
	t.Helper()
	body, sig := a.wh.Event(eventType, object)
	req, err := http.NewRequest(http.MethodPost, a.authSrv.URL+"/v1/webhooks/stripe", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Stripe-Signature", sig)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func (a *authHarness) dialRelay(t *testing.T, ctx context.Context, bearer string) (*testclient.Client, error) {
	t.Helper()
	return testclient.Dial(ctx, a.wsURL, bearer, http.DefaultClient)
}

func mustUnmarshal(t *testing.T, data []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("unmarshal %s: %v", data, err)
	}
}
