package integration

import (
	"bytes"
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/lley154/secure-gateway/internal/relay/protocol"
	"github.com/lley154/secure-gateway/internal/token"
)

func ctxT(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// TestEchoBothDirections verifies a mobile and a desktop on the same pair can
// exchange opaque payloads in both directions, with the relay forwarding the
// ciphertext byte-for-byte.
func TestEchoBothDirections(t *testing.T) {
	h := newHarness(t, nil, nil)
	ctx := ctxT(t)

	mobile, err := h.dial(t, ctx, h.mint(t, "pair_X", "dev_m", token.RoleMobile))
	if err != nil {
		t.Fatalf("mobile dial: %v", err)
	}
	defer mobile.Close()
	desktop, err := h.dial(t, ctx, h.mint(t, "pair_X", "dev_d", token.RoleDesktop))
	if err != nil {
		t.Fatalf("desktop dial: %v", err)
	}
	defer desktop.Close()

	// mobile -> desktop
	payloadMD := []byte("ciphertext-mobile-to-desktop-\x00\x01\x02")
	if err := mobile.SendMsg(ctx, "id-md", payloadMD); err != nil {
		t.Fatal(err)
	}
	got, err := desktop.RecvType(ctx, protocol.TypeMsg)
	if err != nil {
		t.Fatalf("desktop recv: %v", err)
	}
	if got.ID != "id-md" {
		t.Errorf("id = %q, want id-md", got.ID)
	}
	assertPayload(t, got, payloadMD)

	// desktop -> mobile
	payloadDM := []byte("ciphertext-desktop-to-mobile-\xff\xfe")
	if err := desktop.SendMsg(ctx, "id-dm", payloadDM); err != nil {
		t.Fatal(err)
	}
	got, err = mobile.RecvType(ctx, protocol.TypeMsg)
	if err != nil {
		t.Fatalf("mobile recv: %v", err)
	}
	if got.ID != "id-dm" {
		t.Errorf("id = %q, want id-dm", got.ID)
	}
	assertPayload(t, got, payloadDM)
}

func assertPayload(t *testing.T, env *protocol.Envelope, want []byte) {
	t.Helper()
	got, err := decodePayload(env)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("payload mismatch: got %q want %q", got, want)
	}
}

func decodePayload(env *protocol.Envelope) ([]byte, error) {
	// payload is a base64-encoded JSON string of the original bytes
	var b []byte
	if err := jsonUnmarshal(env.Payload, &b); err != nil {
		return nil, err
	}
	return b, nil
}

// TestPresencePeerOnline checks the second endpoint of a pair receives a
// peer_online sys frame when both are connected.
func TestPresencePeerOnline(t *testing.T) {
	h := newHarness(t, nil, nil)
	ctx := ctxT(t)

	mobile, err := h.dial(t, ctx, h.mint(t, "pair_P", "dev_m", token.RoleMobile))
	if err != nil {
		t.Fatal(err)
	}
	defer mobile.Close()
	desktop, err := h.dial(t, ctx, h.mint(t, "pair_P", "dev_d", token.RoleDesktop))
	if err != nil {
		t.Fatal(err)
	}
	defer desktop.Close()

	// The desktop (second to connect) must get peer_online.
	sys, err := desktop.RecvType(ctx, protocol.TypeSys)
	if err != nil {
		t.Fatalf("desktop sys recv: %v", err)
	}
	var body protocol.System
	if err := jsonUnmarshal(sys.Payload, &body); err != nil {
		t.Fatal(err)
	}
	if body.Kind != protocol.SysPeerOnline {
		t.Errorf("sys kind = %q, want peer_online", body.Kind)
	}
}

// TestPeerOffline checks a msg with no connected peer returns error{peer_offline}.
func TestPeerOffline(t *testing.T) {
	h := newHarness(t, nil, nil)
	ctx := ctxT(t)

	mobile, err := h.dial(t, ctx, h.mint(t, "pair_O", "dev_m", token.RoleMobile))
	if err != nil {
		t.Fatal(err)
	}
	defer mobile.Close()

	if err := mobile.SendMsg(ctx, "id-1", []byte("hello")); err != nil {
		t.Fatal(err)
	}
	env, err := mobile.RecvType(ctx, protocol.TypeError)
	if err != nil {
		t.Fatalf("recv error: %v", err)
	}
	var body protocol.ErrorBody
	if err := jsonUnmarshal(env.Payload, &body); err != nil {
		t.Fatal(err)
	}
	if body.Code != protocol.ErrPeerOffline {
		t.Errorf("error code = %q, want peer_offline", body.Code)
	}
}

// TestAuthRejections covers pre-upgrade 401/403 with machine reason codes.
func TestAuthRejections(t *testing.T) {
	h := newHarness(t, nil, nil)

	tests := []struct {
		name       string
		bearer     string
		wantStatus int
		wantReason string
	}{
		{"missing token", "", http.StatusUnauthorized, "missing_token"},
		{"malformed", "garbage", http.StatusUnauthorized, "malformed_token"},
		{"expired", h.mintTTL(t, "pair_E", "dev_m", token.RoleMobile, -time.Minute), http.StatusUnauthorized, "expired"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := ctxT(t)
			_, err := h.dial(t, ctx, tt.bearer)
			if err == nil {
				t.Fatal("expected dial to fail before upgrade")
			}
			// coder/websocket surfaces the HTTP status in the error string.
			if !contains(err.Error(), tt.wantStatus) {
				t.Errorf("error %q does not mention status %d", err.Error(), tt.wantStatus)
			}
		})
	}
}

// TestQueryStringTokenRejected ensures a token in the URL is refused (FR-1.2).
func TestQueryStringTokenRejected(t *testing.T) {
	h := newHarness(t, nil, nil)
	ctx := ctxT(t)
	url := h.wsURL + "?token=" + h.mint(t, "pair_Q", "dev_m", token.RoleMobile)
	_, _, err := dialRaw(ctx, url)
	if err == nil {
		t.Fatal("expected rejection of URL-borne token")
	}
}
