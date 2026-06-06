package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/lley154/secure-gateway/internal/e2ee"
	"github.com/lley154/secure-gateway/internal/relay/protocol"
	"github.com/lley154/secure-gateway/internal/token"
	"github.com/lley154/secure-gateway/test/testclient"
)

// e2eeSessions builds the mobile and desktop sessions for one connection from a
// fresh X25519 exchange and a pair of handshake nonces (FR-5.2).
func e2eeSessions(t *testing.T) (mobile, desktop *e2ee.Session) {
	t.Helper()
	m, err := e2ee.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	d, err := e2ee.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	mn, _ := e2ee.NewHandshakeNonce()
	dn, _ := e2ee.NewHandshakeNonce()
	if mobile, err = e2ee.NewSession(m.Private, d.Public, token.RoleMobile, mn, dn); err != nil {
		t.Fatal(err)
	}
	if desktop, err = e2ee.NewSession(d.Private, m.Public, token.RoleDesktop, mn, dn); err != nil {
		t.Fatal(err)
	}
	return mobile, desktop
}

// TestE2EECiphertextThroughRelay encrypts with the reference E2EE package, sends
// the ciphertext through the (unmodified) relay, decrypts on the peer, and
// asserts the relay only ever handled opaque ciphertext (FR-4.2, FR-5.4).
func TestE2EECiphertextThroughRelay(t *testing.T) {
	h := newHarness(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const pair = "pair_e2e"
	desktop, err := h.dial(t, ctx, h.mint(t, pair, "dev_desktop", token.RoleDesktop))
	if err != nil {
		t.Fatalf("desktop dial: %v", err)
	}
	defer desktop.Close()
	mobile, err := h.dial(t, ctx, h.mint(t, pair, "dev_mobile", token.RoleMobile))
	if err != nil {
		t.Fatalf("mobile dial: %v", err)
	}
	defer mobile.Close()

	mSess, dSess := e2eeSessions(t)

	// Mobile -> desktop: seal, send ciphertext, receive, open.
	const id, ts = "0196a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b", int64(1765432100123)
	plaintext := []byte("transfer $100 to account 12345 — secret app message")
	ciphertext, err := mSess.Seal(id, ts, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, plaintext) {
		t.Fatal("plaintext leaked into ciphertext")
	}
	if err := mobile.SendMsg(ctx, id, ciphertext); err != nil {
		t.Fatalf("send: %v", err)
	}
	env, err := desktop.RecvType(ctx, protocol.TypeMsg)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}

	// The relay forwarded the ciphertext verbatim (no decryption, no mutation).
	forwarded, err := testclient.DecodePayload(env)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if !bytes.Equal(forwarded, ciphertext) {
		t.Fatal("relay did not forward the ciphertext byte-for-byte")
	}
	// The plaintext never appears in any byte the relay carried.
	if bytes.Contains(env.Payload, plaintext) {
		t.Fatal("plaintext present in the relayed envelope payload")
	}
	got, err := dSess.Open(id, ts, forwarded)
	if err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("desktop open: got %q err=%v", got, err)
	}

	// Desktop -> mobile uses the other directional key.
	const id2, ts2 = "0196a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c", int64(1765432100456)
	reply := []byte("ack: transfer queued")
	rct, err := dSess.Seal(id2, ts2, reply)
	if err != nil {
		t.Fatal(err)
	}
	if err := desktop.SendMsg(ctx, id2, rct); err != nil {
		t.Fatalf("send reply: %v", err)
	}
	renv, err := mobile.RecvType(ctx, protocol.TypeMsg)
	if err != nil {
		t.Fatalf("recv reply: %v", err)
	}
	rforwarded, _ := testclient.DecodePayload(renv)
	gotReply, err := mSess.Open(id2, ts2, rforwarded)
	if err != nil || !bytes.Equal(gotReply, reply) {
		t.Fatalf("mobile open reply: got %q err=%v", gotReply, err)
	}
}

// TestRelayPayloadStaysOpaque asserts at the protocol layer that the relay's
// envelope decoding never touches the payload: an encrypted payload survives a
// decode/encode round-trip byte-for-byte and is exposed only as raw bytes
// (FR-4.2). The relay code reads v/type/id and forwards the payload untouched.
func TestRelayPayloadStaysOpaque(t *testing.T) {
	mSess, _ := e2eeSessions(t)
	const id, ts = "msg-opaque-1", int64(42)
	ciphertext, err := mSess.Seal(id, ts, []byte("opaque to the relay"))
	if err != nil {
		t.Fatal(err)
	}

	// Build a wire frame the way testclient does (ciphertext base64 in payload).
	sent, err := mobileFrame(id, ts, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	// The relay decodes only the structural fields; the payload is opaque.
	env, err := protocol.Decode(sent, 256*1024)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Type != protocol.TypeMsg || env.ID != id {
		t.Fatalf("unexpected envelope %+v", env)
	}
	// Re-encoding yields an identical payload: nothing was inspected or rewritten.
	reencoded, err := env.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reencoded, sent) {
		t.Fatal("payload mutated across relay decode/encode")
	}
}

// mobileFrame encodes a msg envelope carrying ciphertext exactly as testclient
// puts it on the wire (the opaque bytes base64-encoded as a JSON string).
func mobileFrame(id string, ts int64, ciphertext []byte) ([]byte, error) {
	pl, err := json.Marshal(ciphertext)
	if err != nil {
		return nil, err
	}
	env := &protocol.Envelope{V: protocol.Version, Type: protocol.TypeMsg, ID: id, TS: ts, Payload: pl}
	return env.Encode()
}
