package e2ee

import (
	"bytes"
	"errors"
	"testing"

	"github.com/context-solutions-inc/secure-gateway/internal/token"
)

// sessionPair builds the mobile and desktop sessions for one connection from a
// fresh identity key exchange plus per-session ephemeral keys.
func sessionPair(t *testing.T) (mobile, desktop *Session) {
	t.Helper()
	m, err := GenerateKeyPair() // mobile identity
	if err != nil {
		t.Fatal(err)
	}
	d, err := GenerateKeyPair() // desktop identity
	if err != nil {
		t.Fatal(err)
	}
	me, err := GenerateKeyPair() // mobile ephemeral
	if err != nil {
		t.Fatal(err)
	}
	de, err := GenerateKeyPair() // desktop ephemeral
	if err != nil {
		t.Fatal(err)
	}
	mobile, err = NewSession(m.Private, d.Public, me.Private, de.Public, token.RoleMobile)
	if err != nil {
		t.Fatal(err)
	}
	desktop, err = NewSession(d.Private, m.Public, de.Private, me.Public, token.RoleDesktop)
	if err != nil {
		t.Fatal(err)
	}
	return mobile, desktop
}

func TestRoundTripBothDirections(t *testing.T) {
	mobile, desktop := sessionPair(t)

	const (
		id = "0196a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"
		ts = int64(1765432100123)
	)
	msg := []byte("hello desktop, this is the mobile")

	ct, err := mobile.Seal(id, ts, msg)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, msg) {
		t.Fatal("plaintext appears in ciphertext")
	}
	got, err := desktop.Open(id, ts, ct)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("desktop open: got %q err=%v", got, err)
	}

	// Reverse direction uses the other directional key.
	reply := []byte("ack from desktop")
	ct2, err := desktop.Seal(id, ts, reply)
	if err != nil {
		t.Fatal(err)
	}
	got2, err := mobile.Open(id, ts, ct2)
	if err != nil || !bytes.Equal(got2, reply) {
		t.Fatalf("mobile open: got %q err=%v", got2, err)
	}
}

func TestEmptyPlaintextRoundTrip(t *testing.T) {
	mobile, desktop := sessionPair(t)
	ct, err := mobile.Seal("id-empty", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := desktop.Open("id-empty", 1, ct)
	if err != nil || len(got) != 0 {
		t.Fatalf("open empty: got %q err=%v", got, err)
	}
}

func TestTamperDetection(t *testing.T) {
	mobile, desktop := sessionPair(t)
	const id, ts = "msg-1", int64(42)
	ct, err := mobile.Seal(id, ts, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	// Tampered ciphertext byte.
	bad := bytes.Clone(ct)
	bad[len(bad)-1] ^= 0x01
	if _, err := desktop.Open(id, ts, bad); err == nil {
		t.Fatal("expected open to fail on tampered ciphertext")
	}
	// Wrong id (AAD mismatch).
	if _, err := desktop.Open("msg-2", ts, ct); err == nil {
		t.Fatal("expected open to fail on mismatched id")
	}
	// Wrong ts (AAD mismatch) — guards against replay/splicing (FR-5.1).
	if _, err := desktop.Open(id, ts+1, ct); err == nil {
		t.Fatal("expected open to fail on mismatched ts")
	}
}

func TestReplayRejected(t *testing.T) {
	mobile, desktop := sessionPair(t)
	const (
		id = "0196a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"
		ts = int64(1765432100123)
	)
	ct, err := mobile.Seal(id, ts, []byte("deliver once"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := desktop.Open(id, ts, ct); err != nil {
		t.Fatalf("first open: %v", err)
	}
	// Re-injecting the exact same authenticated envelope must be rejected (SG-02).
	if _, err := desktop.Open(id, ts, ct); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay: want ErrReplay, got %v", err)
	}
}

func TestStaleTimestampRejected(t *testing.T) {
	mobile, desktop := sessionPair(t)
	// Advance the receive high-water mark with a recent message.
	ctNew, err := mobile.Seal("id-new", 10_000_000, []byte("recent"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := desktop.Open("id-new", 10_000_000, ctNew); err != nil {
		t.Fatalf("open recent: %v", err)
	}
	// A far-older authenticated message (outside the window) is refused even though
	// its AEAD tag is valid, blocking long-delayed replays.
	ctOld, err := mobile.Seal("id-old", 1, []byte("ancient"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := desktop.Open("id-old", 1, ctOld); !errors.Is(err, ErrStale) {
		t.Fatalf("stale: want ErrStale, got %v", err)
	}
}

func TestWrongDirectionKeyFails(t *testing.T) {
	mobile, desktop := sessionPair(t)
	// A frame the mobile sealed must not open with the mobile's own recv key.
	ct, err := mobile.Seal("id", 1, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mobile.Open("id", 1, ct); err == nil {
		t.Fatal("sender must not be able to open its own m2d frame with the d2m key")
	}
	_ = desktop
}

func TestDistinctSessionsDistinctKeys(t *testing.T) {
	// Same identity keypairs, different ephemeral keys => different session keys.
	// This is the basis of forward secrecy (FR-5.2): the ephemeral DH is mixed
	// into the keying material, so a session's keys can't be recomputed from the
	// long-term identity keys alone.
	m, _ := GenerateKeyPair()
	d, _ := GenerateKeyPair()
	me1, _ := GenerateKeyPair()
	de1, _ := GenerateKeyPair()
	me2, _ := GenerateKeyPair()
	de2, _ := GenerateKeyPair()

	s1, err := NewSession(m.Private, d.Public, me1.Private, de1.Public, token.RoleMobile)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := NewSession(m.Private, d.Public, me2.Private, de2.Public, token.RoleMobile)
	if err != nil {
		t.Fatal(err)
	}
	if s1.sendKey == s2.sendKey {
		t.Fatal("different ephemeral keys must yield different session keys")
	}
}

func TestNewSessionValidation(t *testing.T) {
	m, _ := GenerateKeyPair()
	d, _ := GenerateKeyPair()
	me, _ := GenerateKeyPair()
	de, _ := GenerateKeyPair()
	if _, err := NewSession(m.Private, d.Public, me.Private, de.Public, "bogus"); err == nil {
		t.Fatal("expected invalid-role error")
	}
}
