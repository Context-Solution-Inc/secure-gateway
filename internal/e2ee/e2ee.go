// Package e2ee is the Go reference implementation of the relay's end-to-end
// encryption (PRD FR-5). It is the authoritative behavior the M4 platform SDKs
// (Tink / CryptoKit / lazysodium) must match; the committed interop vectors in
// testdata/vectors.json are the cross-platform contract.
//
// The relay never links this package: payloads are opaque ciphertext to it
// (FR-4.2, FR-5.4). Only the mobile and desktop clients encrypt and decrypt.
//
// # Scheme (the contract)
//
//   - Keys: X25519 (Curve25519). A private key is 32 random bytes; the public
//     key is X25519(priv, basepoint).
//   - Shared secret: ss = X25519(myPriv, peerPub) (32 bytes).
//   - Session keys (directional, per session): each side contributes a fresh
//     32-byte handshake nonce, exchanged in the first message of the session. Two
//     directional keys are derived with HKDF-SHA256:
//     salt = mobileHandshakeNonce || desktopHandshakeNonce (mobile first, fixed
//     by role — not by who initiated); info = "secure-gateway/e2ee/v1|" + dir
//     where dir is "m2d" (mobile→desktop) or "d2m" (desktop→mobile); output is
//     32 bytes. K_m2d is used by the mobile to seal and the desktop to open;
//     K_d2m is the reverse.
//   - AEAD: XChaCha20-Poly1305 with a random 24-byte nonce per message, the
//     nonce prepended to the ciphertext (wire = nonce(24) || aead_ciphertext).
//   - The envelope id and ts are bound as AEAD associated data, so the relay
//     cannot tamper with or splice them onto a different ciphertext (FR-5.1):
//     aad = utf8(id) || bigEndianUint64(ts). Verbatim replay of a whole envelope
//     is prevented separately by a per-session anti-replay window on the receive
//     path (see Session.Open / replayGuard), not by the AAD binding alone.
//
// Only golang.org/x/crypto primitives are used; there is no custom cryptography
// (FR-5.3).
//
// # Forward secrecy (not yet provided — FR-5.2)
//
// The shared secret is computed from the long-term X25519 identity keys only; the
// handshake nonces vary the derived keys per session but feed the HKDF salt, not
// the input keying material. This gives per-session key separation but NOT forward
// secrecy: an adversary who records ciphertext and the cleartext handshake nonces
// and later compromises a device's long-term identity private key can re-derive
// every past and future session key and decrypt the recorded traffic. Adding an
// ephemeral X25519 exchange per session (mixing the ephemeral DH into the HKDF
// IKM) to provide real forward secrecy is tracked as a follow-up; until it lands,
// do not rely on forward secrecy. See docs/SECURITY-AUDIT.md (SG-01).
package e2ee

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	"github.com/lley154/secure-gateway/internal/token"
)

// ErrReplay is returned by Open when an envelope id has already been delivered on
// this session, and ErrStale when its timestamp falls before the replay window.
// Both reject duplicate delivery of an authenticated message (FR-5.1, SG-02).
var (
	ErrReplay = errors.New("e2ee: replay detected")
	ErrStale  = errors.New("e2ee: timestamp outside replay window")
)

// defaultReplayWindowMillis bounds how far behind the highest seen timestamp an
// envelope may be and still be accepted. Envelope ts is unix-milliseconds (the
// relay protocol's ts unit), so this is a 5-minute acceptance window.
const defaultReplayWindowMillis int64 = 5 * 60 * 1000

const (
	// KeySize is the X25519 key length and the derived AEAD key length.
	KeySize = 32
	// HandshakeNonceSize is the per-session handshake nonce length each side
	// contributes to the HKDF salt.
	HandshakeNonceSize = 32
	// NonceSize is the XChaCha20-Poly1305 nonce length prepended to ciphertext.
	NonceSize = chacha20poly1305.NonceSizeX // 24

	infoPrefix = "secure-gateway/e2ee/v1|"
	dirM2D     = "m2d" // mobile -> desktop
	dirD2M     = "d2m" // desktop -> mobile
)

// Role names the device's role on the pairing, reused from the token package so
// the E2EE direction matches the connection-token role exactly.
type Role = token.Role

// KeyPair is an X25519 keypair. The private key never leaves the device
// (FR-2.3); only the public key is exchanged during pairing.
type KeyPair struct {
	Private [KeySize]byte
	Public  [KeySize]byte
}

// GenerateKeyPair returns a fresh X25519 keypair.
func GenerateKeyPair() (KeyPair, error) {
	var kp KeyPair
	if _, err := io.ReadFull(rand.Reader, kp.Private[:]); err != nil {
		return KeyPair{}, fmt.Errorf("e2ee: read random: %w", err)
	}
	pub, err := PublicFromPrivate(kp.Private)
	if err != nil {
		return KeyPair{}, err
	}
	kp.Public = pub
	return kp, nil
}

// PublicFromPrivate derives the X25519 public key for priv.
func PublicFromPrivate(priv [KeySize]byte) ([KeySize]byte, error) {
	var pub [KeySize]byte
	out, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return pub, fmt.Errorf("e2ee: derive public key: %w", err)
	}
	copy(pub[:], out)
	return pub, nil
}

// NewHandshakeNonce returns a fresh 32-byte session handshake nonce.
func NewHandshakeNonce() ([]byte, error) {
	n := make([]byte, HandshakeNonceSize)
	if _, err := io.ReadFull(rand.Reader, n); err != nil {
		return nil, fmt.Errorf("e2ee: read random: %w", err)
	}
	return n, nil
}

// Session holds the two directional keys for one connection session. Build one
// per session after both handshake nonces have been exchanged.
type Session struct {
	sendKey [KeySize]byte // seals outbound (this device -> peer)
	recvKey [KeySize]byte // opens inbound (peer -> this device)
	recv    *replayGuard  // anti-replay state for inbound envelopes (SG-02)
}

// replayGuard enforces single-delivery of authenticated (id, ts) envelopes within
// a sliding timestamp window. It must only be advanced with id/ts that the AEAD
// has already authenticated, so an attacker cannot inject an unauthenticated high
// ts to push the window forward and starve legitimate messages.
type replayGuard struct {
	mu     sync.Mutex
	window int64
	lastTS int64
	seen   map[string]int64
	primed bool
}

func newReplayGuard(window int64) *replayGuard {
	return &replayGuard{window: window, seen: make(map[string]int64)}
}

func (g *replayGuard) check(id string, ts int64) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.primed && ts < g.lastTS-g.window {
		return ErrStale
	}
	if _, ok := g.seen[id]; ok {
		return ErrReplay
	}
	g.seen[id] = ts
	if !g.primed || ts > g.lastTS {
		g.lastTS = ts
	}
	g.primed = true
	// Prune ids that have fallen out of the window relative to the high-water mark.
	floor := g.lastTS - g.window
	for k, v := range g.seen {
		if v < floor {
			delete(g.seen, k)
		}
	}
	return nil
}

// NewSession derives the directional session keys from the X25519 shared secret
// and both sides' handshake nonces, assigning send/recv from myRole. mobileNonce
// and desktopNonce must each be HandshakeNonceSize bytes and identical on both
// devices.
func NewSession(myPriv, peerPub [KeySize]byte, myRole Role, mobileNonce, desktopNonce []byte) (*Session, error) {
	if myRole != token.RoleMobile && myRole != token.RoleDesktop {
		return nil, fmt.Errorf("e2ee: invalid role %q", myRole)
	}
	if len(mobileNonce) != HandshakeNonceSize || len(desktopNonce) != HandshakeNonceSize {
		return nil, fmt.Errorf("e2ee: handshake nonces must be %d bytes", HandshakeNonceSize)
	}
	shared, err := x25519(myPriv, peerPub)
	if err != nil {
		// X25519 rejects low-order points (all-zero shared secret).
		return nil, fmt.Errorf("e2ee: ecdh: %w", err)
	}
	keyM2D, err := deriveKey(shared, mobileNonce, desktopNonce, dirM2D)
	if err != nil {
		return nil, err
	}
	keyD2M, err := deriveKey(shared, mobileNonce, desktopNonce, dirD2M)
	if err != nil {
		return nil, err
	}
	s := &Session{recv: newReplayGuard(defaultReplayWindowMillis)}
	if myRole == token.RoleMobile {
		s.sendKey, s.recvKey = keyM2D, keyD2M
	} else {
		s.sendKey, s.recvKey = keyD2M, keyM2D
	}
	return s, nil
}

// x25519 computes the raw Curve25519 shared secret, rejecting low-order points.
func x25519(priv, peerPub [KeySize]byte) ([]byte, error) {
	return curve25519.X25519(priv[:], peerPub[:])
}

func deriveKey(shared, mobileNonce, desktopNonce []byte, dir string) ([KeySize]byte, error) {
	salt := make([]byte, 0, len(mobileNonce)+len(desktopNonce))
	salt = append(salt, mobileNonce...)
	salt = append(salt, desktopNonce...)
	r := hkdf.New(sha256.New, shared, salt, []byte(infoPrefix+dir))
	var key [KeySize]byte
	if _, err := io.ReadFull(r, key[:]); err != nil {
		return key, fmt.Errorf("e2ee: hkdf: %w", err)
	}
	return key, nil
}

// Seal encrypts plaintext for the peer, binding the envelope id and ts as AEAD
// associated data. The returned bytes are nonce(24) || ciphertext, ready to be
// carried verbatim as the envelope payload.
func (s *Session) Seal(id string, ts int64, plaintext []byte) ([]byte, error) {
	var nonce [NonceSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, fmt.Errorf("e2ee: read random: %w", err)
	}
	return s.sealWith(nonce[:], id, ts, plaintext)
}

// sealWith is Seal with an explicit nonce, for deterministic interop vectors and
// round-trip tests. Production code uses Seal (random nonce).
func (s *Session) sealWith(nonce []byte, id string, ts int64, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(s.sendKey[:])
	if err != nil {
		return nil, fmt.Errorf("e2ee: new aead: %w", err)
	}
	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("e2ee: nonce must be %d bytes", aead.NonceSize())
	}
	out := make([]byte, len(nonce), len(nonce)+len(plaintext)+aead.Overhead())
	copy(out, nonce)
	return aead.Seal(out, nonce, plaintext, aad(id, ts)), nil
}

// Open decrypts a wire payload (nonce(24) || ciphertext) from the peer, checking
// it against the envelope id and ts. It fails if the ciphertext, id, or ts was
// tampered with.
func (s *Session) Open(id string, ts int64, wire []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(s.recvKey[:])
	if err != nil {
		return nil, fmt.Errorf("e2ee: new aead: %w", err)
	}
	if len(wire) < aead.NonceSize() {
		return nil, errors.New("e2ee: ciphertext too short")
	}
	nonce, ct := wire[:aead.NonceSize()], wire[aead.NonceSize():]
	pt, err := aead.Open(nil, nonce, ct, aad(id, ts))
	if err != nil {
		return nil, fmt.Errorf("e2ee: open: %w", err)
	}
	// Reject duplicate delivery only after the AEAD has authenticated id and ts,
	// so the replay window cannot be advanced by forged metadata (SG-02, FR-5.1).
	if err := s.recv.check(id, ts); err != nil {
		return nil, err
	}
	return pt, nil
}

// aad binds the envelope id and ts as AEAD associated data: utf8(id) followed by
// the big-endian uint64 ts.
func aad(id string, ts int64) []byte {
	b := make([]byte, len(id)+8)
	copy(b, id)
	binary.BigEndian.PutUint64(b[len(id):], uint64(ts))
	return b
}
