package e2ee

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/context-solutions-inc/secure-gateway/internal/token"
)

// vectorFile is the on-disk shape of the canonical interop contract
// (testdata/vectors.json). All byte fields are lowercase hex.
type vectorFile struct {
	Scheme  schemeDoc `json:"scheme"`
	Vectors []vector  `json:"vectors"`
}

type schemeDoc struct {
	KDF  string `json:"kdf"`
	AEAD string `json:"aead"`
	Salt string `json:"salt"`
	Info string `json:"info"`
	AAD  string `json:"aad"`
	Wire string `json:"wire"`
}

type vector struct {
	Name                    string `json:"name"`
	Sender                  string `json:"sender"` // "mobile" | "desktop"
	MobilePrivate           string `json:"mobile_private"`
	MobilePublic            string `json:"mobile_public"`
	DesktopPrivate          string `json:"desktop_private"`
	DesktopPublic           string `json:"desktop_public"`
	MobileEphemeralPrivate  string `json:"mobile_ephemeral_private"`
	MobileEphemeralPublic   string `json:"mobile_ephemeral_public"`
	DesktopEphemeralPrivate string `json:"desktop_ephemeral_private"`
	DesktopEphemeralPublic  string `json:"desktop_ephemeral_public"`
	KeyM2D                  string `json:"key_m2d"`
	KeyD2M                  string `json:"key_d2m"`
	MessageNonce            string `json:"message_nonce"`
	ID                      string `json:"id"`
	TS                      int64  `json:"ts"`
	Plaintext               string `json:"plaintext"`       // hex
	WireCiphertext          string `json:"wire_ciphertext"` // hex: nonce(24) || aead_ct
}

// vectorInputs are the deterministic inputs for each vector; outputs (public
// keys, derived keys, ciphertext) are computed by the implementation.
type vectorInputs struct {
	name                          string
	sender                        token.Role
	mobilePriv, desktopPriv       [KeySize]byte // long-term identity keys
	mobileEphPriv, desktopEphPriv [KeySize]byte // per-session ephemeral keys
	messageNonce                  []byte
	id                            string
	ts                            int64
	plaintext                     []byte
}

func fixed(b byte) [KeySize]byte {
	var a [KeySize]byte
	for i := range a {
		a[i] = b + byte(i)
	}
	return a
}

func fixedSlice(b byte, n int) []byte {
	s := make([]byte, n)
	for i := range s {
		s[i] = b + byte(i)
	}
	return s
}

func vectorInputSet() []vectorInputs {
	mPriv := fixed(0x01)
	dPriv := fixed(0x21)
	mEph := fixed(0x50) // mobile ephemeral
	dEph := fixed(0x80) // desktop ephemeral
	return []vectorInputs{
		{
			name: "mobile_to_desktop_basic", sender: token.RoleMobile,
			mobilePriv: mPriv, desktopPriv: dPriv, mobileEphPriv: mEph, desktopEphPriv: dEph,
			messageNonce: fixedSlice(0xa0, NonceSize),
			id:           "0196a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b", ts: 1765432100123,
			plaintext: []byte("hello desktop, this is the mobile"),
		},
		{
			name: "desktop_to_mobile_basic", sender: token.RoleDesktop,
			mobilePriv: mPriv, desktopPriv: dPriv, mobileEphPriv: mEph, desktopEphPriv: dEph,
			messageNonce: fixedSlice(0xb0, NonceSize),
			id:           "0196a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c", ts: 1765432100456,
			plaintext: []byte("ack from the desktop side"),
		},
		{
			name: "mobile_to_desktop_empty", sender: token.RoleMobile,
			mobilePriv: mPriv, desktopPriv: dPriv, mobileEphPriv: mEph, desktopEphPriv: dEph,
			messageNonce: fixedSlice(0xc0, NonceSize),
			id:           "empty-1", ts: 1,
			plaintext: []byte{},
		},
		{
			name: "mobile_to_desktop_binary", sender: token.RoleMobile,
			mobilePriv: mPriv, desktopPriv: dPriv, mobileEphPriv: mEph, desktopEphPriv: dEph,
			messageNonce: fixedSlice(0xd0, NonceSize),
			id:           "binary-1", ts: 9007199254740991,
			plaintext: []byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0x00, 0x80, 0x7f},
		},
	}
}

const vectorsPath = "testdata/vectors.json"

// buildVector computes the full vector (outputs included) from inputs.
func buildVector(t *testing.T, in vectorInputs) vector {
	t.Helper()
	mPub := pub(t, in.mobilePriv)
	dPub := pub(t, in.desktopPriv)
	mEphPub := pub(t, in.mobileEphPriv)
	dEphPub := pub(t, in.desktopEphPriv)

	// Directional keys are independent of sender role: the mobile session seals
	// with K_m2d and opens with K_d2m, so read both off a mobile session.
	mobile, err := NewSession(in.mobilePriv, dPub, in.mobileEphPriv, dEphPub, token.RoleMobile)
	if err != nil {
		t.Fatal(err)
	}
	km2d, kd2m := mobile.sendKey, mobile.recvKey

	// The sender's session seals with the fixed message nonce.
	var sender *Session
	if in.sender == token.RoleMobile {
		sender = mobile
	} else {
		sender, err = NewSession(in.desktopPriv, mPub, in.desktopEphPriv, mEphPub, token.RoleDesktop)
		if err != nil {
			t.Fatal(err)
		}
	}
	wire, err := sender.sealWith(in.messageNonce, in.id, in.ts, in.plaintext)
	if err != nil {
		t.Fatal(err)
	}

	return vector{
		Name: in.name, Sender: string(in.sender),
		MobilePrivate: hex.EncodeToString(in.mobilePriv[:]), MobilePublic: hex.EncodeToString(mPub[:]),
		DesktopPrivate: hex.EncodeToString(in.desktopPriv[:]), DesktopPublic: hex.EncodeToString(dPub[:]),
		MobileEphemeralPrivate: hex.EncodeToString(in.mobileEphPriv[:]), MobileEphemeralPublic: hex.EncodeToString(mEphPub[:]),
		DesktopEphemeralPrivate: hex.EncodeToString(in.desktopEphPriv[:]), DesktopEphemeralPublic: hex.EncodeToString(dEphPub[:]),
		KeyM2D: hex.EncodeToString(km2d[:]), KeyD2M: hex.EncodeToString(kd2m[:]),
		MessageNonce: hex.EncodeToString(in.messageNonce), ID: in.id, TS: in.ts,
		Plaintext: hex.EncodeToString(in.plaintext), WireCiphertext: hex.EncodeToString(wire),
	}
}

// pub is a test helper: the X25519 public key for a private key, failing the test
// on error.
func pub(t *testing.T, priv [KeySize]byte) [KeySize]byte {
	t.Helper()
	p, err := PublicFromPrivate(priv)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestWriteVectors regenerates testdata/vectors.json from the fixed inputs. It is
// skipped during normal test runs; run it with E2EE_GEN_VECTORS=1 to refresh the
// committed contract after an intentional scheme change.
func TestWriteVectors(t *testing.T) {
	if os.Getenv("E2EE_GEN_VECTORS") == "" {
		t.Skip("set E2EE_GEN_VECTORS=1 to regenerate testdata/vectors.json")
	}
	f := vectorFile{
		Scheme: schemeDoc{
			KDF:  "HKDF-SHA256 over ikm = ss || ee || md || dm (ss=DH(mIdentity,dIdentity), ee=DH(mEphemeral,dEphemeral), md=DH(mIdentity,dEphemeral), dm=DH(dIdentity,mEphemeral))",
			AEAD: "XChaCha20-Poly1305 (24-byte nonce)",
			Salt: "mobile_ephemeral_public || desktop_ephemeral_public",
			Info: "secure-gateway/e2ee/v2|<dir>  (dir = m2d for mobile->desktop, d2m for desktop->mobile)",
			AAD:  "utf8(id) || big-endian uint64(ts)",
			Wire: "message_nonce(24) || aead_ciphertext(plaintext + 16-byte tag)",
		},
	}
	for _, in := range vectorInputSet() {
		f.Vectors = append(f.Vectors, buildVector(t, in))
	}
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // keep the human-facing scheme doc readable (<dir>, ->)
	enc.SetIndent("", "  ")
	if err := enc.Encode(f); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vectorsPath, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d vectors to %s", len(f.Vectors), vectorsPath)
}

// TestVectors is the exit criterion (PRD §11 M3): the Go reference reproduces the
// committed interop vectors byte-for-byte and decrypts them. The M4 SDKs must
// match the same file.
func TestVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Clean(vectorsPath))
	if err != nil {
		t.Fatalf("read vectors (run TestWriteVectors with E2EE_GEN_VECTORS=1 first): %v", err)
	}
	var f vectorFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Vectors) == 0 {
		t.Fatal("no vectors in file")
	}
	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			mPriv := mustKey(t, v.MobilePrivate)
			dPriv := mustKey(t, v.DesktopPrivate)
			mPub := mustKey(t, v.MobilePublic)
			dPub := mustKey(t, v.DesktopPublic)
			mEphPriv := mustKey(t, v.MobileEphemeralPrivate)
			dEphPriv := mustKey(t, v.DesktopEphemeralPrivate)
			mEphPub := mustKey(t, v.MobileEphemeralPublic)
			dEphPub := mustKey(t, v.DesktopEphemeralPublic)

			// Public keys (identity and ephemeral) must derive from the committed privs.
			if got, _ := PublicFromPrivate(mPriv); got != mPub {
				t.Fatalf("mobile public key mismatch")
			}
			if got, _ := PublicFromPrivate(dPriv); got != dPub {
				t.Fatalf("desktop public key mismatch")
			}
			if got, _ := PublicFromPrivate(mEphPriv); got != mEphPub {
				t.Fatalf("mobile ephemeral public key mismatch")
			}
			if got, _ := PublicFromPrivate(dEphPriv); got != dEphPub {
				t.Fatalf("desktop ephemeral public key mismatch")
			}

			// Directional keys must match the committed values (read off a mobile session).
			mobile, err := NewSession(mPriv, dPub, mEphPriv, dEphPub, token.RoleMobile)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(mobile.sendKey[:]) != v.KeyM2D {
				t.Fatalf("K_m2d mismatch: got %x want %s", mobile.sendKey, v.KeyM2D)
			}
			if hex.EncodeToString(mobile.recvKey[:]) != v.KeyD2M {
				t.Fatalf("K_d2m mismatch: got %x want %s", mobile.recvKey, v.KeyD2M)
			}

			// Re-seal with the committed nonce must reproduce the wire bytes.
			senderRole := token.Role(v.Sender)
			var sender *Session
			if senderRole == token.RoleMobile {
				sender = mobile
			} else {
				sender, err = NewSession(dPriv, mPub, dEphPriv, mEphPub, token.RoleDesktop)
				if err != nil {
					t.Fatal(err)
				}
			}
			wire, err := sender.sealWith(mustHex(t, v.MessageNonce), v.ID, v.TS, mustHex(t, v.Plaintext))
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(wire) != v.WireCiphertext {
				t.Fatalf("ciphertext mismatch:\n got  %x\n want %s", wire, v.WireCiphertext)
			}

			// The peer must open the committed ciphertext back to the plaintext.
			var peer *Session
			if senderRole == token.RoleMobile {
				peer, err = NewSession(dPriv, mPub, dEphPriv, mEphPub, token.RoleDesktop)
			} else {
				peer = mobile
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := peer.Open(v.ID, v.TS, mustHex(t, v.WireCiphertext))
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			if hex.EncodeToString(got) != v.Plaintext {
				t.Fatalf("decrypted plaintext mismatch: got %x want %s", got, v.Plaintext)
			}
		})
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func mustKey(t *testing.T, s string) [KeySize]byte {
	t.Helper()
	b := mustHex(t, s)
	if len(b) != KeySize {
		t.Fatalf("key %q is %d bytes, want %d", s, len(b), KeySize)
	}
	var k [KeySize]byte
	copy(k[:], b)
	return k
}
