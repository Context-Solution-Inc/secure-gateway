package e2ee

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/lley154/secure-gateway/internal/token"
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
	Name                  string `json:"name"`
	Sender                string `json:"sender"` // "mobile" | "desktop"
	MobilePrivate         string `json:"mobile_private"`
	MobilePublic          string `json:"mobile_public"`
	DesktopPrivate        string `json:"desktop_private"`
	DesktopPublic         string `json:"desktop_public"`
	MobileHandshakeNonce  string `json:"mobile_handshake_nonce"`
	DesktopHandshakeNonce string `json:"desktop_handshake_nonce"`
	KeyM2D                string `json:"key_m2d"`
	KeyD2M                string `json:"key_d2m"`
	MessageNonce          string `json:"message_nonce"`
	ID                    string `json:"id"`
	TS                    int64  `json:"ts"`
	Plaintext             string `json:"plaintext"`       // hex
	WireCiphertext        string `json:"wire_ciphertext"` // hex: nonce(24) || aead_ct
}

// vectorInputs are the deterministic inputs for each vector; outputs (public
// keys, derived keys, ciphertext) are computed by the implementation.
type vectorInputs struct {
	name                      string
	sender                    token.Role
	mobilePriv, desktopPriv   [KeySize]byte
	mobileNonce, desktopNonce []byte
	messageNonce              []byte
	id                        string
	ts                        int64
	plaintext                 []byte
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
	mNonce := fixedSlice(0x40, HandshakeNonceSize)
	dNonce := fixedSlice(0x70, HandshakeNonceSize)
	return []vectorInputs{
		{
			name: "mobile_to_desktop_basic", sender: token.RoleMobile,
			mobilePriv: mPriv, desktopPriv: dPriv, mobileNonce: mNonce, desktopNonce: dNonce,
			messageNonce: fixedSlice(0xa0, NonceSize),
			id:           "0196a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b", ts: 1765432100123,
			plaintext: []byte("hello desktop, this is the mobile"),
		},
		{
			name: "desktop_to_mobile_basic", sender: token.RoleDesktop,
			mobilePriv: mPriv, desktopPriv: dPriv, mobileNonce: mNonce, desktopNonce: dNonce,
			messageNonce: fixedSlice(0xb0, NonceSize),
			id:           "0196a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c", ts: 1765432100456,
			plaintext: []byte("ack from the desktop side"),
		},
		{
			name: "mobile_to_desktop_empty", sender: token.RoleMobile,
			mobilePriv: mPriv, desktopPriv: dPriv, mobileNonce: mNonce, desktopNonce: dNonce,
			messageNonce: fixedSlice(0xc0, NonceSize),
			id:           "empty-1", ts: 1,
			plaintext: []byte{},
		},
		{
			name: "mobile_to_desktop_binary", sender: token.RoleMobile,
			mobilePriv: mPriv, desktopPriv: dPriv, mobileNonce: mNonce, desktopNonce: dNonce,
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
	mPub, err := PublicFromPrivate(in.mobilePriv)
	if err != nil {
		t.Fatal(err)
	}
	dPub, err := PublicFromPrivate(in.desktopPriv)
	if err != nil {
		t.Fatal(err)
	}

	// Sender's session seals; the seal uses sendKey for the sender's role.
	var myPriv, peerPub [KeySize]byte
	if in.sender == token.RoleMobile {
		myPriv, peerPub = in.mobilePriv, dPub
	} else {
		myPriv, peerPub = in.desktopPriv, mPub
	}
	sender, err := NewSession(myPriv, peerPub, in.sender, in.mobileNonce, in.desktopNonce)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := sender.sealWith(in.messageNonce, in.id, in.ts, in.plaintext)
	if err != nil {
		t.Fatal(err)
	}

	// Directional keys are independent of sender role; derive both for the file.
	shared, err := x25519(in.mobilePriv, dPub)
	if err != nil {
		t.Fatal(err)
	}
	km2d, err := deriveKey(shared, in.mobileNonce, in.desktopNonce, dirM2D)
	if err != nil {
		t.Fatal(err)
	}
	kd2m, err := deriveKey(shared, in.mobileNonce, in.desktopNonce, dirD2M)
	if err != nil {
		t.Fatal(err)
	}

	return vector{
		Name: in.name, Sender: string(in.sender),
		MobilePrivate: hex.EncodeToString(in.mobilePriv[:]), MobilePublic: hex.EncodeToString(mPub[:]),
		DesktopPrivate: hex.EncodeToString(in.desktopPriv[:]), DesktopPublic: hex.EncodeToString(dPub[:]),
		MobileHandshakeNonce: hex.EncodeToString(in.mobileNonce), DesktopHandshakeNonce: hex.EncodeToString(in.desktopNonce),
		KeyM2D: hex.EncodeToString(km2d[:]), KeyD2M: hex.EncodeToString(kd2m[:]),
		MessageNonce: hex.EncodeToString(in.messageNonce), ID: in.id, TS: in.ts,
		Plaintext: hex.EncodeToString(in.plaintext), WireCiphertext: hex.EncodeToString(wire),
	}
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
			KDF:  "HKDF-SHA256",
			AEAD: "XChaCha20-Poly1305 (24-byte nonce)",
			Salt: "mobile_handshake_nonce || desktop_handshake_nonce",
			Info: "secure-gateway/e2ee/v1|<dir>  (dir = m2d for mobile->desktop, d2m for desktop->mobile)",
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
			mNonce := mustHex(t, v.MobileHandshakeNonce)
			dNonce := mustHex(t, v.DesktopHandshakeNonce)

			// Public keys must derive from the committed private keys.
			if got, _ := PublicFromPrivate(mPriv); got != mPub {
				t.Fatalf("mobile public key mismatch")
			}
			if got, _ := PublicFromPrivate(dPriv); got != dPub {
				t.Fatalf("desktop public key mismatch")
			}

			// Directional keys must match the committed values.
			shared, err := x25519(mPriv, dPub)
			if err != nil {
				t.Fatal(err)
			}
			km2d, _ := deriveKey(shared, mNonce, dNonce, dirM2D)
			kd2m, _ := deriveKey(shared, mNonce, dNonce, dirD2M)
			if hex.EncodeToString(km2d[:]) != v.KeyM2D {
				t.Fatalf("K_m2d mismatch: got %x want %s", km2d, v.KeyM2D)
			}
			if hex.EncodeToString(kd2m[:]) != v.KeyD2M {
				t.Fatalf("K_d2m mismatch: got %x want %s", kd2m, v.KeyD2M)
			}

			// Re-seal with the committed nonce must reproduce the wire bytes.
			senderRole := token.Role(v.Sender)
			var myPriv, peerPub [KeySize]byte
			if senderRole == token.RoleMobile {
				myPriv, peerPub = mPriv, dPub
			} else {
				myPriv, peerPub = dPriv, mPub
			}
			sender, err := NewSession(myPriv, peerPub, senderRole, mNonce, dNonce)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := sender.sealWith(mustHex(t, v.MessageNonce), v.ID, v.TS, mustHex(t, v.Plaintext))
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(wire) != v.WireCiphertext {
				t.Fatalf("ciphertext mismatch:\n got  %x\n want %s", wire, v.WireCiphertext)
			}

			// The peer must open the committed ciphertext back to the plaintext.
			peerRole := senderRole.Opposite()
			var peerPriv, senderPub [KeySize]byte
			if peerRole == token.RoleMobile {
				peerPriv, senderPub = mPriv, dPub
			} else {
				peerPriv, senderPub = dPriv, mPub
			}
			peer, err := NewSession(peerPriv, senderPub, peerRole, mNonce, dNonce)
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
