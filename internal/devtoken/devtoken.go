// Package devtoken mints signed connection tokens for development and tests.
//
// It exists so Go test clients and the cmd/devtoken CLI can obtain valid JWTs
// without standing up the Auth & License Service. The token-minting
// implementation now lives in internal/signer (the package the Auth service
// uses in production); devtoken is a thin, backward-compatible alias kept so the
// relay binary still never links token-minting code while existing dev/test
// call sites continue to compile unchanged.
package devtoken

import "github.com/lley154/secure-gateway/internal/signer"

// Signer mints tokens with a single asymmetric key. Alias of signer.Signer.
type Signer = signer.Signer

// TokenParams describe the claims to embed. Alias of signer.TokenParams.
type TokenParams = signer.TokenParams

// NewSigner generates a fresh keypair for the given algorithm ("ES256" or
// "EdDSA") and binds it to kid.
func NewSigner(alg, kid string) (*Signer, error) { return signer.NewSigner(alg, kid) }

// SignerFromPEM reconstructs a Signer from a previously exported PKCS#8 private
// key PEM.
func SignerFromPEM(alg, kid string, privPEM []byte) (*Signer, error) {
	return signer.SignerFromPEM(alg, kid, privPEM)
}
