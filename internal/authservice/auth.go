package authservice

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"

	"github.com/lley154/secure-gateway/internal/authstore"
)

// errUnauthorized is the generic auth failure; handlers map it to 401.
var errUnauthorized = errors.New("unauthorized")

// hashSecret returns the hex SHA-256 of a high-entropy secret. The secrets here
// are 128-bit random tokens (not passwords), so a fast hash is appropriate and a
// password KDF is unnecessary.
func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// newAccountSecret mints an account credential of the form "<account_id>.<rand>"
// so the account id can be recovered from the bearer without a secondary index.
func newAccountSecret(accountID string) string {
	return accountID + "." + authstore.NewID("s")[2:] // drop the "s_" prefix; keep random tail
}

// bearer extracts the token from an Authorization: Bearer header.
func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if len(h) > len(p) && strings.EqualFold(h[:len(p)], p) {
		return strings.TrimSpace(h[len(p):])
	}
	return ""
}

// authenticateAccount verifies the account bearer secret and returns the
// authenticated account id (FR-3.1; M2-minimal account credential). The secret
// encodes the account id as its prefix; we verify it against the stored hash in
// constant time.
func (s *Service) authenticateAccount(ctx context.Context, r *http.Request) (string, error) {
	secret := bearer(r)
	if secret == "" {
		return "", errUnauthorized
	}
	accountID, _, ok := strings.Cut(secret, ".")
	if !ok || accountID == "" {
		return "", errUnauthorized
	}
	acct, err := s.store.GetAccount(ctx, accountID)
	if err != nil || acct.SecretHash == "" {
		return "", errUnauthorized
	}
	if subtle.ConstantTimeCompare([]byte(hashSecret(secret)), []byte(acct.SecretHash)) != 1 {
		return "", errUnauthorized
	}
	return accountID, nil
}

// authorizeAdmin checks the admin bearer used to provision account secrets.
func (s *Service) authorizeAdmin(r *http.Request) bool {
	if s.adminKey == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(bearer(r)), []byte(s.adminKey)) == 1
}
