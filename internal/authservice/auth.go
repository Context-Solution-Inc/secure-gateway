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

// newPairCredential mints a per-pair credential of the form "<pair_id>.<rand>"
// (security L2), mirroring newAccountSecret so the pair id can be recovered from
// the bearer prefix without a secondary index. The phone uses this instead of the
// account secret, which no longer rides the pairing QR.
func newPairCredential(pairID string) string {
	return pairID + "." + authstore.NewID("pc")[3:] // drop the "pc_" prefix; keep random tail
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

// authenticatePair verifies a per-pair credential bearer (security L2) and
// returns the credential it authenticated. The credential encodes the pair id as
// its prefix (mirroring authenticateAccount); we look the row up by pair id and
// compare the stored hash in constant time, rejecting a revoked credential.
func (s *Service) authenticatePair(ctx context.Context, r *http.Request) (authstore.PairCredential, error) {
	secret := bearer(r)
	if secret == "" {
		return authstore.PairCredential{}, errUnauthorized
	}
	pairID, _, ok := strings.Cut(secret, ".")
	if !ok || pairID == "" {
		return authstore.PairCredential{}, errUnauthorized
	}
	cred, err := s.store.GetPairCredential(ctx, pairID)
	if err != nil || cred.SecretHash == "" || !cred.Active(s.now()) {
		return authstore.PairCredential{}, errUnauthorized
	}
	if subtle.ConstantTimeCompare([]byte(hashSecret(secret)), []byte(cred.SecretHash)) != 1 {
		return authstore.PairCredential{}, errUnauthorized
	}
	return cred, nil
}

// authenticateAccountOrPair accepts EITHER the desktop's account secret OR a
// phone's per-pair credential (security L2) at the relay token/unpair endpoints.
// It returns the authenticated account id and, when the caller used a pair
// credential, that credential (else nil) so callers can additionally bind the
// request to the credential's pair/device. The two credential forms have
// disjoint prefixes ("<account_id>." vs "<pair_id>."), so trying account-first
// can never misclassify one as the other.
func (s *Service) authenticateAccountOrPair(ctx context.Context, r *http.Request) (string, *authstore.PairCredential, error) {
	if accountID, err := s.authenticateAccount(ctx, r); err == nil {
		return accountID, nil, nil
	}
	if cred, err := s.authenticatePair(ctx, r); err == nil {
		return cred.AccountID, &cred, nil
	}
	return "", nil, errUnauthorized
}

// authorizeAdmin checks the admin bearer used to provision account secrets.
func (s *Service) authorizeAdmin(r *http.Request) bool {
	if s.adminKey == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(bearer(r)), []byte(s.adminKey)) == 1
}
