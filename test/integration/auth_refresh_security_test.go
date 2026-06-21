package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
)

// TestRefreshTokenSingleUseUnderConcurrency is the SG-03 regression: refresh-token
// rotation must be atomic, so two requests presenting the same refresh token
// concurrently yield exactly one new token pair (the loser is rejected). Before
// the atomic ConsumeRefreshToken gate, both could pass the Active() check and each
// receive a valid, independently-rotating token.
func TestRefreshTokenSingleUseUnderConcurrency(t *testing.T) {
	a := newAuthHarnessNoBilling(t)
	secret, licenseID := a.createAccountOpen(t, "acct_sg03")
	mobileID := a.registerDevice(t, secret, "mobile")
	desktopID := a.registerDevice(t, secret, "desktop")
	pairID, _, _ := a.qrPair(t, secret, licenseID, mobileID, desktopID)

	_, tok := a.issueToken(t, secret, mobileID, pairID)
	if tok.RefreshToken == "" {
		t.Fatal("expected a refresh token")
	}

	const n = 8
	var wg sync.WaitGroup
	var ok200 int64
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // release all goroutines together to maximize the race window
			if refreshRaw(t, a.authSrv.URL, tok.RefreshToken) == http.StatusOK {
				atomic.AddInt64(&ok200, 1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if ok200 != 1 {
		t.Fatalf("concurrent refresh of one token: want exactly 1 success, got %d", ok200)
	}
	// Sequential reuse of the original token is also refused.
	if status, _ := a.refreshToken(t, tok.RefreshToken); status == http.StatusOK {
		t.Fatal("original refresh token must not be reusable after rotation")
	}
}

// TestRepairEvictsRefreshTokens is the SG-04 regression: after re-pairing replaces
// a device, the evicted device's refresh token must no longer mint connection
// tokens (FR-2.4). Previously the refresh path skipped the pairing-membership
// check and re-pair never revoked the evicted device's refresh tokens, so the
// replaced device could refresh and hijack the relay slot for up to the refresh TTL.
func TestRepairEvictsRefreshTokens(t *testing.T) {
	a := newAuthHarnessNoBilling(t)
	secret, licenseID := a.createAccountOpen(t, "acct_sg04")
	oldMobileID := a.registerDevice(t, secret, "mobile")
	desktopID := a.registerDevice(t, secret, "desktop")
	pairID, _, _ := a.qrPair(t, secret, licenseID, oldMobileID, desktopID)

	_, oldTok := a.issueToken(t, secret, oldMobileID, pairID)
	if oldTok.RefreshToken == "" {
		t.Fatal("expected a refresh token for the original mobile")
	}

	// Re-pair the same desktop with a NEW mobile device, evicting the old mobile.
	newMobileID := a.registerDevice(t, secret, "mobile")
	rePairID, _, _ := a.qrPair(t, secret, licenseID, newMobileID, desktopID)
	if rePairID != pairID {
		t.Fatalf("re-pair should reuse the same pair_id: got %s want %s", rePairID, pairID)
	}

	// The evicted device's refresh token must be rejected.
	if status, _ := a.refreshToken(t, oldTok.RefreshToken); status == http.StatusOK {
		t.Fatal("evicted device's refresh token must not mint new connection tokens")
	}
	// And it cannot issue a fresh token pair either (no longer in the pairing).
	if status, _ := a.issueToken(t, secret, oldMobileID, pairID); status == http.StatusOK {
		t.Fatal("evicted device must not be able to issue new tokens for the pairing")
	}
}

// TestRefreshTokenReuseRevokesChain is the SG-17 regression: presenting an
// already-rotated (revoked, not merely expired) refresh token is a leaked-token
// signal. Reuse detection must revoke the whole descendant chain for the device
// and publish a revocation, so the attacker cannot keep a self-renewing chain
// alive after racing the legitimate client's rotation.
func TestRefreshTokenReuseRevokesChain(t *testing.T) {
	a := newAuthHarnessNoBilling(t)
	secret, licenseID := a.createAccountOpen(t, "acct_sg17")
	mobileID := a.registerDevice(t, secret, "mobile")
	desktopID := a.registerDevice(t, secret, "desktop")
	pairID, _, _ := a.qrPair(t, secret, licenseID, mobileID, desktopID)

	_, tok := a.issueToken(t, secret, mobileID, pairID)
	if tok.RefreshToken == "" {
		t.Fatal("expected a refresh token")
	}

	// Legitimate rotation: original -> rotated. The original is now revoked.
	status, rotated := a.refreshToken(t, tok.RefreshToken)
	if status != http.StatusOK || rotated.RefreshToken == "" {
		t.Fatalf("first refresh should rotate successfully: status %d", status)
	}

	// Reuse the ORIGINAL (already-consumed) token: this trips reuse detection.
	if status, _ := a.refreshToken(t, tok.RefreshToken); status == http.StatusOK {
		t.Fatal("reused (already-rotated) refresh token must be rejected")
	}
	// The rotated descendant must now also be dead — the chain was revoked.
	if status, _ := a.refreshToken(t, rotated.RefreshToken); status == http.StatusOK {
		t.Fatal("descendant token must be revoked after reuse of an ancestor (chain revocation)")
	}
}

// refreshRaw posts a refresh request directly (no t.Fatal), so it is safe to call
// from concurrent goroutines.
func refreshRaw(t *testing.T, baseURL, refresh string) int {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"refresh_token": refresh})
	resp, err := http.Post(baseURL+"/v1/token/refresh", "application/json", bytes.NewReader(body))
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}
