package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/context-solutions-inc/secure-gateway/internal/e2ee"
)

// TestPairingCapacityNotExceededUnderConcurrency is the SG-16 regression: the
// max_pairs capacity check used to be TOCTOU — two completions for distinct
// pairing tokens on the same license could both observe a free slot and both
// insert, exceeding the licensed pair count. The count+insert is now atomic, so
// on a max_pairs=1 license exactly one of two concurrent completions wins.
func TestPairingCapacityNotExceededUnderConcurrency(t *testing.T) {
	a := newAuthHarnessNoBilling(t)
	secret, licenseID := a.createAccountOpen(t, "acct_sg16") // open license: max_pairs=1

	// Two distinct desktop+mobile pairs, each with its own pairing token, so both
	// completions are brand-new pairings (not a re-pair that reuses a slot).
	type attempt struct {
		token     string
		mobileID  string
		mobilePub string
	}
	var attempts []attempt
	for i := 0; i < 2; i++ {
		desktopID := a.registerDevice(t, secret, "desktop")
		mobileID := a.registerDevice(t, secret, "mobile")
		desktopKP, err := e2ee.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		mobileKP, err := e2ee.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		status, body := a.do(t, http.MethodPost, "/v1/pairing-tokens", secret, map[string]string{
			"license_id": licenseID, "desktop_device_id": desktopID,
			"desktop_public_key": base64.StdEncoding.EncodeToString(desktopKP.Public[:]),
		})
		if status != http.StatusOK {
			t.Fatalf("issue pairing token %d: status %d body %s", i, status, body)
		}
		var issued struct {
			PairingToken string `json:"pairing_token"`
		}
		mustUnmarshal(t, body, &issued)
		attempts = append(attempts, attempt{
			token: issued.PairingToken, mobileID: mobileID,
			mobilePub: base64.StdEncoding.EncodeToString(mobileKP.Public[:]),
		})
	}

	var wg sync.WaitGroup
	var ok200, conflict409 int64
	start := make(chan struct{})
	for _, at := range attempts {
		wg.Add(1)
		go func(at attempt) {
			defer wg.Done()
			<-start // release together to maximize the race window
			switch completePairingRaw(a.authSrv.URL, at.token, at.mobileID, at.mobilePub) {
			case http.StatusOK:
				atomic.AddInt64(&ok200, 1)
			case http.StatusConflict:
				atomic.AddInt64(&conflict409, 1)
			}
		}(at)
	}
	close(start)
	wg.Wait()

	if ok200 != 1 || conflict409 != 1 {
		t.Fatalf("concurrent completion on max_pairs=1: want 1 ok + 1 conflict, got ok=%d conflict=%d", ok200, conflict409)
	}
	if n, err := a.store.ActivePairCount(context.Background(), licenseID); err != nil || n != 1 {
		t.Fatalf("ActivePairCount = %d err=%v, want 1 (license must not be over-subscribed)", n, err)
	}
}

// completePairingRaw posts a pairing completion directly (no t.Fatal), so it is
// safe to call from concurrent goroutines.
func completePairingRaw(baseURL, token, mobileID, mobilePub string) int {
	body, _ := json.Marshal(map[string]string{
		"pairing_token": token, "mobile_device_id": mobileID, "mobile_public_key": mobilePub,
	})
	resp, err := http.Post(baseURL+"/v1/pairings", "application/json", bytes.NewReader(body))
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}
