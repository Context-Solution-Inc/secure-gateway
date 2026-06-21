package integration

import (
	"context"
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/lley154/secure-gateway/internal/e2ee"
)

// TestDeviceRegistrationCap is the SG-10 regression (cap half): POST /v1/devices
// used to insert a new row on every call with no per-account bound. The default
// cap is 10 devices/account; the 11th distinct device is refused with 409.
func TestDeviceRegistrationCap(t *testing.T) {
	a := newAuthHarnessNoBilling(t)
	secret, _ := a.createAccountOpen(t, "acct_sg10_cap")

	for i := 0; i < 10; i++ {
		kp, err := e2ee.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		status, body := a.do(t, http.MethodPost, "/v1/devices", secret, map[string]string{
			"role": "mobile", "public_key": base64.StdEncoding.EncodeToString(kp.Public[:]),
		})
		if status != http.StatusOK {
			t.Fatalf("device %d within cap: status %d body %s", i, status, body)
		}
	}
	kp, err := e2ee.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	status, body := a.do(t, http.MethodPost, "/v1/devices", secret, map[string]string{
		"role": "mobile", "public_key": base64.StdEncoding.EncodeToString(kp.Public[:]),
	})
	if status != http.StatusConflict {
		t.Fatalf("11th device past cap: want 409, got %d body %s", status, body)
	}
}

// TestDeviceRegistrationIdempotent is the SG-10 regression (idempotency half):
// re-registering the same role+public_key returns the existing device id and
// does not grow the row count, so a retrying client cannot amplify rows.
func TestDeviceRegistrationIdempotent(t *testing.T) {
	a := newAuthHarnessNoBilling(t)
	const accountID = "acct_sg10_idem"
	secret, _ := a.createAccountOpen(t, accountID)

	kp, err := e2ee.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub := base64.StdEncoding.EncodeToString(kp.Public[:])

	register := func() string {
		status, body := a.do(t, http.MethodPost, "/v1/devices", secret, map[string]string{
			"role": "mobile", "public_key": pub,
		})
		if status != http.StatusOK {
			t.Fatalf("register: status %d body %s", status, body)
		}
		var r struct {
			DeviceID string `json:"device_id"`
		}
		mustUnmarshal(t, body, &r)
		return r.DeviceID
	}

	first := register()
	second := register()
	if first != second {
		t.Fatalf("re-registration not idempotent: %s vs %s", first, second)
	}
	if n, err := a.store.CountDevicesByAccount(context.Background(), accountID); err != nil || n != 1 {
		t.Fatalf("CountDevicesByAccount = %d err=%v, want 1 (idempotent re-registration must not grow rows)", n, err)
	}
}
