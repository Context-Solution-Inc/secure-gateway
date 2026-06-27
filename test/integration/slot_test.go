package integration

import (
	"testing"
	"time"

	"github.com/context-solutions-inc/secure-gateway/internal/backplane"
	"github.com/context-solutions-inc/secure-gateway/internal/token"
)

// TestSlotEvictionSupersedes verifies that a second connection for the same
// (pair, role) evicts the first with close code 4001 (FR-3.4, default newest-
// wins). The newcomer remains connected.
func TestSlotEvictionSupersedes(t *testing.T) {
	h := newHarness(t, nil, nil)
	ctx := ctxT(t)

	first, err := h.dial(t, ctx, h.mint(t, "pair_S", "dev_m", token.RoleMobile))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()

	// Second mobile on the same pair+role supersedes the first.
	second, err := h.dial(t, ctx, h.mint(t, "pair_S", "dev_m2", token.RoleMobile))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	code, _ := first.WaitClose(ctx)
	if code != 4001 {
		t.Fatalf("evicted connection close code = %d, want 4001 superseded", code)
	}

	// The newcomer must still be usable: with no peer it should get peer_offline.
	if err := second.SendMsg(ctx, "id-1", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := second.RecvType(ctx, "error"); err != nil {
		t.Fatalf("newcomer not usable after eviction: %v", err)
	}
}

// TestRevocationByPairClosesBothEnds verifies a pair-scoped revocation closes
// both endpoints with 4004 within the 2s budget (FR-3.6).
func TestRevocationByPairClosesBothEnds(t *testing.T) {
	h := newHarness(t, nil, nil)
	ctx := ctxT(t)

	mobile, err := h.dial(t, ctx, h.mint(t, "pair_RV", "dev_m", token.RoleMobile))
	if err != nil {
		t.Fatal(err)
	}
	defer mobile.Close()
	desktop, err := h.dial(t, ctx, h.mint(t, "pair_RV", "dev_d", token.RoleDesktop))
	if err != nil {
		t.Fatal(err)
	}
	defer desktop.Close()

	start := time.Now()
	if err := h.bp.PublishRevocation(ctx, backplane.RevocationEvent{PairID: "pair_RV"}); err != nil {
		t.Fatal(err)
	}

	if code, _ := mobile.WaitClose(ctx); code != 4004 {
		t.Fatalf("mobile close code = %d, want 4004 revoked", code)
	}
	if code, _ := desktop.WaitClose(ctx); code != 4004 {
		t.Fatalf("desktop close code = %d, want 4004 revoked", code)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("revocation took %s, want <= 2s", elapsed)
	}
}

// TestRevocationByAccount verifies an account-scoped revocation closes the
// session with 4004.
func TestRevocationByAccount(t *testing.T) {
	h := newHarness(t, nil, nil)
	ctx := ctxT(t)

	mobile, err := h.dial(t, ctx, h.mint(t, "pair_AC", "dev_m", token.RoleMobile))
	if err != nil {
		t.Fatal(err)
	}
	defer mobile.Close()

	if err := h.bp.PublishRevocation(ctx, backplane.RevocationEvent{AccountID: "acct_1"}); err != nil {
		t.Fatal(err)
	}
	if code, _ := mobile.WaitClose(ctx); code != 4004 {
		t.Fatalf("close code = %d, want 4004 revoked", code)
	}
}
