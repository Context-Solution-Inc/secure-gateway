package integration

import (
	"bytes"
	"testing"
	"time"

	"github.com/lley154/secure-gateway/internal/relay/protocol"
	"github.com/lley154/secure-gateway/internal/token"
)

// TestReconnectKeepsPeerOnline reproduces the "desktop status stuck DOWN after
// the phone switches networks" bug. When the mobile reconnects on a new network
// its fresh session registers and announces peer_online to the still-connected
// desktop; the old, now-superseded session's deferred Deregister must NOT then
// send a spurious peer_offline that clobbers the desktop back to PEER_OFFLINE
// while the new session is alive and routing (relay hub Deregister fix).
func TestReconnectKeepsPeerOnline(t *testing.T) {
	h := newHarness(t, nil, nil)
	ctx := ctxT(t)

	desktop, err := h.dial(t, ctx, h.mint(t, "pair_RC", "dev_d", token.RoleDesktop))
	if err != nil {
		t.Fatalf("desktop dial: %v", err)
	}
	defer desktop.Close()

	mobile1, err := h.dial(t, ctx, h.mint(t, "pair_RC", "dev_m", token.RoleMobile))
	if err != nil {
		t.Fatalf("mobile1 dial: %v", err)
	}
	defer mobile1.Close()

	// Desktop (connected first) gets peer_online when the mobile joins.
	sys, err := desktop.RecvType(ctx, protocol.TypeSys)
	if err != nil {
		t.Fatalf("desktop initial sys recv: %v", err)
	}
	var body protocol.System
	if err := jsonUnmarshal(sys.Payload, &body); err != nil {
		t.Fatal(err)
	}
	if body.Kind != protocol.SysPeerOnline {
		t.Fatalf("initial sys kind = %q, want peer_online", body.Kind)
	}

	// Phone switches networks: a new mobile session on the same pair+role
	// supersedes mobile1 (close 4001).
	mobile2, err := h.dial(t, ctx, h.mint(t, "pair_RC", "dev_m2", token.RoleMobile))
	if err != nil {
		t.Fatalf("mobile2 dial: %v", err)
	}
	defer mobile2.Close()
	if code, _ := mobile1.WaitClose(ctx); code != 4001 {
		t.Fatalf("superseded mobile1 close code = %d, want 4001", code)
	}

	// Let mobile1's deferred deregister run; in the buggy version it enqueues a
	// spurious peer_offline to the desktop, which would then sit ahead of the
	// sentinel msg below in the desktop's FIFO write queue.
	time.Sleep(250 * time.Millisecond)

	// Drive a sentinel msg from the new mobile and read the desktop's frames in
	// order until it arrives. Before the sentinel the desktop must have seen
	// mobile2's peer_online and must NOT have received a peer_offline (which would
	// leave its link status stuck DOWN). Reading on the long-lived ctx avoids
	// cancelling the read (which would close the desktop socket).
	payloadMD := []byte("md-after-reconnect")
	if err := mobile2.SendMsg(ctx, "id-md", payloadMD); err != nil {
		t.Fatal(err)
	}
	sawOnline := false
	for {
		env, err := desktop.Recv(ctx)
		if err != nil {
			t.Fatalf("desktop recv after reconnect: %v", err)
		}
		switch env.Type {
		case protocol.TypeSys:
			var b protocol.System
			if err := jsonUnmarshal(env.Payload, &b); err != nil {
				t.Fatal(err)
			}
			switch b.Kind {
			case protocol.SysPeerOffline:
				t.Fatal("desktop got spurious peer_offline after phone reconnect (status would be stuck DOWN)")
			case protocol.SysPeerOnline:
				sawOnline = true
			}
		case protocol.TypeMsg:
			if dec, _ := decodePayload(env); !bytes.Equal(dec, payloadMD) {
				t.Errorf("mobile->desktop payload mismatch: got %q want %q", dec, payloadMD)
			}
			if !sawOnline {
				t.Fatal("desktop did not get peer_online after phone reconnect")
			}
			// Reverse direction sanity: desktop -> mobile2 still routes.
			payloadDM := []byte("dm-after-reconnect")
			if err := desktop.SendMsg(ctx, "id-dm", payloadDM); err != nil {
				t.Fatal(err)
			}
			rev, err := mobile2.RecvType(ctx, protocol.TypeMsg)
			if err != nil {
				t.Fatalf("mobile2 recv after reconnect: %v", err)
			}
			if dec, _ := decodePayload(rev); !bytes.Equal(dec, payloadDM) {
				t.Errorf("desktop->mobile payload mismatch: got %q want %q", dec, payloadDM)
			}
			return
		}
	}
}
