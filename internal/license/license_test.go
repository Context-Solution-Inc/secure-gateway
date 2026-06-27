package license_test

import (
	"strings"
	"testing"
	"time"

	"github.com/context-solutions-inc/secure-gateway/internal/authstore"
	"github.com/context-solutions-inc/secure-gateway/internal/license"
)

func TestEvaluate(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name   string
		status authstore.SubStatus
		grace  time.Time
		want   license.Behavior
	}{
		{"trialing", authstore.SubTrialing, time.Time{}, license.Valid},
		{"active", authstore.SubActive, time.Time{}, license.Valid},
		{"past_due in grace", authstore.SubPastDue, now.Add(time.Hour), license.Grace},
		{"past_due grace just-began", authstore.SubPastDue, time.Time{}, license.Grace},
		{"past_due grace expired", authstore.SubPastDue, now.Add(-time.Hour), license.Revoked},
		{"paused", authstore.SubPaused, time.Time{}, license.Suspended},
		{"canceled", authstore.SubCanceled, time.Time{}, license.Revoked},
		{"unpaid", authstore.SubUnpaid, time.Time{}, license.Revoked},
		{"incomplete_expired", authstore.SubIncompleteExpired, time.Time{}, license.Revoked},
		{"unknown fails closed", authstore.SubStatus("weird"), time.Time{}, license.Revoked},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := license.Evaluate(authstore.Subscription{Status: c.status, GraceUntil: c.grace}, now)
			if got != c.want {
				t.Fatalf("Evaluate(%s)=%v want %v", c.status, got, c.want)
			}
		})
	}
}

func TestIssuableEnforced(t *testing.T) {
	if !license.Issuable(license.Valid) || !license.Issuable(license.Grace) {
		t.Fatal("Valid and Grace must be issuable")
	}
	if license.Issuable(license.Revoked) || license.Issuable(license.Suspended) {
		t.Fatal("Revoked/Suspended must not be issuable")
	}
	if !license.Enforced(license.Revoked) || !license.Enforced(license.Suspended) {
		t.Fatal("Revoked/Suspended must be enforced")
	}
	if license.Enforced(license.Valid) || license.Enforced(license.Grace) {
		t.Fatal("Valid/Grace must not trigger enforcement")
	}
}

func TestMaxPairs(t *testing.T) {
	cases := []struct {
		md   map[string]string
		want int
	}{
		{nil, 1},
		{map[string]string{}, 1},
		{map[string]string{"max_pairs": "3"}, 3},
		{map[string]string{"max_pairs": " 2 "}, 2},
		{map[string]string{"max_pairs": "0"}, 1},
		{map[string]string{"max_pairs": "-5"}, 1},
		{map[string]string{"max_pairs": "abc"}, 1},
	}
	for _, c := range cases {
		if got := license.MaxPairs(c.md); got != c.want {
			t.Fatalf("MaxPairs(%v)=%d want %d", c.md, got, c.want)
		}
	}
}

func TestNewKey(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		k := license.NewKey()
		if !strings.HasPrefix(k, "lic_") {
			t.Fatalf("missing prefix: %q", k)
		}
		if seen[k] {
			t.Fatalf("duplicate key generated: %q", k)
		}
		seen[k] = true
	}
}
