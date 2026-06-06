package billing

import (
	"encoding/json"
	"fmt"
	"time"

	stripe "github.com/stripe/stripe-go/v82"

	"github.com/lley154/secure-gateway/internal/license"
)

// customerIDOf returns the customer id from a (possibly id-only) Customer.
func customerIDOf(c *stripe.Customer) string {
	if c == nil {
		return ""
	}
	return c.ID
}

// subscriptionIDOf returns the subscription id from a (possibly id-only)
// Subscription pointer.
func subscriptionIDOf(s *stripe.Subscription) string {
	if s == nil {
		return ""
	}
	return s.ID
}

// maxPairsFor resolves the entitlement count from price metadata (preferred) or
// subscription metadata (PRD §6.1).
func maxPairsFor(sub *stripe.Subscription) int {
	if sub.Items != nil {
		for _, it := range sub.Items.Data {
			if it != nil && it.Price != nil && it.Price.Metadata != nil {
				if _, ok := it.Price.Metadata["max_pairs"]; ok {
					return license.MaxPairs(it.Price.Metadata)
				}
			}
		}
	}
	return license.MaxPairs(sub.Metadata)
}

// currentPeriodEnd reads the period end from the first subscription item (in
// recent Stripe API versions the period lives on items, not the subscription).
func currentPeriodEnd(sub *stripe.Subscription) time.Time {
	if sub.Items != nil {
		for _, it := range sub.Items.Data {
			if it != nil && it.CurrentPeriodEnd > 0 {
				return time.Unix(it.CurrentPeriodEnd, 0).UTC()
			}
		}
	}
	return time.Time{}
}

// firstItemID returns the first subscription item id, used to bind a license to
// a subscription item (PRD §6.1).
func firstItemID(sub *stripe.Subscription) string {
	if sub.Items != nil {
		for _, it := range sub.Items.Data {
			if it != nil && it.ID != "" {
				return it.ID
			}
		}
	}
	return ""
}

// invoiceSubscriptionID extracts the subscription id an invoice event belongs
// to, via invoice.parent.subscription_details.subscription.
func invoiceSubscriptionID(ev stripe.Event) (string, error) {
	var inv stripe.Invoice
	if err := json.Unmarshal(ev.Data.Raw, &inv); err != nil {
		return "", fmt.Errorf("parse invoice: %w", err)
	}
	if inv.Parent == nil || inv.Parent.SubscriptionDetails == nil || inv.Parent.SubscriptionDetails.Subscription == nil {
		return "", fmt.Errorf("invoice %s has no subscription parent", inv.ID)
	}
	id := inv.Parent.SubscriptionDetails.Subscription.ID
	if id == "" {
		return "", fmt.Errorf("invoice %s subscription id empty", inv.ID)
	}
	return id, nil
}
