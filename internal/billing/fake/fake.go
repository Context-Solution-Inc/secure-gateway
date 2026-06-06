// Package fake provides a hermetic Stripe test double: an in-memory StripeAPI
// for reconciliation and a webhook builder that signs synthetic events with the
// test secret (using stripe-go's real signature scheme and API version). It lets
// the full subscription lifecycle run as an automated test with no network.
package fake

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	stripe "github.com/stripe/stripe-go/v82"
	"github.com/stripe/stripe-go/v82/webhook"
)

// API is an in-memory billing.StripeAPI.
type API struct {
	mu   sync.RWMutex
	subs map[string]*stripe.Subscription
}

// NewAPI returns an empty fake Stripe API.
func NewAPI() *API { return &API{subs: map[string]*stripe.Subscription{}} }

// Set stores (or replaces) a subscription so GetSubscription/ListSubscriptions
// return it. Used to seed reconciliation and the checkout fetch.
func (a *API) Set(sub *stripe.Subscription) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.subs[sub.ID] = sub
}

func (a *API) GetSubscription(_ context.Context, id string) (*stripe.Subscription, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	sub, ok := a.subs[id]
	if !ok {
		return nil, fmt.Errorf("fake: subscription %s not found", id)
	}
	return sub, nil
}

func (a *API) ListSubscriptions(_ context.Context) ([]*stripe.Subscription, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]*stripe.Subscription, 0, len(a.subs))
	for _, s := range a.subs {
		out = append(out, s)
	}
	return out, nil
}

// Webhook builds signed webhook request bodies + signature headers.
type Webhook struct {
	secret string
	now    func() time.Time
}

// NewWebhook returns a webhook builder for the given signing secret.
func NewWebhook(secret string) *Webhook {
	return &Webhook{secret: secret, now: time.Now}
}

// Event marshals a Stripe event of the given type wrapping object, and returns
// the raw body plus a valid Stripe-Signature header. The event's api_version is
// stamped to the SDK's expected version so webhook.ConstructEvent accepts it.
func (w *Webhook) Event(eventType stripe.EventType, object json.RawMessage) (body []byte, sigHeader string) {
	ev := map[string]any{
		"id":          "evt_" + randHex(8),
		"object":      "event",
		"type":        string(eventType),
		"api_version": stripe.APIVersion,
		"created":     w.now().Unix(),
		"data":        map[string]any{"object": object},
	}
	body, err := json.Marshal(ev)
	if err != nil {
		panic("fake: marshal event: " + err.Error())
	}
	t := w.now()
	sig := webhook.ComputeSignature(t, body, w.secret)
	sigHeader = fmt.Sprintf("t=%d,v1=%s", t.Unix(), hex.EncodeToString(sig))
	return body, sigHeader
}

// --- Object builders ---

// Subscription builds a subscription with one item carrying max_pairs price
// metadata and a 30-day period end, suitable for both the fake API and as a
// webhook event object.
func Subscription(id, customerID string, status stripe.SubscriptionStatus, maxPairs int) *stripe.Subscription {
	return &stripe.Subscription{
		ID:       id,
		Customer: &stripe.Customer{ID: customerID},
		Status:   status,
		Items: &stripe.SubscriptionItemList{
			Data: []*stripe.SubscriptionItem{{
				ID:               id + "_si",
				CurrentPeriodEnd: time.Now().Add(30 * 24 * time.Hour).Unix(),
				Price: &stripe.Price{
					ID:       "price_test",
					Metadata: map[string]string{"max_pairs": fmt.Sprintf("%d", maxPairs)},
				},
			}},
		},
	}
}

// MarshalSubscription renders a subscription as a webhook event object.
func MarshalSubscription(sub *stripe.Subscription) json.RawMessage {
	b, err := json.Marshal(sub)
	if err != nil {
		panic("fake: marshal subscription: " + err.Error())
	}
	return b
}

// CheckoutCompletedObject builds a checkout.session.completed data object. The
// customer and subscription are emitted as id strings (as Stripe sends them);
// account is carried in client_reference_id.
func CheckoutCompletedObject(sessionID, customerID, accountID, subID string) json.RawMessage {
	return mustJSON(map[string]any{
		"id":                  sessionID,
		"object":              "checkout.session",
		"customer":            customerID,
		"client_reference_id": accountID,
		"subscription":        subID,
		"mode":                "subscription",
	})
}

// InvoiceObject builds an invoice data object linked to subID via
// parent.subscription_details.subscription.
func InvoiceObject(invID, subID string) json.RawMessage {
	return mustJSON(map[string]any{
		"id":     invID,
		"object": "invoice",
		"parent": map[string]any{
			"type": "subscription_details",
			"subscription_details": map[string]any{
				"subscription": subID,
			},
		},
	})
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic("fake: marshal: " + err.Error())
	}
	return b
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
