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

	"github.com/context-solutions-inc/secure-gateway/internal/billing"
)

// API is an in-memory billing.StripeAPI.
type API struct {
	mu       sync.RWMutex
	subs     map[string]*stripe.Subscription
	sessions []FakeSession // checkout sessions created, in order
}

// FakeSession records a checkout session created via CreateCheckoutSession so a
// test can assert on it and build the matching webhook event.
type FakeSession struct {
	ID         string
	PriceID    string
	SuccessURL string
	CancelURL  string
	Metadata   map[string]string
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

func (a *API) CreateCheckoutSession(_ context.Context, p billing.CheckoutSessionParams) (string, string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	sessionID := "cs_" + randHex(8)
	md := map[string]string{}
	for k, v := range p.Metadata {
		md[k] = v
	}
	a.sessions = append(a.sessions, FakeSession{
		ID: sessionID, PriceID: p.PriceID, SuccessURL: p.SuccessURL, CancelURL: p.CancelURL, Metadata: md,
	})
	return "https://checkout.stripe.test/" + sessionID, sessionID, nil
}

func (a *API) CreateBillingPortalSession(_ context.Context, customerID, _ string) (string, error) {
	return "https://billing.stripe.test/portal/" + customerID, nil
}

// Sessions returns the checkout sessions created so far (test assertions).
func (a *API) Sessions() []FakeSession {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]FakeSession, len(a.sessions))
	copy(out, a.sessions)
	return out
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
	return w.EventWithAPIVersion(eventType, object, stripe.APIVersion)
}

// EventWithAPIVersion is like Event but stamps an explicit api_version, so tests
// can simulate a live Stripe account whose API version differs from stripe-go's
// pinned stripe.APIVersion (the version-mismatch regression).
func (w *Webhook) EventWithAPIVersion(eventType stripe.EventType, object json.RawMessage, apiVersion string) (body []byte, sigHeader string) {
	ev := map[string]any{
		"id":          "evt_" + randHex(8),
		"object":      "event",
		"type":        string(eventType),
		"api_version": apiVersion,
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

// CheckoutCompletedWithNonce is like CheckoutCompletedObject but carries a nonce
// in session metadata, as the desktop onboarding flow does (accountID is left to
// the webhook to mint, so client_reference_id is empty).
func CheckoutCompletedWithNonce(sessionID, customerID, subID, nonce string) json.RawMessage {
	return mustJSON(map[string]any{
		"id":           sessionID,
		"object":       "checkout.session",
		"customer":     customerID,
		"subscription": subID,
		"mode":         "subscription",
		"metadata":     map[string]string{"nonce": nonce},
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
