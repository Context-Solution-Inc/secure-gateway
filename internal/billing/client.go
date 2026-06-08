// Package billing integrates Stripe with the Auth & License Service: it verifies
// and processes webhooks (PRD §6.4), derives license behavior from subscription
// state, publishes revocations for cutoffs (§6.5), and reconciles the local
// mirror against the Stripe API (Risk 4). The relay has no Stripe dependency;
// all Stripe code lives here.
package billing

import (
	"context"

	stripe "github.com/stripe/stripe-go/v82"
	"github.com/stripe/stripe-go/v82/client"
)

// CheckoutSessionParams is the input to CreateCheckoutSession. The desktop
// onboarding flow embeds a client-generated nonce in Metadata so the webhook can
// bind the resulting account/license/subscription back to the waiting desktop.
type CheckoutSessionParams struct {
	PriceID    string
	SuccessURL string
	CancelURL  string
	Metadata   map[string]string
}

// StripeAPI is the narrow outbound Stripe surface the service needs (the nightly
// reconciliation job and desktop checkout onboarding). It is an interface so
// tests can substitute a fake and run the whole lifecycle hermetically
// (billing/fake).
type StripeAPI interface {
	// GetSubscription fetches a single subscription with items+prices expanded.
	GetSubscription(ctx context.Context, id string) (*stripe.Subscription, error)
	// ListSubscriptions returns all subscriptions (items+prices expanded),
	// for reconciliation.
	ListSubscriptions(ctx context.Context) ([]*stripe.Subscription, error)
	// CreateCheckoutSession creates a subscription-mode Stripe Checkout Session
	// and returns its hosted URL and session id.
	CreateCheckoutSession(ctx context.Context, p CheckoutSessionParams) (url, sessionID string, err error)
}

// RealAPI is the production StripeAPI backed by stripe-go.
type RealAPI struct {
	sc *client.API
}

// NewRealAPI builds a RealAPI from a Stripe secret key.
func NewRealAPI(secretKey string) *RealAPI {
	sc := &client.API{}
	sc.Init(secretKey, nil)
	return &RealAPI{sc: sc}
}

const expandItemsPrice = "data.items.data.price"

func (a *RealAPI) GetSubscription(ctx context.Context, id string) (*stripe.Subscription, error) {
	params := &stripe.SubscriptionParams{}
	params.Context = ctx
	params.AddExpand("items.data.price")
	return a.sc.Subscriptions.Get(id, params)
}

func (a *RealAPI) ListSubscriptions(ctx context.Context) ([]*stripe.Subscription, error) {
	params := &stripe.SubscriptionListParams{}
	params.Context = ctx
	params.AddExpand(expandItemsPrice)
	params.Status = stripe.String("all")
	it := a.sc.Subscriptions.List(params)
	var out []*stripe.Subscription
	for it.Next() {
		out = append(out, it.Subscription())
	}
	if err := it.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (a *RealAPI) CreateCheckoutSession(ctx context.Context, p CheckoutSessionParams) (string, string, error) {
	params := &stripe.CheckoutSessionParams{
		Mode:       stripe.String(string(stripe.CheckoutSessionModeSubscription)),
		SuccessURL: stripe.String(p.SuccessURL),
		CancelURL:  stripe.String(p.CancelURL),
		LineItems: []*stripe.CheckoutSessionLineItemParams{{
			Price:    stripe.String(p.PriceID),
			Quantity: stripe.Int64(1),
		}},
	}
	params.Context = ctx
	for k, v := range p.Metadata {
		params.AddMetadata(k, v)
	}
	sess, err := a.sc.CheckoutSessions.New(params)
	if err != nil {
		return "", "", err
	}
	return sess.URL, sess.ID, nil
}
