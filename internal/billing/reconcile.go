package billing

import (
	"context"
	"fmt"

	"github.com/context-solutions-inc/secure-gateway/internal/logging"
)

// Reconcile re-reads every subscription from the Stripe API and heals the local
// mirror, recovering from any missed or out-of-order webhooks (PRD §6.4, Risk
// 4). It is safe to run repeatedly and is intended for a nightly ticker; it is
// also invoked directly by tests.
func (p *Processor) Reconcile(ctx context.Context) error {
	subs, err := p.api.ListSubscriptions(ctx)
	if err != nil {
		return fmt.Errorf("reconcile list subscriptions: %w", err)
	}
	var firstErr error
	healed := 0
	for _, sub := range subs {
		accountID, err := p.resolveAccount(ctx, customerIDOf(sub.Customer))
		if err != nil {
			p.log.Error("reconcile: resolve account", "subscription_id", sub.ID, logging.FieldReason, err.Error())
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err := p.syncSubscription(ctx, sub, accountID); err != nil {
			p.log.Error("reconcile: sync subscription", "subscription_id", sub.ID, logging.FieldReason, err.Error())
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		healed++
	}
	p.log.Info("reconciliation complete", "subscriptions", len(subs), "synced", healed)
	return firstErr
}
