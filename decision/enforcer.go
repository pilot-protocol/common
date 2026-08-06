// SPDX-License-Identifier: AGPL-3.0-or-later

package decision

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"time"
)

// TrustStore resolves keys within an explicit tenant scope and supplies the
// minimum state an enforcement point is willing to accept.
type TrustStore interface {
	IntentKey(ctx context.Context, tenantID, agentID, keyID string) (ed25519.PublicKey, error)
	DecisionKey(ctx context.Context, tenantID, keyID string) (ed25519.PublicKey, error)
	MinimumState(ctx context.Context, tenantID string) (policyRevision, revocationEpoch uint64, err error)
}

// AuthorityCeiling checks the tenant's local mandate and deterministic policy.
// A provider decision is usable only when this local ceiling also permits it.
type AuthorityCeiling interface {
	Check(ctx context.Context, intent Intent, decision Decision) error
}

// DisclosureCeiling is the strict local policy extension used when an Intent
// binds a DisclosureBinding. A receiver must not accept typed metadata using a
// ceiling that can only inspect the legacy Intent fields, because that would
// silently drop label, content-type, recipient, purpose, or residency rules.
type DisclosureCeiling interface {
	CheckDisclosure(ctx context.Context, intent Intent, result Decision, disclosure DisclosureBinding) error
}

// Enforcer performs the complete provider-independent authorization sequence.
// It intentionally has no billing dependency.
type Enforcer struct {
	Provider Authorizer
	Trust    TrustStore
	Ceiling  AuthorityCeiling
	Now      func() time.Time
}

func (e *Enforcer) Authorize(ctx context.Context, intent Intent) (Decision, error) {
	if e == nil || e.Provider == nil || e.Trust == nil || e.Ceiling == nil {
		return Decision{}, fmt.Errorf("decision: enforcer is missing provider, trust store, or local ceiling")
	}
	result, err := e.Provider.Authorize(ctx, intent)
	if err != nil {
		return Decision{}, fmt.Errorf("decision: provider unavailable or refused request: %w", err)
	}
	if err := e.Verify(ctx, intent, result); err != nil {
		return Decision{}, err
	}
	return result, nil
}

// AuthorizeDisclosure requests and locally verifies a Decision for a
// disclosure-bound Intent. Both the provider and local ceiling must opt in to
// the explicit disclosure interfaces; falling back to legacy authorization is
// unsafe because it would ignore typed policy inputs.
func (e *Enforcer) AuthorizeDisclosure(ctx context.Context, intent Intent, disclosure DisclosureBinding) (Decision, error) {
	if e == nil || e.Provider == nil || e.Trust == nil || e.Ceiling == nil {
		return Decision{}, fmt.Errorf("decision: enforcer is missing provider, trust store, or local ceiling")
	}
	if err := disclosure.VerifyIntent(intent); err != nil {
		return Decision{}, err
	}
	provider, supported := e.Provider.(DisclosureAuthorizer)
	if !supported {
		return Decision{}, fmt.Errorf("decision: provider does not support disclosure binding")
	}
	result, err := provider.AuthorizeDisclosure(ctx, intent, disclosure)
	if err != nil {
		return Decision{}, fmt.Errorf("decision: provider unavailable or refused request: %w", err)
	}
	if err := e.VerifyDisclosure(ctx, intent, result, disclosure); err != nil {
		return Decision{}, err
	}
	return result, nil
}

// Verify applies the local trust, freshness, state-floor, and deterministic
// ceiling checks to a signed decision obtained through a non-standard path,
// such as a completed long-running approval workflow. The caller remains
// responsible for obtaining the decision and for resource-side idempotency.
func (e *Enforcer) Verify(ctx context.Context, intent Intent, result Decision) error {
	return e.verify(ctx, intent, result, nil)
}

// VerifyDisclosure applies the normal signed decision checks and an explicit
// disclosure-aware local ceiling. It rejects a legacy ceiling rather than
// treating its non-disclosure check as evidence that a typed rule was applied.
func (e *Enforcer) VerifyDisclosure(ctx context.Context, intent Intent, result Decision, disclosure DisclosureBinding) error {
	if err := disclosure.VerifyIntent(intent); err != nil {
		return err
	}
	return e.verify(ctx, intent, result, &disclosure)
}

func (e *Enforcer) verify(ctx context.Context, intent Intent, result Decision, disclosure *DisclosureBinding) error {
	if e == nil || e.Trust == nil || e.Ceiling == nil {
		return fmt.Errorf("decision: enforcer is missing trust store or local ceiling")
	}
	now := time.Now()
	if e.Now != nil {
		now = e.Now()
	}
	intentKey, err := e.Trust.IntentKey(ctx, intent.TenantID, intent.AgentID, intent.KeyID)
	if err != nil {
		return fmt.Errorf("decision: resolve intent key: %w", err)
	}
	if err := intent.Verify(intentKey, now); err != nil {
		return err
	}
	decisionKey, err := e.Trust.DecisionKey(ctx, intent.TenantID, result.KeyID)
	if err != nil {
		return fmt.Errorf("decision: resolve decision key: %w", err)
	}
	if err := result.VerifyFor(intent, decisionKey, now); err != nil {
		return err
	}
	minimumPolicy, minimumRevocation, err := e.Trust.MinimumState(ctx, intent.TenantID)
	if err != nil {
		return fmt.Errorf("decision: resolve minimum authority state: %w", err)
	}
	if result.PolicyRevision < minimumPolicy {
		return fmt.Errorf("decision: stale policy revision %d, require at least %d", result.PolicyRevision, minimumPolicy)
	}
	if result.RevocationEpoch < minimumRevocation {
		return fmt.Errorf("decision: stale revocation epoch %d, require at least %d", result.RevocationEpoch, minimumRevocation)
	}
	if disclosure != nil {
		ceiling, supported := e.Ceiling.(DisclosureCeiling)
		if !supported {
			return fmt.Errorf("decision: local authority ceiling does not support disclosure binding")
		}
		if err := ceiling.CheckDisclosure(ctx, intent, result, *disclosure); err != nil {
			return fmt.Errorf("decision: local authority ceiling: %w", err)
		}
		return nil
	}
	if err := e.Ceiling.Check(ctx, intent, result); err != nil {
		return fmt.Errorf("decision: local authority ceiling: %w", err)
	}
	return nil
}
