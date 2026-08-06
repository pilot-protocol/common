// SPDX-License-Identifier: AGPL-3.0-or-later

package decision

import (
	"context"
	"fmt"
	"time"
)

// StaticMandateStore holds a reviewed snapshot of signed mandates. It is
// deliberately immutable: configuration reloads replace the complete store,
// while every enforcement check still revalidates the mandate against current
// trust and revocation state through MandateCeiling.
type StaticMandateStore struct {
	mandates map[string]Mandate
}

// NewStaticMandateStore verifies a tenant-scoped mandate snapshot before it
// can be attached to an enforcement point. An empty snapshot is rejected so a
// configuration that claims to require delegation cannot silently become
// permissive.
func NewStaticMandateStore(ctx context.Context, tenantID string, mandates []Mandate, keys MandateKeyResolver, state MandateStateResolver, now time.Time) (*StaticMandateStore, error) {
	if err := validateIdentifier("tenant_id", tenantID); err != nil {
		return nil, err
	}
	if len(mandates) == 0 {
		return nil, fmt.Errorf("decision: at least one mandate is required")
	}
	if keys == nil || state == nil {
		return nil, fmt.Errorf("decision: mandate key and state resolvers are required")
	}
	if now.IsZero() {
		now = time.Now()
	}
	_, revocationEpoch, err := state.MinimumState(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("decision: resolve mandate state: %w", err)
	}
	store := &StaticMandateStore{mandates: make(map[string]Mandate, len(mandates))}
	for _, mandate := range mandates {
		if mandate.TenantID != tenantID {
			return nil, fmt.Errorf("decision: mandate %q has a different tenant", mandate.ID)
		}
		if mandate.RevocationEpoch < revocationEpoch {
			return nil, fmt.Errorf("decision: mandate %q is below the active revocation epoch", mandate.ID)
		}
		issuer, keyErr := keys.MandateKey(ctx, tenantID, mandate.KeyID)
		if keyErr != nil {
			return nil, fmt.Errorf("decision: resolve mandate %q issuer: %w", mandate.ID, keyErr)
		}
		if verifyErr := mandate.Verify(issuer, now); verifyErr != nil {
			return nil, fmt.Errorf("decision: verify mandate %q: %w", mandate.ID, verifyErr)
		}
		if _, exists := store.mandates[mandate.ID]; exists {
			return nil, fmt.Errorf("decision: duplicate mandate %q", mandate.ID)
		}
		store.mandates[mandate.ID] = cloneMandate(mandate)
	}
	return store, nil
}

// NewStaticMandateStoreFromBundle verifies a complete signed distribution
// snapshot before exposing its mandates to an enforcement point. Empty bundles
// are valid and intentionally create an empty, fail-closed delegation set.
func NewStaticMandateStoreFromBundle(ctx context.Context, bundle MandateBundle, keys MandateKeyResolver, state MandateStateResolver, now time.Time) (*StaticMandateStore, error) {
	if keys == nil || state == nil {
		return nil, fmt.Errorf("decision: mandate key and state resolvers are required")
	}
	if now.IsZero() {
		now = time.Now()
	}
	bundleKey, err := keys.MandateKey(ctx, bundle.TenantID, bundle.KeyID)
	if err != nil {
		return nil, fmt.Errorf("decision: resolve mandate bundle issuer: %w", err)
	}
	if err := bundle.Verify(ctx, bundleKey, keys, now); err != nil {
		return nil, err
	}
	_, revocationEpoch, err := state.MinimumState(ctx, bundle.TenantID)
	if err != nil {
		return nil, fmt.Errorf("decision: resolve mandate state: %w", err)
	}
	if bundle.RevocationEpoch < revocationEpoch {
		return nil, fmt.Errorf("decision: mandate bundle revocation epoch %d is stale", bundle.RevocationEpoch)
	}
	store := &StaticMandateStore{mandates: make(map[string]Mandate, len(bundle.Mandates))}
	for _, mandate := range bundle.Mandates {
		store.mandates[mandate.ID] = cloneMandate(mandate)
	}
	return store, nil
}

// Mandate returns an independent copy so a caller cannot alter the retained
// signed delegation between checks.
func (store *StaticMandateStore) Mandate(_ context.Context, tenantID, mandateID string) (Mandate, error) {
	if store == nil {
		return Mandate{}, fmt.Errorf("decision: mandate store is not initialized")
	}
	mandate, found := store.mandates[mandateID]
	if !found || mandate.TenantID != tenantID {
		return Mandate{}, fmt.Errorf("decision: mandate %q is not available", mandateID)
	}
	return cloneMandate(mandate), nil
}

func cloneMandate(mandate Mandate) Mandate {
	mandate.Actions = append([]string(nil), mandate.Actions...)
	mandate.ResourcePrefixes = append([]string(nil), mandate.ResourcePrefixes...)
	mandate.Constraints = append([]Constraint(nil), mandate.Constraints...)
	return mandate
}
