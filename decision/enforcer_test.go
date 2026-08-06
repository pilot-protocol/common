// SPDX-License-Identifier: AGPL-3.0-or-later

package decision

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"
)

type authorizerFunc func(context.Context, Intent) (Decision, error)

func (f authorizerFunc) Authorize(ctx context.Context, intent Intent) (Decision, error) {
	return f(ctx, intent)
}

type testTrustStore struct {
	intentKey       ed25519.PublicKey
	decisionKey     ed25519.PublicKey
	policyRevision  uint64
	revocationEpoch uint64
}

func (s testTrustStore) IntentKey(_ context.Context, _, _, _ string) (ed25519.PublicKey, error) {
	return s.intentKey, nil
}
func (s testTrustStore) DecisionKey(_ context.Context, _, _ string) (ed25519.PublicKey, error) {
	return s.decisionKey, nil
}
func (s testTrustStore) MinimumState(_ context.Context, _ string) (uint64, uint64, error) {
	return s.policyRevision, s.revocationEpoch, nil
}

type ceilingFunc func(context.Context, Intent, Decision) error

func (f ceilingFunc) Check(ctx context.Context, intent Intent, result Decision) error {
	return f(ctx, intent, result)
}

type disclosureCeilingFunc func(context.Context, Intent, Decision, DisclosureBinding) error

func (ceiling disclosureCeilingFunc) Check(context.Context, Intent, Decision) error {
	return errors.New("plain ceiling method should not be used")
}

func (ceiling disclosureCeilingFunc) CheckDisclosure(ctx context.Context, intent Intent, result Decision, disclosure DisclosureBinding) error {
	return ceiling(ctx, intent, result, disclosure)
}

func TestEnforcerVerifiesBothSignaturesStateAndLocalCeiling(t *testing.T) {
	t.Parallel()
	intentPublic, intentPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	decisionPublic, decisionPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1785500000, 0)
	intent := testIntent(t, now)
	if err := intent.Sign(intentPrivate); err != nil {
		t.Fatal(err)
	}
	intentHash, err := intent.Hash()
	if err != nil {
		t.Fatal(err)
	}
	result := Decision{
		Version: SchemaVersion, ID: "decision-enforcer", IntentHash: intentHash,
		TenantID: intent.TenantID, AgentID: intent.AgentID, Outcome: Allow,
		PolicyRevision: 8, RevocationEpoch: 5, ProviderID: "managed",
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(), KeyID: "issuer-key-1",
	}
	if err := result.Sign(decisionPrivate); err != nil {
		t.Fatal(err)
	}
	ceilingCalled := false
	enforcer := Enforcer{
		Provider: authorizerFunc(func(context.Context, Intent) (Decision, error) { return result, nil }),
		Trust: testTrustStore{
			intentKey: intentPublic, decisionKey: decisionPublic, policyRevision: 8, revocationEpoch: 5,
		},
		Ceiling: ceilingFunc(func(context.Context, Intent, Decision) error {
			ceilingCalled = true
			return nil
		}),
		Now: func() time.Time { return now },
	}
	if _, err := enforcer.Authorize(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	if !ceilingCalled {
		t.Fatal("local authority ceiling was not consulted")
	}
}

func TestEnforcerDisclosureVerificationRequiresDisclosureAwareCeiling(t *testing.T) {
	intentPublic, intentPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	decisionPublic, decisionPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1785500000, 0)
	disclosure := DisclosureBinding{
		Version: DisclosureBindingVersion, ContentHash: HashPayload([]byte("invoice")), DeclaredBytes: 7,
		ContentType: "application/pdf", Labels: []string{"finance", "pii"}, Recipient: "agent:finance",
		Purpose: "invoice-payment", Residency: "eu-west-1", Filename: "invoice.pdf",
	}
	disclosureHash, err := disclosure.Hash()
	if err != nil {
		t.Fatal(err)
	}
	intent := testIntent(t, now)
	intent.Audience, intent.Purpose, intent.PayloadHash = disclosure.Recipient, disclosure.Purpose, disclosureHash
	if err := intent.Sign(intentPrivate); err != nil {
		t.Fatal(err)
	}
	intentHash, err := intent.Hash()
	if err != nil {
		t.Fatal(err)
	}
	result := Decision{
		Version: SchemaVersion, ID: "disclosure-decision", IntentHash: intentHash, TenantID: intent.TenantID, AgentID: intent.AgentID,
		Outcome: Allow, PolicyRevision: 8, RevocationEpoch: 5, ProviderID: "managed", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(), KeyID: "issuer-key-1",
	}
	if err := result.Sign(decisionPrivate); err != nil {
		t.Fatal(err)
	}
	trust := testTrustStore{intentKey: intentPublic, decisionKey: decisionPublic, policyRevision: 8, revocationEpoch: 5}
	legacy := Enforcer{Trust: trust, Ceiling: ceilingFunc(func(context.Context, Intent, Decision) error { return nil }), Now: func() time.Time { return now }}
	if err := legacy.VerifyDisclosure(context.Background(), intent, result, disclosure); err == nil || !strings.Contains(err.Error(), "does not support disclosure") {
		t.Fatalf("legacy ceiling accepted disclosure: %v", err)
	}
	called := false
	aware := Enforcer{Trust: trust, Ceiling: disclosureCeilingFunc(func(_ context.Context, got Intent, gotResult Decision, gotDisclosure DisclosureBinding) error {
		called = true
		if got.ID != intent.ID || gotResult.ID != result.ID || gotDisclosure.Residency != disclosure.Residency {
			t.Fatalf("disclosure ceiling inputs intent=%+v result=%+v disclosure=%+v", got, gotResult, gotDisclosure)
		}
		return nil
	}), Now: func() time.Time { return now }}
	if err := aware.VerifyDisclosure(context.Background(), intent, result, disclosure); err != nil || !called {
		t.Fatalf("disclosure ceiling err=%v called=%t", err, called)
	}
}

func TestEnforcerFailsClosedOnProviderCeilingAndStaleState(t *testing.T) {
	t.Parallel()
	intentPublic, intentPrivate, _ := ed25519.GenerateKey(rand.Reader)
	decisionPublic, decisionPrivate, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(1785500000, 0)
	intent := testIntent(t, now)
	if err := intent.Sign(intentPrivate); err != nil {
		t.Fatal(err)
	}
	intentHash, _ := intent.Hash()
	result := Decision{
		Version: SchemaVersion, ID: "decision-stale", IntentHash: intentHash,
		TenantID: intent.TenantID, AgentID: intent.AgentID, Outcome: Allow,
		PolicyRevision: 4, RevocationEpoch: 2, ProviderID: "managed",
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(), KeyID: "issuer-key-1",
	}
	if err := result.Sign(decisionPrivate); err != nil {
		t.Fatal(err)
	}

	base := Enforcer{
		Provider: authorizerFunc(func(context.Context, Intent) (Decision, error) { return result, nil }),
		Trust: testTrustStore{
			intentKey: intentPublic, decisionKey: decisionPublic, policyRevision: 5, revocationEpoch: 2,
		},
		Ceiling: ceilingFunc(func(context.Context, Intent, Decision) error { return nil }),
		Now:     func() time.Time { return now },
	}
	if _, err := base.Authorize(context.Background(), intent); err == nil || !strings.Contains(err.Error(), "stale policy") {
		t.Fatalf("stale state error = %v", err)
	}

	base.Trust = testTrustStore{intentKey: intentPublic, decisionKey: decisionPublic}
	base.Ceiling = ceilingFunc(func(context.Context, Intent, Decision) error { return errors.New("mandate exceeded") })
	if _, err := base.Authorize(context.Background(), intent); err == nil || !strings.Contains(err.Error(), "mandate exceeded") {
		t.Fatalf("ceiling error = %v", err)
	}

	base.Provider = authorizerFunc(func(context.Context, Intent) (Decision, error) { return Decision{}, errors.New("offline") })
	if got, err := base.Authorize(context.Background(), intent); err == nil || got.Outcome == Allow {
		t.Fatalf("provider outage returned %+v, err=%v", got, err)
	}
}

func TestEnforcerVerifiesExternalWorkflowDecisionWithoutCallingProvider(t *testing.T) {
	t.Parallel()
	intentPublic, intentPrivate, _ := ed25519.GenerateKey(rand.Reader)
	decisionPublic, decisionPrivate, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(1785500000, 0)
	intent := testIntent(t, now)
	if err := intent.Sign(intentPrivate); err != nil {
		t.Fatal(err)
	}
	intentHash, _ := intent.Hash()
	result := Decision{
		Version: SchemaVersion, ID: "workflow-external", IntentHash: intentHash, TenantID: intent.TenantID, AgentID: intent.AgentID,
		Outcome: Constrain, Constraints: []Constraint{{Key: "amount", Operator: "max", Value: "100"}},
		PolicyRevision: 3, RevocationEpoch: 2, ProviderID: "managed", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(), KeyID: "issuer-key-1",
	}
	if err := result.Sign(decisionPrivate); err != nil {
		t.Fatal(err)
	}
	enforcer := Enforcer{
		Trust:   testTrustStore{intentKey: intentPublic, decisionKey: decisionPublic, policyRevision: 3, revocationEpoch: 2},
		Ceiling: ceilingFunc(func(context.Context, Intent, Decision) error { return nil }), Now: func() time.Time { return now },
	}
	if err := enforcer.Verify(context.Background(), intent, result); err != nil {
		t.Fatal(err)
	}
}
