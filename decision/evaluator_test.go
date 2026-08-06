// SPDX-License-Identifier: AGPL-3.0-or-later

package decision

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type evaluationCollector struct {
	mu      sync.Mutex
	records []EvaluationRecord
	err     error
}

type disclosureEvaluatorFunc func(context.Context, Intent, DisclosureBinding) (Decision, error)

type semanticEvaluatorFunc func(context.Context, Intent, SemanticPolicyContext) (Decision, error)

type federatedEvaluatorFunc func(context.Context, Intent, FederatedContent) (Decision, error)

func (evaluator federatedEvaluatorFunc) Authorize(context.Context, Intent) (Decision, error) {
	return Decision{}, errors.New("plain semantic authorization is not expected")
}

func (evaluator federatedEvaluatorFunc) AuthorizeFederatedContent(ctx context.Context, intent Intent, content FederatedContent) (Decision, error) {
	return evaluator(ctx, intent, content)
}

func (evaluator semanticEvaluatorFunc) Authorize(context.Context, Intent) (Decision, error) {
	return Decision{}, errors.New("plain semantic authorization is not expected")
}

func (evaluator semanticEvaluatorFunc) AuthorizeSemantic(ctx context.Context, intent Intent, policy SemanticPolicyContext) (Decision, error) {
	return evaluator(ctx, intent, policy)
}

type semanticContextProviderFunc func(context.Context, Intent) (SemanticPolicyContext, bool, error)

func (provider semanticContextProviderFunc) SemanticPolicyContext(ctx context.Context, intent Intent) (SemanticPolicyContext, bool, error) {
	return provider(ctx, intent)
}

func (evaluator disclosureEvaluatorFunc) Authorize(context.Context, Intent) (Decision, error) {
	return Decision{}, errors.New("plain authorization is not expected")
}

func (evaluator disclosureEvaluatorFunc) AuthorizeDisclosure(ctx context.Context, intent Intent, disclosure DisclosureBinding) (Decision, error) {
	return evaluator(ctx, intent, disclosure)
}

func (collector *evaluationCollector) RecordEvaluation(_ context.Context, record EvaluationRecord) error {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	collector.records = append(collector.records, record)
	return collector.err
}

func evaluatorIdentity() EvaluatorIdentity {
	return EvaluatorIdentity{EvaluatorID: "semantic-1", Model: "model-a", ModelVersion: "2026-07", PromptVersion: "prompt-3"}
}

func TestGuardedAuthorizerShadowCannotChangeAuthority(t *testing.T) {
	t.Parallel()
	now := time.Unix(1785500000, 0)
	collector := &evaluationCollector{}
	authorizer := GuardedAuthorizer{
		Base: authorizerFunc(func(context.Context, Intent) (Decision, error) {
			return Decision{Outcome: Allow, PolicyRevision: 7, RevocationEpoch: 2, Reasons: []string{"base"}}, nil
		}),
		Semantic: authorizerFunc(func(context.Context, Intent) (Decision, error) {
			return Decision{Outcome: Deny, Reasons: []string{"semantic-risk"}}, nil
		}),
		Mode: EvaluationShadow, Identity: evaluatorIdentity(), Observer: collector,
		Now: func() time.Time { return now },
	}
	result, err := authorizer.Authorize(context.Background(), testIntent(t, now))
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != Allow || len(collector.records) != 1 || collector.records[0].Applied {
		t.Fatalf("shadow result=%+v records=%+v", result, collector.records)
	}
	if !strings.HasPrefix(result.Reasons[len(result.Reasons)-1], "evaluation:") {
		t.Fatal("signed decision template is not bound to evaluation usage ID")
	}
}

func TestGuardedAuthorizerPassesReviewedSemanticContextAndJournalsHash(t *testing.T) {
	now := time.Unix(1785500000, 0)
	intent := testIntent(t, now)
	policy, err := NewSemanticPolicyContext(intent.TenantID, []SemanticPolicyClause{{
		ID: "clause-a", StatementID: "statement-a", StatementRevision: 4, Instruction: "Deny when the resource belongs to Acme.",
		Actions: []string{intent.Action}, OutcomeOnMatch: Deny, MetadataFields: []string{"action", "resource"}, FailureMode: EvaluationFailureClosed,
	}})
	if err != nil {
		t.Fatal(err)
	}
	collector := &evaluationCollector{}
	semanticCalls := 0
	authorizer := GuardedAuthorizer{
		Base: authorizerFunc(func(context.Context, Intent) (Decision, error) { return Decision{Outcome: Allow}, nil }),
		Semantic: semanticEvaluatorFunc(func(ctx context.Context, got Intent, semanticContext SemanticPolicyContext) (Decision, error) {
			semanticCalls++
			if got.ID != intent.ID || semanticContext.ContextHash != policy.ContextHash || semanticContext.Clauses[0].StatementID != "statement-a" {
				t.Fatalf("semantic context mismatch: intent=%+v context=%+v", got, semanticContext)
			}
			if err := ReportModelUsage(ctx, ModelUsage{ModelCalls: 1, InputTokens: 41, OutputTokens: 7}); err != nil {
				t.Fatal(err)
			}
			return Decision{Outcome: Deny, Reasons: []string{"semantic-clause:clause-a"}}, nil
		}),
		ContextProvider: semanticContextProviderFunc(func(context.Context, Intent) (SemanticPolicyContext, bool, error) { return policy, true, nil }),
		Mode:            EvaluationNarrow, Identity: evaluatorIdentity(), Observer: collector, RequireObservation: true, Now: func() time.Time { return now },
	}
	result, err := authorizer.Authorize(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != Deny || semanticCalls != 1 || len(collector.records) != 1 || collector.records[0].SemanticContextHash != policy.ContextHash {
		t.Fatalf("result=%+v calls=%d records=%+v", result, semanticCalls, collector.records)
	}
	if record := collector.records[0]; record.ModelCalls != 1 || record.InputTokens != 41 || record.OutputTokens != 7 {
		t.Fatalf("model usage not journaled: %+v", record)
	}
}

func TestGuardedAuthorizerSkipsSemanticWhenNoActiveClause(t *testing.T) {
	now := time.Unix(1785500000, 0)
	semanticCalls := 0
	authorizer := GuardedAuthorizer{
		Base: authorizerFunc(func(context.Context, Intent) (Decision, error) { return Decision{Outcome: Allow}, nil }),
		Semantic: semanticEvaluatorFunc(func(context.Context, Intent, SemanticPolicyContext) (Decision, error) {
			semanticCalls++
			return Decision{Outcome: Deny}, nil
		}),
		ContextProvider: semanticContextProviderFunc(func(context.Context, Intent) (SemanticPolicyContext, bool, error) {
			return SemanticPolicyContext{}, false, nil
		}),
		Mode: EvaluationNarrow, Identity: evaluatorIdentity(), Observer: &evaluationCollector{}, RequireObservation: true, Now: func() time.Time { return now },
	}
	result, err := authorizer.Authorize(context.Background(), testIntent(t, now))
	if err != nil || result.Outcome != Allow || semanticCalls != 0 {
		t.Fatalf("result=%+v calls=%d err=%v", result, semanticCalls, err)
	}
}

func TestGuardedAuthorizerDoesNotDiscloseHostedContentWithoutActiveClause(t *testing.T) {
	now := time.Unix(1785500000, 0)
	body := []byte("customer message body")
	disclosure := DisclosureBinding{
		Version: DisclosureBindingRetentionVersion, ContentHash: HashPayload(body), DeclaredBytes: uint64(len(body)),
		ContentType: "text/plain", Labels: []string{"customer-message"}, Recipient: "agent:support", Purpose: "reply to customer", Residency: "eu-west-1", RetentionClass: "standard",
	}
	content, err := NewFederatedContent(disclosure, body)
	if err != nil {
		t.Fatal(err)
	}
	intent := testIntent(t, now)
	intent.Audience, intent.Purpose = disclosure.Recipient, disclosure.Purpose
	intent.PayloadHash, err = disclosure.Hash()
	if err != nil {
		t.Fatal(err)
	}
	semanticCalls := 0
	collector := &evaluationCollector{}
	authorizer := GuardedAuthorizer{
		Base: disclosureEvaluatorFunc(func(context.Context, Intent, DisclosureBinding) (Decision, error) {
			return Decision{Outcome: Allow}, nil
		}),
		Semantic: federatedEvaluatorFunc(func(_ context.Context, got Intent, gotContent FederatedContent) (Decision, error) {
			semanticCalls++
			if got.ID != intent.ID || string(gotContent.Body) != string(body) {
				t.Fatalf("hosted content mismatch: intent=%+v content=%q", got, gotContent.Body)
			}
			return Decision{Outcome: Deny, Reasons: []string{"hosted_content_denied"}}, nil
		}),
		ContextProvider: semanticContextProviderFunc(func(context.Context, Intent) (SemanticPolicyContext, bool, error) {
			return SemanticPolicyContext{}, false, nil
		}),
		Mode: EvaluationNarrow, Identity: evaluatorIdentity(), Observer: collector, RequireObservation: true, Now: func() time.Time { return now },
	}
	result, err := authorizer.AuthorizeFederatedContent(context.Background(), intent, content)
	if err != nil || result.Outcome != Allow || semanticCalls != 0 || len(collector.records) != 0 {
		t.Fatalf("result=%+v calls=%d records=%+v err=%v", result, semanticCalls, collector.records, err)
	}
}

func TestGuardedAuthorizerDoesNotDiscloseContentAfterDeterministicDeny(t *testing.T) {
	now := time.Unix(1785500000, 0)
	body := []byte("destructive command with sensitive arguments")
	disclosure := DisclosureBinding{
		Version: DisclosureBindingVersion, ContentHash: HashPayload(body), DeclaredBytes: uint64(len(body)),
		ContentType: "text/plain", Labels: []string{"restricted"}, Recipient: "process:host", Purpose: "execute command", Residency: "eu",
	}
	content, err := NewFederatedContent(disclosure, body)
	if err != nil {
		t.Fatal(err)
	}
	intent := testIntent(t, now)
	intent.Audience, intent.Purpose = disclosure.Recipient, disclosure.Purpose
	intent.PayloadHash, err = disclosure.Hash()
	if err != nil {
		t.Fatal(err)
	}
	semanticCalls := 0
	collector := &evaluationCollector{}
	authorizer := GuardedAuthorizer{
		Base: disclosureEvaluatorFunc(func(context.Context, Intent, DisclosureBinding) (Decision, error) {
			return Decision{Outcome: Deny, Reasons: []string{"deterministic-deny"}}, nil
		}),
		Semantic: federatedEvaluatorFunc(func(context.Context, Intent, FederatedContent) (Decision, error) {
			semanticCalls++
			return Decision{Outcome: Allow}, nil
		}),
		Mode: EvaluationNarrow, Identity: evaluatorIdentity(), Observer: collector, RequireObservation: true, Now: func() time.Time { return now },
	}
	result, err := authorizer.AuthorizeFederatedContent(context.Background(), intent, content)
	if err != nil || result.Outcome != Deny || semanticCalls != 0 || len(collector.records) != 0 {
		t.Fatalf("result=%+v calls=%d records=%+v err=%v", result, semanticCalls, collector.records, err)
	}
}

func TestSemanticApprovalPinsReviewedPlanAndRejectsInventedClause(t *testing.T) {
	now := time.Unix(1785500000, 0)
	intent := testIntent(t, now)
	policy, err := NewSemanticPolicyContext(intent.TenantID, []SemanticPolicyClause{{
		ID: "clause-approval", StatementID: "statement-a", StatementRevision: 7, Instruction: "Require security approval for an external recipient.",
		Actions: []string{intent.Action}, OutcomeOnMatch: ApprovalRequired, ApprovalPlanID: "security-review", ApprovalPlanRevision: 3,
		MetadataFields: []string{"resource"}, FailureMode: EvaluationFailureClosed,
	}})
	if err != nil {
		t.Fatal(err)
	}
	collector := &evaluationCollector{}
	semantic := semanticEvaluatorFunc(func(context.Context, Intent, SemanticPolicyContext) (Decision, error) {
		return Decision{Outcome: ApprovalRequired, Reasons: []string{"semantic-clause:clause-approval"}}, nil
	})
	authorizer := GuardedAuthorizer{
		Base: authorizerFunc(func(context.Context, Intent) (Decision, error) { return Decision{Outcome: Allow}, nil }), Semantic: semantic,
		ContextProvider: semanticContextProviderFunc(func(context.Context, Intent) (SemanticPolicyContext, bool, error) { return policy, true, nil }),
		Mode:            EvaluationNarrow, Identity: evaluatorIdentity(), Observer: collector, RequireObservation: true, FailClosed: true, Now: func() time.Time { return now },
	}
	result, err := authorizer.Authorize(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != ApprovalRequired || !containsString(result.Reasons, "approval-plan:security-review:3") {
		t.Fatalf("approval plan was not pinned in result: %+v", result)
	}
	if len(collector.records) != 1 || collector.records[0].ApprovalPlanID != "security-review" || collector.records[0].ApprovalPlanRevision != 3 {
		t.Fatalf("approval plan was not journaled: %+v", collector.records)
	}
	authorizer.Semantic = semanticEvaluatorFunc(func(context.Context, Intent, SemanticPolicyContext) (Decision, error) {
		return Decision{Outcome: ApprovalRequired, Reasons: []string{"semantic-clause:invented"}}, nil
	})
	if _, err := authorizer.Authorize(context.Background(), intent); err == nil || !strings.Contains(err.Error(), "inactive semantic clause") {
		t.Fatalf("invented semantic clause was accepted: %v", err)
	}
}

func TestGuardedAuthorizerPassesDisclosureOnlyToAwareEvaluators(t *testing.T) {
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
	var baseCalls, semanticCalls int
	base := disclosureEvaluatorFunc(func(_ context.Context, received Intent, got DisclosureBinding) (Decision, error) {
		baseCalls++
		if received.PayloadHash != disclosureHash || got.Residency != disclosure.Residency {
			t.Fatalf("base metadata was not bound: intent=%+v disclosure=%+v", received, got)
		}
		return Decision{Outcome: Allow}, nil
	})
	semantic := disclosureEvaluatorFunc(func(_ context.Context, _ Intent, got DisclosureBinding) (Decision, error) {
		semanticCalls++
		if got.ContentType != disclosure.ContentType || got.Filename != disclosure.Filename {
			t.Fatalf("semantic metadata mismatch: %+v", got)
		}
		return Decision{Outcome: Deny}, nil
	})
	authorizer := GuardedAuthorizer{
		Base: base, Semantic: semantic, Mode: EvaluationDenyOnly, Identity: evaluatorIdentity(),
		Observer: &evaluationCollector{}, RequireObservation: true, Now: func() time.Time { return now },
	}
	result, err := authorizer.AuthorizeDisclosure(context.Background(), intent, disclosure)
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != Deny || baseCalls != 1 || semanticCalls != 1 {
		t.Fatalf("result=%+v base=%d semantic=%d", result, baseCalls, semanticCalls)
	}

	authorizer.Base = authorizerFunc(func(context.Context, Intent) (Decision, error) { return Decision{Outcome: Allow}, nil })
	if _, err := authorizer.AuthorizeDisclosure(context.Background(), intent, disclosure); err == nil || !strings.Contains(err.Error(), "does not support disclosure") {
		t.Fatalf("non-disclosure base evaluator was accepted: %v", err)
	}
}

func TestGuardedAuthorizerDenyOnlyAndNarrowModes(t *testing.T) {
	t.Parallel()
	now := time.Unix(1785500000, 0)
	intent := testIntent(t, now)
	for _, test := range []struct {
		name        string
		mode        EvaluationMode
		base        Decision
		semantic    Decision
		want        Outcome
		constraints int
	}{
		{name: "deny-only applies deny", mode: EvaluationDenyOnly, base: Decision{Outcome: Allow}, semantic: Decision{Outcome: Deny}, want: Deny},
		{name: "deny-only ignores constraint", mode: EvaluationDenyOnly, base: Decision{Outcome: Allow}, semantic: Decision{Outcome: Constrain, Constraints: []Constraint{{Key: "amount", Operator: "max", Value: "10"}}}, want: Allow},
		{name: "narrow applies constraint", mode: EvaluationNarrow, base: Decision{Outcome: Allow}, semantic: Decision{Outcome: Constrain, Constraints: []Constraint{{Key: "amount", Operator: "max", Value: "10"}}}, want: Constrain, constraints: 1},
		{name: "allow cannot expand deny", mode: EvaluationNarrow, base: Decision{Outcome: Deny}, semantic: Decision{Outcome: Allow}, want: Deny},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			collector := &evaluationCollector{}
			authorizer := GuardedAuthorizer{
				Base:     authorizerFunc(func(context.Context, Intent) (Decision, error) { return test.base, nil }),
				Semantic: authorizerFunc(func(context.Context, Intent) (Decision, error) { return test.semantic, nil }),
				Mode:     test.mode, Identity: evaluatorIdentity(), Observer: collector,
				RequireObservation: test.mode != EvaluationShadow, Now: func() time.Time { return now },
			}
			result, err := authorizer.Authorize(context.Background(), intent)
			if err != nil {
				t.Fatal(err)
			}
			if result.Outcome != test.want || len(result.Constraints) != test.constraints {
				t.Fatalf("result=%+v", result)
			}
		})
	}
}

func TestGuardedAuthorizerFailureAndObservationPolicies(t *testing.T) {
	t.Parallel()
	now := time.Unix(1785500000, 0)
	intent := testIntent(t, now)
	collector := &evaluationCollector{}
	authorizer := GuardedAuthorizer{
		Base:     authorizerFunc(func(context.Context, Intent) (Decision, error) { return Decision{Outcome: Allow}, nil }),
		Semantic: authorizerFunc(func(context.Context, Intent) (Decision, error) { return Decision{}, errors.New("model down") }),
		Mode:     EvaluationShadow, Identity: evaluatorIdentity(), Observer: collector,
		FailClosed: true, Now: func() time.Time { return now },
	}
	if _, err := authorizer.Authorize(context.Background(), intent); err == nil {
		t.Fatal("fail-closed semantic outage was accepted")
	}
	if len(collector.records) != 1 || collector.records[0].ErrorCode == "" {
		t.Fatalf("semantic failure was not observed: %+v", collector.records)
	}
	collector.err = errors.New("journal down")
	authorizer.FailClosed = false
	authorizer.RequireObservation = true
	if _, err := authorizer.Authorize(context.Background(), intent); err == nil {
		t.Fatal("required observation failure was accepted")
	}
}

func TestGuardedAuthorizerAppliesRiskSpecificFailurePolicyAndEvidence(t *testing.T) {
	t.Parallel()
	now := time.Unix(1785500000, 0)
	collector := &evaluationCollector{}
	authorizer := GuardedAuthorizer{
		Base:     authorizerFunc(func(context.Context, Intent) (Decision, error) { return Decision{Outcome: Allow}, nil }),
		Semantic: authorizerFunc(func(context.Context, Intent) (Decision, error) { return Decision{}, errors.New("model down") }),
		Mode:     EvaluationShadow, Identity: evaluatorIdentity(), Observer: collector,
		FailClosed: false, Timeout: time.Second,
		RiskPolicies: map[RiskClass]EvaluationRiskPolicy{
			RiskHigh: {Timeout: 20 * time.Millisecond, FailureMode: EvaluationFailureClosed},
			RiskLow:  {FailureMode: EvaluationFailureOpen},
		},
		Now: func() time.Time { return now },
	}
	high := testIntent(t, now)
	high.Risk = RiskHigh
	if _, err := authorizer.Authorize(context.Background(), high); err == nil {
		t.Fatal("high-risk evaluator outage did not fail closed")
	}
	low := testIntent(t, now)
	low.Risk = RiskLow
	result, err := authorizer.Authorize(context.Background(), low)
	if err != nil || result.Outcome != Allow {
		t.Fatalf("low-risk evaluator outage result=%+v err=%v", result, err)
	}
	if len(collector.records) != 2 {
		t.Fatalf("evaluation records=%+v", collector.records)
	}
	highRecord, lowRecord := collector.records[0], collector.records[1]
	if highRecord.FailureMode != EvaluationFailureClosed || highRecord.TimeoutMillis != 20 || highRecord.ErrorCode == "" {
		t.Fatalf("high-risk evaluation evidence=%+v", highRecord)
	}
	if lowRecord.FailureMode != EvaluationFailureOpen || lowRecord.TimeoutMillis != 1000 || lowRecord.ErrorCode == "" {
		t.Fatalf("low-risk evaluation evidence=%+v", lowRecord)
	}
}

func TestAutonomousSemanticModeRequiresDurableObservation(t *testing.T) {
	t.Parallel()
	now := time.Unix(1785500000, 0)
	authorizer := GuardedAuthorizer{
		Base:     authorizerFunc(func(context.Context, Intent) (Decision, error) { return Decision{Outcome: Allow}, nil }),
		Semantic: authorizerFunc(func(context.Context, Intent) (Decision, error) { return Decision{Outcome: Deny}, nil }),
		Mode:     EvaluationDenyOnly, Identity: evaluatorIdentity(), Observer: &evaluationCollector{},
		Now: func() time.Time { return now },
	}
	if _, err := authorizer.Authorize(context.Background(), testIntent(t, now)); err == nil {
		t.Fatal("autonomous semantic decision ran without durable-observation requirement")
	}
}

func TestEvaluationJournalDeduplicatesUsageAcrossRestart(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "evaluations.jsonl")
	journal, err := OpenEvaluationJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	record := EvaluationRecord{
		Version: SchemaVersion, ID: strings.Repeat("a", 64), IntentHash: strings.Repeat("b", 64),
		TenantID: "tenant-a", AgentID: "agent-1", Mode: EvaluationShadow,
		Identity: evaluatorIdentity(), BaseOutcome: Allow, SemanticOutcome: Deny, AppliedOutcome: Allow,
		StartedAt: 1, CompletedAt: 2,
	}
	if err := journal.RecordEvaluation(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	if err := journal.RecordEvaluation(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenEvaluationJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.RecordEvaluation(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	lookedUp, found, err := reopened.EvaluationRecordForIntent(context.Background(), record.TenantID, record.IntentHash)
	if err != nil || !found || lookedUp.ID != record.ID {
		t.Fatalf("intent lookup=%+v found=%v err=%v", lookedUp, found, err)
	}
	conflict := record
	conflict.AppliedOutcome = Deny
	if err := reopened.RecordEvaluation(context.Background(), conflict); err == nil {
		t.Fatal("conflicting evaluation usage unit was accepted")
	}
}
