// SPDX-License-Identifier: AGPL-3.0-or-later

package decision

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

type EvaluationMode string

const (
	EvaluationShadow   EvaluationMode = "shadow"
	EvaluationDenyOnly EvaluationMode = "deny_only"
	EvaluationNarrow   EvaluationMode = "narrow"
)

// EvaluationFailureMode determines how a semantic evaluator outage is handled
// for one risk class. Inherit keeps the GuardedAuthorizer's legacy global
// FailClosed setting; explicit modes let tenants preserve availability for
// low-risk actions while failing closed for sensitive or irreversible work.
type EvaluationFailureMode string

const (
	EvaluationFailureInherit EvaluationFailureMode = ""
	EvaluationFailureOpen    EvaluationFailureMode = "fail_open"
	EvaluationFailureClosed  EvaluationFailureMode = "fail_closed"
)

// EvaluationRiskPolicy overrides semantic timeout and/or outage behavior for
// a signed Intent risk class. A zero timeout inherits GuardedAuthorizer.Timeout.
type EvaluationRiskPolicy struct {
	Timeout     time.Duration
	FailureMode EvaluationFailureMode
}

type EvaluatorIdentity struct {
	EvaluatorID   string `json:"evaluator_id"`
	Model         string `json:"model"`
	ModelVersion  string `json:"model_version"`
	PromptVersion string `json:"prompt_version"`
}

type EvaluationRecord struct {
	Version              uint16                `json:"version"`
	ID                   string                `json:"id"`
	IntentHash           string                `json:"intent_hash"`
	TenantID             string                `json:"tenant_id"`
	AgentID              string                `json:"agent_id"`
	Mode                 EvaluationMode        `json:"mode"`
	Identity             EvaluatorIdentity     `json:"identity"`
	BaseOutcome          Outcome               `json:"base_outcome"`
	SemanticOutcome      Outcome               `json:"semantic_outcome,omitempty"`
	AppliedOutcome       Outcome               `json:"applied_outcome"`
	Applied              bool                  `json:"applied"`
	StartedAt            int64                 `json:"started_at_unix_nano"`
	CompletedAt          int64                 `json:"completed_at_unix_nano"`
	TimeoutMillis        int64                 `json:"timeout_millis,omitempty"`
	FailureMode          EvaluationFailureMode `json:"failure_mode,omitempty"`
	SemanticContextHash  string                `json:"semantic_context_hash,omitempty"`
	MatchedClauseIDs     []string              `json:"matched_clause_ids,omitempty"`
	ApprovalPlanID       string                `json:"approval_plan_id,omitempty"`
	ApprovalPlanRevision uint64                `json:"approval_plan_revision,omitempty"`
	ErrorCode            string                `json:"error_code,omitempty"`
	ModelCalls           uint64                `json:"model_calls,omitempty"`
	InputTokens          uint64                `json:"input_tokens,omitempty"`
	OutputTokens         uint64                `json:"output_tokens,omitempty"`
}

func (record EvaluationRecord) Validate() error {
	if record.Version != SchemaVersion || !lowerHex(record.ID, 64) || !lowerHex(record.IntentHash, 64) {
		return fmt.Errorf("decision: invalid evaluation record identity")
	}
	for name, value := range map[string]string{
		"tenant_id": record.TenantID, "agent_id": record.AgentID,
		"evaluator_id": record.Identity.EvaluatorID, "model": record.Identity.Model,
		"model_version": record.Identity.ModelVersion, "prompt_version": record.Identity.PromptVersion,
	} {
		if err := validateIdentifier(name, value); err != nil {
			return err
		}
	}
	switch record.Mode {
	case EvaluationShadow, EvaluationDenyOnly, EvaluationNarrow:
	default:
		return fmt.Errorf("decision: invalid evaluation mode %q", record.Mode)
	}
	if !validOutcome(record.BaseOutcome) || !validOutcome(record.AppliedOutcome) {
		return fmt.Errorf("decision: invalid evaluation outcomes")
	}
	if record.SemanticOutcome != "" && !validOutcome(record.SemanticOutcome) {
		return fmt.Errorf("decision: invalid semantic outcome")
	}
	if record.StartedAt <= 0 || record.CompletedAt < record.StartedAt {
		return fmt.Errorf("decision: invalid evaluation timing")
	}
	if record.TimeoutMillis < 0 {
		return fmt.Errorf("decision: invalid evaluation timeout")
	}
	if err := (ModelUsage{ModelCalls: record.ModelCalls, InputTokens: record.InputTokens, OutputTokens: record.OutputTokens}).Validate(); err != nil {
		return err
	}
	switch record.FailureMode {
	case EvaluationFailureInherit, EvaluationFailureOpen, EvaluationFailureClosed:
	default:
		return fmt.Errorf("decision: invalid evaluation failure mode %q", record.FailureMode)
	}
	if record.ErrorCode != "" {
		if err := validateIdentifier("evaluation error_code", record.ErrorCode); err != nil {
			return err
		}
	}
	if record.SemanticContextHash != "" && !lowerHex(record.SemanticContextHash, 64) {
		return fmt.Errorf("decision: invalid semantic context hash")
	}
	if len(record.MatchedClauseIDs) > 64 {
		return fmt.Errorf("decision: too many matched semantic clauses")
	}
	seenClauses := make(map[string]struct{}, len(record.MatchedClauseIDs))
	for _, clauseID := range record.MatchedClauseIDs {
		if err := validateIdentifier("matched semantic clause", clauseID); err != nil {
			return err
		}
		if _, duplicate := seenClauses[clauseID]; duplicate {
			return fmt.Errorf("decision: duplicate matched semantic clause")
		}
		seenClauses[clauseID] = struct{}{}
	}
	if (record.ApprovalPlanID == "") != (record.ApprovalPlanRevision == 0) {
		return fmt.Errorf("decision: incomplete evaluation approval plan")
	}
	if record.ApprovalPlanID != "" {
		if err := validateIdentifier("evaluation approval plan", record.ApprovalPlanID); err != nil {
			return err
		}
		if record.SemanticOutcome != ApprovalRequired || len(record.MatchedClauseIDs) == 0 {
			return fmt.Errorf("decision: evaluation approval plan lacks matching approval clause")
		}
	}
	return nil
}

func (record EvaluationRecord) UsageUnitID() string { return record.ID }

type EvaluationObserver interface {
	RecordEvaluation(context.Context, EvaluationRecord) error
}

type GuardedAuthorizer struct {
	Base               Authorizer
	Semantic           Authorizer
	Mode               EvaluationMode
	Identity           EvaluatorIdentity
	Observer           EvaluationObserver
	Timeout            time.Duration
	FailClosed         bool
	RiskPolicies       map[RiskClass]EvaluationRiskPolicy
	ContextProvider    SemanticPolicyContextProvider
	RequireObservation bool
	Now                func() time.Time
}

// Authorize evaluates deterministic policy first. Semantic output is never
// permitted to expand the base result; its strongest production mode can only
// deny, require approval, or add constraints.
func (authorizer *GuardedAuthorizer) Authorize(ctx context.Context, intent Intent) (Decision, error) {
	return authorizer.authorize(ctx, intent, nil, nil)
}

// AuthorizeDisclosure preserves the same deterministic-first and
// non-expansion guarantees while passing only hash-bound typed metadata to
// evaluators that explicitly support it. A missing implementation is an error
// rather than a fallback to Authorize, because a required disclosure profile
// must not silently drop labels or residency information.
func (authorizer *GuardedAuthorizer) AuthorizeDisclosure(ctx context.Context, intent Intent, disclosure DisclosureBinding) (Decision, error) {
	if err := disclosure.VerifyIntent(intent); err != nil {
		return Decision{}, err
	}
	return authorizer.authorize(ctx, intent, &disclosure, nil)
}

// AuthorizeFederatedContent evaluates the exact exchange body through Pilot's
// hosted semantic provider. The deterministic base still receives only the
// signed intent and disclosure metadata, preserving the rule that semantic
// content analysis can narrow but never create authority.
func (authorizer *GuardedAuthorizer) AuthorizeFederatedContent(ctx context.Context, intent Intent, content FederatedContent) (Decision, error) {
	if err := content.VerifyIntent(intent); err != nil {
		return Decision{}, err
	}
	cloned := content.Clone()
	disclosure := cloned.Disclosure
	return authorizer.authorize(ctx, intent, &disclosure, &cloned)
}

func (authorizer *GuardedAuthorizer) authorize(ctx context.Context, intent Intent, disclosure *DisclosureBinding, content *FederatedContent) (Decision, error) {
	if authorizer == nil || authorizer.Base == nil || authorizer.Semantic == nil || authorizer.Observer == nil {
		return Decision{}, fmt.Errorf("decision: guarded authorizer is incomplete")
	}
	if err := authorizer.validateConfig(); err != nil {
		return Decision{}, err
	}
	base, err := authorizeWithDisclosure(ctx, authorizer.Base, intent, disclosure)
	if err != nil {
		return Decision{}, fmt.Errorf("decision: deterministic evaluator failed: %w", err)
	}
	if err := validateTemplate(base); err != nil {
		return Decision{}, fmt.Errorf("decision: invalid deterministic result: %w", err)
	}
	// Semantic evaluation is narrowing-only. Once deterministic policy has
	// denied an action, forwarding its content to a model cannot change the
	// answer and only adds cost, latency, and an unnecessary disclosure path.
	if base.Outcome == Deny {
		return base, nil
	}
	var semanticContext *SemanticPolicyContext
	if authorizer.ContextProvider != nil {
		policyContext, found, contextErr := authorizer.ContextProvider.SemanticPolicyContext(ctx, intent)
		if contextErr != nil {
			return Decision{}, fmt.Errorf("decision: load semantic policy context: %w", contextErr)
		}
		// A hosted model may interpret only clauses that an operator reviewed
		// and activated. Federated content is still verified and retained by
		// the exchange boundary, but sending it to a model without applicable
		// policy would add disclosure, latency, and billable tokens without a
		// governed question to answer.
		if !found {
			return base, nil
		}
		if found {
			if err := policyContext.ValidateIntent(intent, intent.IssuedAt); err != nil {
				return Decision{}, err
			}
			semanticContext = &policyContext
		}
	}
	intentHash, err := intent.Hash()
	if err != nil {
		return Decision{}, err
	}
	now := time.Now
	if authorizer.Now != nil {
		now = authorizer.Now
	}
	started := now()
	timeout, failClosed, failureMode := authorizer.evaluationPolicy(intent.Risk)
	evaluationCtx := ctx
	cancel := func() {}
	if timeout > 0 {
		evaluationCtx, cancel = context.WithTimeout(ctx, timeout)
	}
	evaluationCtx, usageRecorder := WithModelUsageRecorder(evaluationCtx)
	semantic, semanticErr := authorizeSemanticWithDisclosure(evaluationCtx, authorizer.Semantic, intent, disclosure, content, semanticContext)
	cancel()
	completed := now()
	modelUsage := usageRecorder.Snapshot()
	if semanticErr == nil {
		semanticErr = validateTemplate(semantic)
	}
	var matchedClauseIDs []string
	var approvalPlanID string
	var approvalPlanRevision uint64
	if semanticErr == nil && semanticContext != nil {
		matchedClauseIDs, approvalPlanID, approvalPlanRevision, semanticErr = validateSemanticPolicyResult(semantic, *semanticContext)
		if semanticErr == nil && approvalPlanID != "" {
			semantic.Reasons = append(semantic.Reasons, fmt.Sprintf("approval-plan:%s:%d", approvalPlanID, approvalPlanRevision))
		}
	}
	applied := cloneDecisionTemplate(base)
	appliedSemantic := false
	if semanticErr == nil {
		applied, appliedSemantic = applySemantic(base, semantic, authorizer.Mode)
	}
	record := EvaluationRecord{
		Version: SchemaVersion, ID: evaluationUsageID(intentHash, authorizer.Identity),
		IntentHash: intentHash, TenantID: intent.TenantID, AgentID: intent.AgentID,
		Mode: authorizer.Mode, Identity: authorizer.Identity, BaseOutcome: base.Outcome,
		AppliedOutcome: applied.Outcome, Applied: appliedSemantic,
		StartedAt: started.UnixNano(), CompletedAt: completed.UnixNano(),
		TimeoutMillis: timeout.Milliseconds(), FailureMode: failureMode,
		ModelCalls: modelUsage.ModelCalls, InputTokens: modelUsage.InputTokens, OutputTokens: modelUsage.OutputTokens,
	}
	if semanticContext != nil {
		record.SemanticContextHash = semanticContext.ContextHash
	}
	record.MatchedClauseIDs = matchedClauseIDs
	record.ApprovalPlanID, record.ApprovalPlanRevision = approvalPlanID, approvalPlanRevision
	if semanticErr == nil {
		record.SemanticOutcome = semantic.Outcome
	} else {
		record.ErrorCode = "evaluator_unavailable"
	}
	if err := record.Validate(); err != nil {
		return Decision{}, err
	}
	observationErr := authorizer.Observer.RecordEvaluation(ctx, record)
	if observationErr != nil && authorizer.RequireObservation {
		return Decision{}, fmt.Errorf("decision: persist semantic evaluation: %w", observationErr)
	}
	if semanticErr != nil && failClosed {
		return Decision{}, fmt.Errorf("decision: semantic evaluator failed closed: %w", semanticErr)
	}
	applied.Reasons = withEvaluationReason(applied.Reasons, record.ID)
	return applied, nil
}

func authorizeWithDisclosure(ctx context.Context, evaluator Authorizer, intent Intent, disclosure *DisclosureBinding) (Decision, error) {
	if disclosure == nil {
		return evaluator.Authorize(ctx, intent)
	}
	aware, supported := evaluator.(DisclosureAuthorizer)
	if !supported {
		return Decision{}, fmt.Errorf("decision: evaluator does not support disclosure binding")
	}
	return aware.AuthorizeDisclosure(ctx, intent, *disclosure)
}

func authorizeSemanticWithDisclosure(ctx context.Context, evaluator Authorizer, intent Intent, disclosure *DisclosureBinding, content *FederatedContent, policy *SemanticPolicyContext) (Decision, error) {
	if content != nil {
		if disclosure == nil {
			return Decision{}, fmt.Errorf("decision: federated content is missing disclosure binding")
		}
		if err := content.VerifyIntent(intent); err != nil {
			return Decision{}, err
		}
		if policy == nil {
			aware, supported := evaluator.(FederatedContentAuthorizer)
			if !supported {
				return Decision{}, fmt.Errorf("decision: evaluator does not support federated content")
			}
			return aware.AuthorizeFederatedContent(ctx, intent, content.Clone())
		}
		aware, supported := evaluator.(SemanticContextFederatedContentAuthorizer)
		if !supported {
			return Decision{}, fmt.Errorf("decision: evaluator does not support semantic policy context with federated content")
		}
		return aware.AuthorizeSemanticFederatedContent(ctx, intent, content.Clone(), *policy)
	}
	if policy == nil {
		return authorizeWithDisclosure(ctx, evaluator, intent, disclosure)
	}
	if disclosure == nil {
		aware, supported := evaluator.(SemanticContextAuthorizer)
		if !supported {
			return Decision{}, fmt.Errorf("decision: evaluator does not support semantic policy context")
		}
		return aware.AuthorizeSemantic(ctx, intent, *policy)
	}
	aware, supported := evaluator.(SemanticContextDisclosureAuthorizer)
	if !supported {
		return Decision{}, fmt.Errorf("decision: evaluator does not support semantic policy context with disclosure")
	}
	return aware.AuthorizeSemanticDisclosure(ctx, intent, *disclosure, *policy)
}

func validateSemanticPolicyResult(result Decision, policy SemanticPolicyContext) ([]string, string, uint64, error) {
	if result.Outcome == Allow {
		return nil, "", 0, nil
	}
	clauses := make(map[string]SemanticPolicyClause, len(policy.Clauses))
	for _, clause := range policy.Clauses {
		clauses[clause.ID] = clause
	}
	matched := make([]string, 0)
	seen := make(map[string]struct{})
	for _, reason := range result.Reasons {
		if !strings.HasPrefix(reason, "semantic-clause:") {
			continue
		}
		id := strings.TrimPrefix(reason, "semantic-clause:")
		clause, found := clauses[id]
		if !found {
			return nil, "", 0, fmt.Errorf("decision: evaluator referenced inactive semantic clause %q", id)
		}
		if clause.OutcomeOnMatch != result.Outcome {
			return nil, "", 0, fmt.Errorf("decision: evaluator outcome exceeds semantic clause %q", id)
		}
		if _, duplicate := seen[id]; !duplicate {
			matched = append(matched, id)
			seen[id] = struct{}{}
		}
	}
	if len(matched) == 0 {
		return nil, "", 0, fmt.Errorf("decision: narrowing semantic result lacks a reviewed clause")
	}
	if result.Outcome != ApprovalRequired {
		return matched, "", 0, nil
	}
	var planID string
	var planRevision uint64
	for _, id := range matched {
		clause := clauses[id]
		if planID == "" {
			planID, planRevision = clause.ApprovalPlanID, clause.ApprovalPlanRevision
			continue
		}
		if planID != clause.ApprovalPlanID || planRevision != clause.ApprovalPlanRevision {
			return nil, "", 0, fmt.Errorf("decision: matched semantic clauses disagree on approval plan")
		}
	}
	return matched, planID, planRevision, nil
}

func (authorizer *GuardedAuthorizer) evaluationPolicy(risk RiskClass) (time.Duration, bool, EvaluationFailureMode) {
	timeout, failClosed := authorizer.Timeout, authorizer.FailClosed
	failureMode := EvaluationFailureOpen
	if failClosed {
		failureMode = EvaluationFailureClosed
	}
	if policy, exists := authorizer.RiskPolicies[risk]; exists {
		if policy.Timeout > 0 {
			timeout = policy.Timeout
		}
		if policy.FailureMode != EvaluationFailureInherit {
			failureMode = policy.FailureMode
			failClosed = policy.FailureMode == EvaluationFailureClosed
		}
	}
	return timeout, failClosed, failureMode
}

func (authorizer *GuardedAuthorizer) validateConfig() error {
	switch authorizer.Mode {
	case EvaluationShadow, EvaluationDenyOnly, EvaluationNarrow:
	default:
		return fmt.Errorf("decision: invalid semantic evaluation mode %q", authorizer.Mode)
	}
	if authorizer.Mode != EvaluationShadow && !authorizer.RequireObservation {
		return fmt.Errorf("decision: autonomous semantic modes require durable observation")
	}
	for name, value := range map[string]string{
		"evaluator_id": authorizer.Identity.EvaluatorID, "model": authorizer.Identity.Model,
		"model_version": authorizer.Identity.ModelVersion, "prompt_version": authorizer.Identity.PromptVersion,
	} {
		if err := validateIdentifier(name, value); err != nil {
			return err
		}
	}
	for risk, policy := range authorizer.RiskPolicies {
		switch risk {
		case RiskLow, RiskMedium, RiskHigh, RiskCritical:
		default:
			return fmt.Errorf("decision: invalid semantic risk policy %q", risk)
		}
		if policy.Timeout < 0 {
			return fmt.Errorf("decision: semantic timeout for %s must not be negative", risk)
		}
		switch policy.FailureMode {
		case EvaluationFailureInherit, EvaluationFailureOpen, EvaluationFailureClosed:
		default:
			return fmt.Errorf("decision: invalid semantic failure mode %q for %s", policy.FailureMode, risk)
		}
	}
	return nil
}

func applySemantic(base, semantic Decision, mode EvaluationMode) (Decision, bool) {
	result := cloneDecisionTemplate(base)
	if mode == EvaluationShadow || semantic.Outcome == Allow {
		return result, false
	}
	if mode == EvaluationDenyOnly {
		if semantic.Outcome == Deny && base.Outcome != Deny {
			result.Outcome, result.Constraints = Deny, nil
			result.Reasons = mergedReasons(base.Reasons, semantic.Reasons)
			return result, true
		}
		return result, false
	}
	switch semantic.Outcome {
	case Deny:
		if base.Outcome != Deny {
			result.Outcome, result.Constraints = Deny, nil
			result.Reasons = mergedReasons(base.Reasons, semantic.Reasons)
			return result, true
		}
	case ApprovalRequired:
		if base.Outcome == Allow || base.Outcome == Constrain {
			result.Outcome, result.Constraints = ApprovalRequired, nil
			result.Reasons = mergedReasons(base.Reasons, semantic.Reasons)
			return result, true
		}
	case Constrain:
		if base.Outcome == Allow {
			result.Outcome = Constrain
			result.Constraints = append([]Constraint(nil), semantic.Constraints...)
			result.Reasons = mergedReasons(base.Reasons, semantic.Reasons)
			return result, true
		}
		if base.Outcome == Constrain {
			result.Constraints = mergeConstraints(base.Constraints, semantic.Constraints)
			result.Reasons = mergedReasons(base.Reasons, semantic.Reasons)
			return result, len(result.Constraints) > len(base.Constraints)
		}
	}
	return result, false
}

func validateTemplate(template Decision) error {
	probe := cloneDecisionTemplate(template)
	probe.Version = SchemaVersion
	probe.ID = "evaluation-template"
	probe.IntentHash = strings.Repeat("0", 64)
	probe.TenantID = "evaluation-template"
	probe.AgentID = "evaluation-template"
	probe.ProviderID = "evaluation-template"
	probe.IssuedAt = 1
	probe.ExpiresAt = 2
	probe.KeyID = "evaluation-template"
	return probe.Validate()
}

func cloneDecisionTemplate(template Decision) Decision {
	clone := template
	clone.Reasons = append([]string(nil), template.Reasons...)
	clone.Constraints = append([]Constraint(nil), template.Constraints...)
	return clone
}

func mergeConstraints(first, second []Constraint) []Constraint {
	merged := append([]Constraint(nil), first...)
	for _, candidate := range second {
		found := false
		for _, existing := range merged {
			if existing.Key == candidate.Key && existing.Operator == candidate.Operator {
				found = true
				break
			}
		}
		if !found && len(merged) < 32 {
			merged = append(merged, candidate)
		}
	}
	return merged
}

func mergedReasons(first, second []string) []string {
	merged := append([]string(nil), first...)
	for _, reason := range second {
		if len(merged) >= 15 {
			break
		}
		merged = append(merged, reason)
	}
	return merged
}

func withEvaluationReason(reasons []string, evaluationID string) []string {
	if len(reasons) >= 16 {
		reasons = append([]string(nil), reasons[:15]...)
	} else {
		reasons = append([]string(nil), reasons...)
	}
	return append(reasons, "evaluation:"+evaluationID)
}

func evaluationUsageID(intentHash string, identity EvaluatorIdentity) string {
	hash := sha256.New()
	for _, value := range []string{"pilot-evaluation-unit-v1", intentHash, identity.EvaluatorID, identity.Model, identity.ModelVersion, identity.PromptVersion} {
		var length [4]byte
		length[0] = byte(len(value) >> 24)
		length[1] = byte(len(value) >> 16)
		length[2] = byte(len(value) >> 8)
		length[3] = byte(len(value))
		hash.Write(length[:])
		hash.Write([]byte(value))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func validOutcome(outcome Outcome) bool {
	return outcome == Allow || outcome == Deny || outcome == Constrain || outcome == ApprovalRequired
}
