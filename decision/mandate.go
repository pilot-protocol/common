// SPDX-License-Identifier: AGPL-3.0-or-later

package decision

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	MandateDomain         = "pilot-mandate-v1"
	MaxMandateTTL         = 90 * 24 * time.Hour
	MaxMandateActions     = 64
	MaxMandateResources   = 64
	MaxMandateConstraints = 32
	MaxMandateApprovals   = 32
)

// Mandate is a tenant-issuer-signed delegation to one workload. It is a
// ceiling, not a provider decision: a matching policy Decision may only be
// used when it is equal to or narrower than this delegation.
//
// Audience and Purpose are intentionally explicit. A caller cannot use a
// mandate issued for one counterparty or business purpose with another exact
// Intent, even where action and resource names happen to match.
type Mandate struct {
	Version           uint16       `json:"version"`
	ID                string       `json:"id"`
	TenantID          string       `json:"tenant_id"`
	SubjectAgentID    string       `json:"subject_agent_id"`
	Actions           []string     `json:"actions"`
	ResourcePrefixes  []string     `json:"resource_prefixes"`
	Audience          string       `json:"audience"`
	Purpose           string       `json:"purpose"`
	Constraints       []Constraint `json:"constraints,omitempty"`
	RequiredApprovals uint16       `json:"required_approvals,omitempty"`
	RevocationEpoch   uint64       `json:"revocation_epoch"`
	IssuedAt          int64        `json:"issued_at"`
	ExpiresAt         int64        `json:"expires_at"`
	KeyID             string       `json:"key_id"`
	Signature         string       `json:"signature"`
}

func (mandate Mandate) Validate() error {
	if mandate.Version != SchemaVersion {
		return fmt.Errorf("decision: mandate version %d is unsupported", mandate.Version)
	}
	for name, value := range map[string]string{
		"mandate id": mandate.ID, "tenant_id": mandate.TenantID, "subject_agent_id": mandate.SubjectAgentID, "key_id": mandate.KeyID,
	} {
		if err := validateIdentifier(name, value); err != nil {
			return err
		}
	}
	if len(mandate.Actions) == 0 || len(mandate.Actions) > MaxMandateActions {
		return fmt.Errorf("decision: mandate must contain 1-%d actions", MaxMandateActions)
	}
	if len(mandate.ResourcePrefixes) == 0 || len(mandate.ResourcePrefixes) > MaxMandateResources {
		return fmt.Errorf("decision: mandate must contain 1-%d resource prefixes", MaxMandateResources)
	}
	if mandate.Audience == "" || !validMandateAudience(mandate.Audience) {
		return fmt.Errorf("decision: mandate audience is invalid")
	}
	if err := validateText("mandate purpose", mandate.Purpose, 256, false); err != nil {
		return err
	}
	seenActions := make(map[string]struct{}, len(mandate.Actions))
	for _, action := range mandate.Actions {
		if !validMandateAction(action) {
			return fmt.Errorf("decision: invalid mandate action %q", action)
		}
		if _, exists := seenActions[action]; exists {
			return fmt.Errorf("decision: duplicate mandate action %q", action)
		}
		seenActions[action] = struct{}{}
	}
	seenResources := make(map[string]struct{}, len(mandate.ResourcePrefixes))
	for _, resource := range mandate.ResourcePrefixes {
		if !validMandateResource(resource) {
			return fmt.Errorf("decision: invalid mandate resource prefix %q", resource)
		}
		if _, exists := seenResources[resource]; exists {
			return fmt.Errorf("decision: duplicate mandate resource prefix %q", resource)
		}
		seenResources[resource] = struct{}{}
	}
	if len(mandate.Constraints) > MaxMandateConstraints {
		return fmt.Errorf("decision: mandate has more than %d constraints", MaxMandateConstraints)
	}
	seenConstraints := make(map[string]struct{}, len(mandate.Constraints))
	for _, constraint := range mandate.Constraints {
		if err := validateConstraint(constraint); err != nil {
			return fmt.Errorf("decision: invalid mandate constraint: %w", err)
		}
		identity := constraint.Key + "\x00" + constraint.Operator
		if _, exists := seenConstraints[identity]; exists {
			return fmt.Errorf("decision: duplicate mandate constraint %q/%q", constraint.Key, constraint.Operator)
		}
		seenConstraints[identity] = struct{}{}
	}
	if mandate.RequiredApprovals > MaxMandateApprovals {
		return fmt.Errorf("decision: mandate required approvals exceeds %d", MaxMandateApprovals)
	}
	if mandate.RevocationEpoch == 0 {
		return fmt.Errorf("decision: mandate revocation epoch must be positive")
	}
	if mandate.IssuedAt <= 0 || mandate.ExpiresAt <= mandate.IssuedAt || mandate.ExpiresAt-mandate.IssuedAt > int64(MaxMandateTTL/time.Second) {
		return fmt.Errorf("decision: mandate validity window is invalid")
	}
	return nil
}

func (mandate Mandate) Canonical() ([]byte, error) {
	if err := mandate.Validate(); err != nil {
		return nil, err
	}
	actions := append([]string(nil), mandate.Actions...)
	resources := append([]string(nil), mandate.ResourcePrefixes...)
	constraints := append([]Constraint(nil), mandate.Constraints...)
	sort.Strings(actions)
	sort.Strings(resources)
	sort.Slice(constraints, func(left, right int) bool {
		if constraints[left].Key != constraints[right].Key {
			return constraints[left].Key < constraints[right].Key
		}
		if constraints[left].Operator != constraints[right].Operator {
			return constraints[left].Operator < constraints[right].Operator
		}
		return constraints[left].Value < constraints[right].Value
	})
	writer := canonicalWriter{}
	writer.string(MandateDomain)
	writer.u16(mandate.Version)
	writer.string(mandate.ID)
	writer.string(mandate.TenantID)
	writer.string(mandate.SubjectAgentID)
	writer.u16(uint16(len(actions)))
	for _, action := range actions {
		writer.string(action)
	}
	writer.u16(uint16(len(resources)))
	for _, resource := range resources {
		writer.string(resource)
	}
	writer.string(mandate.Audience)
	writer.string(mandate.Purpose)
	writer.u16(uint16(len(constraints)))
	for _, constraint := range constraints {
		writer.string(constraint.Key)
		writer.string(constraint.Operator)
		writer.string(constraint.Value)
	}
	writer.u16(mandate.RequiredApprovals)
	writer.u64(mandate.RevocationEpoch)
	writer.i64(mandate.IssuedAt)
	writer.i64(mandate.ExpiresAt)
	writer.string(mandate.KeyID)
	return writer.Bytes(), nil
}

// Hash is the stable identifier of the mandate's signed content. It excludes
// only the transport encoding of Signature: the issuer key ID and every
// delegated field are part of Canonical and therefore the hash.
func (mandate Mandate) Hash() (string, error) {
	canonical, err := mandate.Canonical()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func (mandate *Mandate) Sign(privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("decision: invalid mandate private key length")
	}
	canonical, err := mandate.Canonical()
	if err != nil {
		return err
	}
	mandate.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical))
	return nil
}

func (mandate Mandate) Verify(publicKey ed25519.PublicKey, now time.Time) error {
	canonical, err := mandate.Canonical()
	if err != nil {
		return err
	}
	if err := verifyFresh("mandate", mandate.IssuedAt, mandate.ExpiresAt, now); err != nil {
		return err
	}
	return verifySignature("mandate", publicKey, canonical, mandate.Signature)
}

// MandateStore supplies locally retained signed mandates. A missing mandate is
// a denial; the store can immediately revoke one by deleting it before an
// updated tenant trust bundle propagates.
type MandateStore interface {
	Mandate(context.Context, string, string) (Mandate, error)
}

// MandateKeyResolver resolves a current tenant-delegated mandate issuer key.
// Implementations normally also satisfy MandateStateResolver via the same
// root-pinned trust store.
type MandateKeyResolver interface {
	MandateKey(context.Context, string, string) (ed25519.PublicKey, error)
}

type MandateStateResolver interface {
	MinimumState(context.Context, string) (policyRevision, revocationEpoch uint64, err error)
}

// MandateCeiling composes mandate checks ahead of the deterministic policy
// ceiling. It cannot create authority: it requires a valid signed mandate,
// makes its restrictions part of the exact Intent, then delegates to Next.
type MandateCeiling struct {
	Store MandateStore
	Keys  MandateKeyResolver
	Next  AuthorityCeiling
	Now   func() time.Time
}

func (ceiling MandateCeiling) Check(ctx context.Context, intent Intent, result Decision) error {
	return ceiling.check(ctx, intent, result, nil)
}

// CheckDisclosure preserves the mandate's exact audience and purpose ceiling,
// then delegates typed disclosure conditions to the next local policy ceiling.
// It never falls back to Next.Check when a disclosure is present.
func (ceiling MandateCeiling) CheckDisclosure(ctx context.Context, intent Intent, result Decision, disclosure DisclosureBinding) error {
	if err := disclosure.VerifyIntent(intent); err != nil {
		return err
	}
	return ceiling.check(ctx, intent, result, &disclosure)
}

func (ceiling MandateCeiling) check(ctx context.Context, intent Intent, result Decision, disclosure *DisclosureBinding) error {
	if ceiling.Store == nil || ceiling.Keys == nil {
		return fmt.Errorf("decision: mandate ceiling is not initialized")
	}
	if intent.MandateID == "" {
		return fmt.Errorf("decision: mandate is required")
	}
	mandate, err := ceiling.Store.Mandate(ctx, intent.TenantID, intent.MandateID)
	if err != nil {
		return fmt.Errorf("decision: resolve mandate: %w", err)
	}
	now := time.Now()
	if ceiling.Now != nil {
		now = ceiling.Now()
	}
	issuer, err := ceiling.Keys.MandateKey(ctx, intent.TenantID, mandate.KeyID)
	if err != nil {
		return fmt.Errorf("decision: resolve mandate key: %w", err)
	}
	if err := mandate.Verify(issuer, now); err != nil {
		return err
	}
	if state, ok := ceiling.Keys.(MandateStateResolver); ok {
		_, revocationEpoch, stateErr := state.MinimumState(ctx, intent.TenantID)
		if stateErr != nil {
			return fmt.Errorf("decision: resolve mandate state: %w", stateErr)
		}
		if mandate.RevocationEpoch < revocationEpoch {
			return fmt.Errorf("decision: mandate revocation epoch %d is stale", mandate.RevocationEpoch)
		}
	}
	if err := mandate.Check(intent, result); err != nil {
		return err
	}
	if ceiling.Next != nil {
		if disclosure != nil {
			next, supported := ceiling.Next.(DisclosureCeiling)
			if !supported {
				return fmt.Errorf("decision: next mandate ceiling does not support disclosure binding")
			}
			return next.CheckDisclosure(ctx, intent, result, *disclosure)
		}
		return ceiling.Next.Check(ctx, intent, result)
	}
	return nil
}

// Check ensures that result cannot exceed the signed delegation. Denials and
// approval-required results are always narrower than an executable result;
// execution after a threshold approval must be represented as a fresh Intent
// and Decision that still satisfies the mandate's constraints.
func (mandate Mandate) Check(intent Intent, result Decision) error {
	if mandate.ID != intent.MandateID || mandate.TenantID != intent.TenantID || mandate.SubjectAgentID != intent.AgentID {
		return fmt.Errorf("decision: mandate binding mismatch")
	}
	if !mandateAllowsAction(mandate.Actions, intent.Action) {
		return fmt.Errorf("decision: mandate does not allow action %q", intent.Action)
	}
	if !mandateAllowsResource(mandate.ResourcePrefixes, intent.Resource) {
		return fmt.Errorf("decision: mandate does not allow resource %q", intent.Resource)
	}
	if intent.Audience == "" || (mandate.Audience != "*" && mandate.Audience != intent.Audience) {
		return fmt.Errorf("decision: mandate audience binding mismatch")
	}
	if mandate.Purpose != intent.Purpose {
		return fmt.Errorf("decision: mandate purpose binding mismatch")
	}
	switch result.Outcome {
	case Deny, ApprovalRequired:
		return nil
	case Allow, Constrain:
		if mandate.RequiredApprovals > 0 {
			return fmt.Errorf("decision: mandate requires %d approvals", mandate.RequiredApprovals)
		}
		if len(mandate.Constraints) == 0 {
			return nil
		}
		if result.Outcome != Constrain || !containsMandateConstraints(result.Constraints, mandate.Constraints) {
			return fmt.Errorf("decision: decision drops mandate constraints")
		}
		return nil
	default:
		return fmt.Errorf("decision: unsupported decision outcome %q", result.Outcome)
	}
}

func validMandateAction(value string) bool {
	if value == "*" {
		return true
	}
	if strings.HasSuffix(value, ".*") {
		return validAction(strings.TrimSuffix(value, ".*"))
	}
	return validAction(value)
}

func validMandateResource(value string) bool {
	return value == "*" || validateText("mandate resource", value, 1024, false) == nil
}

func validMandateAudience(value string) bool {
	return value == "*" || validateIdentifier("mandate audience", value) == nil
}

func mandateAllowsAction(patterns []string, action string) bool {
	for _, pattern := range patterns {
		if pattern == "*" || pattern == action || (strings.HasSuffix(pattern, ".*") && strings.HasPrefix(action, strings.TrimSuffix(pattern, "*"))) {
			return true
		}
	}
	return false
}

func mandateAllowsResource(prefixes []string, resource string) bool {
	for _, prefix := range prefixes {
		if prefix == "*" || strings.HasPrefix(resource, prefix) {
			return true
		}
	}
	return false
}

func containsMandateConstraints(got, required []Constraint) bool {
	for _, requiredConstraint := range required {
		found := false
		for _, candidate := range got {
			if candidate == requiredConstraint {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
