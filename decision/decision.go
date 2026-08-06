// SPDX-License-Identifier: AGPL-3.0-or-later

// Package decision defines the small signed object boundary shared by local
// enforcers and managed or self-hosted authorization providers.
package decision

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	SchemaVersion  uint16 = 1
	IntentDomain          = "pilot-intent-v1"
	DecisionDomain        = "pilot-decision-v1"

	MaxClockSkew   = time.Minute
	MaxIntentTTL   = 5 * time.Minute
	MaxDecisionTTL = 5 * time.Minute
)

type RiskClass string

const (
	RiskLow      RiskClass = "low"
	RiskMedium   RiskClass = "medium"
	RiskHigh     RiskClass = "high"
	RiskCritical RiskClass = "critical"
)

type Outcome string

const (
	Allow            Outcome = "allow"
	Deny             Outcome = "deny"
	Constrain        Outcome = "constrain"
	ApprovalRequired Outcome = "approval_required"
)

// Constraint narrows an allowed action. Enforcers must understand every
// returned operator; an unknown constraint is a denial, never an invitation to
// ignore it.
type Constraint struct {
	Key      string `json:"key"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

// Intent is the privacy-preserving authorization request. PayloadHash binds
// the actual action body without requiring the authority plane to retain it.
type Intent struct {
	Version  uint16 `json:"version"`
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	AgentID  string `json:"agent_id"`
	Action   string `json:"action"`
	Resource string `json:"resource"`
	// MandateID is optional for compatibility with the original v1 wire
	// profile. Enterprise mandate ceilings require it; when present it changes
	// the canonical signing domain so an unmandated Intent cannot be replayed
	// as a delegated one.
	MandateID   string    `json:"mandate_id,omitempty"`
	Audience    string    `json:"audience,omitempty"`
	Purpose     string    `json:"purpose,omitempty"`
	PayloadHash string    `json:"payload_hash"`
	Risk        RiskClass `json:"risk"`
	IssuedAt    int64     `json:"issued_at"`
	ExpiresAt   int64     `json:"expires_at"`
	Nonce       string    `json:"nonce"`
	KeyID       string    `json:"key_id"`
	Signature   string    `json:"signature"`
}

// Decision is an issuer-signed answer tied to one exact Intent hash, tenant,
// and agent. PolicyRevision and RevocationEpoch make stale-state behavior
// observable at the enforcement point.
type Decision struct {
	Version         uint16       `json:"version"`
	ID              string       `json:"id"`
	IntentHash      string       `json:"intent_hash"`
	TenantID        string       `json:"tenant_id"`
	AgentID         string       `json:"agent_id"`
	Outcome         Outcome      `json:"outcome"`
	Reasons         []string     `json:"reasons,omitempty"`
	Constraints     []Constraint `json:"constraints,omitempty"`
	PolicyRevision  uint64       `json:"policy_revision"`
	RevocationEpoch uint64       `json:"revocation_epoch"`
	ProviderID      string       `json:"provider_id"`
	IssuedAt        int64        `json:"issued_at"`
	ExpiresAt       int64        `json:"expires_at"`
	KeyID           string       `json:"key_id"`
	Signature       string       `json:"signature"`
}

// Authorizer is the complete provider hook. A deterministic local evaluator,
// managed policy service, or semantic/LLM evaluator implements the same one
// method. Provider transport and billing are deliberately outside this API.
type Authorizer interface {
	Authorize(context.Context, Intent) (Decision, error)
}

// DisclosureAuthorizer is an explicit extension point for evaluators that can
// inspect typed, hash-bound disclosure metadata. A caller must never fall back
// to Authorize when a DisclosureBinding is present: doing so would silently
// ignore labels or residency that a required profile expects to govern.
type DisclosureAuthorizer interface {
	AuthorizeDisclosure(context.Context, Intent, DisclosureBinding) (Decision, error)
}

// FederatedContentAuthorizer is implemented only by Pilot's hosted exchange
// evaluation path. It receives the exact body after the caller's signed Intent
// and hash-bound DisclosureBinding have been verified. Implementations may
// preserve or narrow authority; content can never be used to expand a signed
// deterministic result.
type FederatedContentAuthorizer interface {
	AuthorizeFederatedContent(context.Context, Intent, FederatedContent) (Decision, error)
}

// DisclosureContentInspector is a receiver-local DLP hook. It receives the
// exact bounded payload reader only after a governed transport has verified
// its Intent, Decision, and (when present) DisclosureBinding. Implementations
// must not treat a successful inspection as authority to expand a Decision;
// they can only reject the delivery. The central authority never invokes this
// interface, keeping ordinary peer payloads out of the decision plane.
type DisclosureContentInspector interface {
	InspectDisclosureContent(ctx context.Context, intent Intent, disclosure *DisclosureBinding, contentType, filename string, content io.Reader) error
}

// HashPayload returns the opaque payload binding placed in Intent.PayloadHash.
func HashPayload(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// NewNonce returns a 128-bit random lowercase-hex nonce.
func NewNonce() (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("decision: generate nonce: %w", err)
	}
	return hex.EncodeToString(nonce[:]), nil
}

func (i Intent) Validate() error {
	if i.Version != SchemaVersion {
		return fmt.Errorf("decision: intent version %d is unsupported", i.Version)
	}
	for name, value := range map[string]string{
		"id": i.ID, "tenant_id": i.TenantID, "agent_id": i.AgentID, "key_id": i.KeyID,
	} {
		if err := validateIdentifier(name, value); err != nil {
			return err
		}
	}
	if !validAction(i.Action) {
		return fmt.Errorf("decision: invalid action %q", i.Action)
	}
	if err := validateText("resource", i.Resource, 1024, false); err != nil {
		return err
	}
	if i.MandateID != "" {
		if err := validateIdentifier("mandate_id", i.MandateID); err != nil {
			return err
		}
	}
	if err := validateText("audience", i.Audience, 256, true); err != nil {
		return err
	}
	if err := validateText("purpose", i.Purpose, 256, true); err != nil {
		return err
	}
	if !lowerHex(i.PayloadHash, 64) {
		return fmt.Errorf("decision: payload_hash must be 64 lowercase hex characters")
	}
	switch i.Risk {
	case RiskLow, RiskMedium, RiskHigh, RiskCritical:
	default:
		return fmt.Errorf("decision: invalid risk class %q", i.Risk)
	}
	if !lowerHex(i.Nonce, 32) {
		return fmt.Errorf("decision: nonce must be 32 lowercase hex characters")
	}
	if err := validateWindow("intent", i.IssuedAt, i.ExpiresAt, MaxIntentTTL); err != nil {
		return err
	}
	return nil
}

func (d Decision) Validate() error {
	if d.Version != SchemaVersion {
		return fmt.Errorf("decision: decision version %d is unsupported", d.Version)
	}
	for name, value := range map[string]string{
		"id": d.ID, "tenant_id": d.TenantID, "agent_id": d.AgentID,
		"provider_id": d.ProviderID, "key_id": d.KeyID,
	} {
		if err := validateIdentifier(name, value); err != nil {
			return err
		}
	}
	if !lowerHex(d.IntentHash, 64) {
		return fmt.Errorf("decision: intent_hash must be 64 lowercase hex characters")
	}
	switch d.Outcome {
	case Allow, Deny, Constrain, ApprovalRequired:
	default:
		return fmt.Errorf("decision: invalid outcome %q", d.Outcome)
	}
	if len(d.Reasons) > 16 {
		return fmt.Errorf("decision: at most 16 reasons are allowed")
	}
	for _, reason := range d.Reasons {
		if err := validateText("reason", reason, 256, false); err != nil {
			return err
		}
	}
	if len(d.Constraints) > 32 {
		return fmt.Errorf("decision: at most 32 constraints are allowed")
	}
	seen := make(map[string]struct{}, len(d.Constraints))
	for _, constraint := range d.Constraints {
		if err := validateConstraint(constraint); err != nil {
			return err
		}
		identity := constraint.Key + "\x00" + constraint.Operator
		if _, exists := seen[identity]; exists {
			return fmt.Errorf("decision: duplicate constraint %q/%q", constraint.Key, constraint.Operator)
		}
		seen[identity] = struct{}{}
	}
	if d.Outcome == Constrain && len(d.Constraints) == 0 {
		return fmt.Errorf("decision: constrain outcome requires at least one constraint")
	}
	if d.Outcome != Constrain && len(d.Constraints) != 0 {
		return fmt.Errorf("decision: constraints require the constrain outcome")
	}
	return validateWindow("decision", d.IssuedAt, d.ExpiresAt, MaxDecisionTTL)
}

func (i Intent) Canonical() ([]byte, error) {
	if err := i.Validate(); err != nil {
		return nil, err
	}
	w := canonicalWriter{}
	if i.MandateID != "" || i.Audience != "" || i.Purpose != "" {
		w.string(IntentDomain + "/delegated")
	} else {
		w.string(IntentDomain)
	}
	w.u16(i.Version)
	w.string(i.ID)
	w.string(i.TenantID)
	w.string(i.AgentID)
	w.string(i.Action)
	w.string(i.Resource)
	w.string(i.PayloadHash)
	w.string(string(i.Risk))
	w.i64(i.IssuedAt)
	w.i64(i.ExpiresAt)
	w.string(i.Nonce)
	w.string(i.KeyID)
	if i.MandateID != "" || i.Audience != "" || i.Purpose != "" {
		w.string(i.MandateID)
		w.string(i.Audience)
		w.string(i.Purpose)
	}
	return w.Bytes(), nil
}

func (d Decision) Canonical() ([]byte, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	w := canonicalWriter{}
	w.string(DecisionDomain)
	w.u16(d.Version)
	w.string(d.ID)
	w.string(d.IntentHash)
	w.string(d.TenantID)
	w.string(d.AgentID)
	w.string(string(d.Outcome))
	w.u16(uint16(len(d.Reasons)))
	for _, reason := range d.Reasons {
		w.string(reason)
	}
	constraints := append([]Constraint(nil), d.Constraints...)
	sort.Slice(constraints, func(a, b int) bool {
		if constraints[a].Key != constraints[b].Key {
			return constraints[a].Key < constraints[b].Key
		}
		if constraints[a].Operator != constraints[b].Operator {
			return constraints[a].Operator < constraints[b].Operator
		}
		return constraints[a].Value < constraints[b].Value
	})
	w.u16(uint16(len(constraints)))
	for _, constraint := range constraints {
		w.string(constraint.Key)
		w.string(constraint.Operator)
		w.string(constraint.Value)
	}
	w.u64(d.PolicyRevision)
	w.u64(d.RevocationEpoch)
	w.string(d.ProviderID)
	w.i64(d.IssuedAt)
	w.i64(d.ExpiresAt)
	w.string(d.KeyID)
	return w.Bytes(), nil
}

func (i Intent) Hash() (string, error) { return hashCanonical(i.Canonical()) }

func (d Decision) Hash() (string, error) { return hashCanonical(d.Canonical()) }

func (i *Intent) Sign(privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("decision: invalid intent private key length")
	}
	return i.SignWith(func(message []byte) ([]byte, error) {
		return ed25519.Sign(privateKey, message), nil
	})
}

func (i *Intent) SignWith(signer func([]byte) ([]byte, error)) error {
	if signer == nil {
		return fmt.Errorf("decision: intent signer is required")
	}
	canonical, err := i.Canonical()
	if err != nil {
		return err
	}
	signature, err := signer(canonical)
	if err != nil {
		return fmt.Errorf("decision: sign intent: %w", err)
	}
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("decision: intent signer returned invalid signature length")
	}
	i.Signature = base64.StdEncoding.EncodeToString(signature)
	return nil
}

func (d *Decision) Sign(privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("decision: invalid decision private key length")
	}
	return d.SignWith(func(message []byte) ([]byte, error) {
		return ed25519.Sign(privateKey, message), nil
	})
}

// SignWith signs the canonical decision using a caller-supplied Ed25519
// operation. It lets a hardware-backed or remote key keep private material
// outside the authority process while preserving the wire signature format.
func (d *Decision) SignWith(signer func([]byte) ([]byte, error)) error {
	if signer == nil {
		return fmt.Errorf("decision: decision signer is required")
	}
	canonical, err := d.Canonical()
	if err != nil {
		return err
	}
	signature, err := signer(canonical)
	if err != nil {
		return fmt.Errorf("decision: sign decision: %w", err)
	}
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("decision: decision signer returned invalid signature length")
	}
	d.Signature = base64.StdEncoding.EncodeToString(signature)
	return nil
}

func (i Intent) Verify(publicKey ed25519.PublicKey, now time.Time) error {
	canonical, err := i.Canonical()
	if err != nil {
		return err
	}
	if err := verifyFresh("intent", i.IssuedAt, i.ExpiresAt, now); err != nil {
		return err
	}
	return verifySignature("intent", publicKey, canonical, i.Signature)
}

func (d Decision) Verify(publicKey ed25519.PublicKey, now time.Time) error {
	canonical, err := d.Canonical()
	if err != nil {
		return err
	}
	if err := verifyFresh("decision", d.IssuedAt, d.ExpiresAt, now); err != nil {
		return err
	}
	return verifySignature("decision", publicKey, canonical, d.Signature)
}

// VerifyFor proves that d is a valid answer for this exact intent. This is the
// enforcement-point check; verifying the decision signature alone is not
// sufficient because a valid answer must not be replayed across actions,
// tenants, agents, or wider time windows.
func (d Decision) VerifyFor(intent Intent, publicKey ed25519.PublicKey, now time.Time) error {
	if err := d.Verify(publicKey, now); err != nil {
		return err
	}
	intentHash, err := intent.Hash()
	if err != nil {
		return err
	}
	if d.IntentHash != intentHash {
		return fmt.Errorf("decision: decision is bound to a different intent")
	}
	if d.TenantID != intent.TenantID || d.AgentID != intent.AgentID {
		return fmt.Errorf("decision: tenant or agent binding mismatch")
	}
	if d.ExpiresAt > intent.ExpiresAt {
		return fmt.Errorf("decision: decision expiry expands intent authority")
	}
	if d.IssuedAt < intent.IssuedAt-int64(MaxClockSkew/time.Second) {
		return fmt.Errorf("decision: decision predates intent")
	}
	return nil
}

func hashCanonical(canonical []byte, err error) (string, error) {
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func verifySignature(kind string, publicKey ed25519.PublicKey, canonical []byte, encoded string) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("decision: invalid %s public key length", kind)
	}
	signature, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("decision: invalid %s signature encoding", kind)
	}
	if !ed25519.Verify(publicKey, canonical, signature) {
		return fmt.Errorf("decision: %s signature verification failed", kind)
	}
	return nil
}

func verifyFresh(kind string, issuedAt, expiresAt int64, now time.Time) error {
	nowUnix := now.Unix()
	if issuedAt > nowUnix+int64(MaxClockSkew/time.Second) {
		return fmt.Errorf("decision: %s is not yet valid", kind)
	}
	if expiresAt < nowUnix {
		return fmt.Errorf("decision: %s is expired", kind)
	}
	return nil
}

func validateWindow(kind string, issuedAt, expiresAt int64, maxTTL time.Duration) error {
	if issuedAt <= 0 || expiresAt <= issuedAt {
		return fmt.Errorf("decision: invalid %s validity window", kind)
	}
	if expiresAt-issuedAt > int64(maxTTL/time.Second) {
		return fmt.Errorf("decision: %s validity exceeds %s", kind, maxTTL)
	}
	return nil
}

func validateConstraint(c Constraint) error {
	if err := validateIdentifier("constraint key", c.Key); err != nil {
		return err
	}
	switch c.Operator {
	case "eq", "max", "min", "one_of", "redact", "require":
	default:
		return fmt.Errorf("decision: unsupported constraint operator %q", c.Operator)
	}
	return validateText("constraint value", c.Value, 1024, true)
}

func validateIdentifier(name, value string) error {
	if len(value) == 0 || len(value) > 128 || !utf8.ValidString(value) {
		return fmt.Errorf("decision: invalid %s", name)
	}
	for index, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			(index > 0 && strings.ContainsRune("._:/@-", r)) {
			continue
		}
		return fmt.Errorf("decision: invalid %s", name)
	}
	return nil
}

func validAction(value string) bool {
	if len(value) == 0 || len(value) > 128 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, r := range value[1:] {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || strings.ContainsRune("._-", r) {
			continue
		}
		return false
	}
	return true
}

func validateText(name, value string, maxBytes int, allowEmpty bool) error {
	if (!allowEmpty && value == "") || len(value) > maxBytes || !utf8.ValidString(value) {
		return fmt.Errorf("decision: invalid %s", name)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("decision: %s contains control characters", name)
		}
	}
	return nil
}

func lowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, c := range value {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

type canonicalWriter struct{ bytes.Buffer }

func (w *canonicalWriter) string(value string) {
	_ = binary.Write(&w.Buffer, binary.BigEndian, uint32(len(value)))
	_, _ = w.WriteString(value)
}

func (w *canonicalWriter) u16(value uint16) {
	_ = binary.Write(&w.Buffer, binary.BigEndian, value)
}

func (w *canonicalWriter) u64(value uint64) {
	_ = binary.Write(&w.Buffer, binary.BigEndian, value)
}

func (w *canonicalWriter) i64(value int64) {
	_ = binary.Write(&w.Buffer, binary.BigEndian, value)
}
