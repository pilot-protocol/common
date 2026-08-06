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
	"time"
)

const (
	MandateBundleDomain = "pilot-mandate-bundle-v1"
	MaxMandateBundleTTL = 24 * time.Hour
	MaxBundleMandates   = 256
)

// MandateBundle is the revisioned, signed distribution snapshot for one
// workload. A newer valid bundle replaces the whole prior set. Consequently,
// a mandate that is absent from a higher revision is revoked at the next local
// refresh, without relying on an unsafe mutable cache-delete signal.
//
// The contained Mandates remain independently signed and verifiable. The
// bundle signature binds their canonical hashes, agent scope, revision, and
// revocation epoch so an authority endpoint cannot splice valid mandates from
// different snapshots or replay an older set after a newer one is installed.
type MandateBundle struct {
	Version         uint16    `json:"version"`
	TenantID        string    `json:"tenant_id"`
	SubjectAgentID  string    `json:"subject_agent_id"`
	Revision        uint64    `json:"revision"`
	RevocationEpoch uint64    `json:"revocation_epoch"`
	Mandates        []Mandate `json:"mandates"`
	IssuedAt        int64     `json:"issued_at"`
	ExpiresAt       int64     `json:"expires_at"`
	KeyID           string    `json:"key_id"`
	Signature       string    `json:"signature"`
}

func (bundle MandateBundle) Validate() error {
	if bundle.Version != SchemaVersion {
		return fmt.Errorf("decision: mandate bundle version %d is unsupported", bundle.Version)
	}
	for name, value := range map[string]string{
		"tenant_id": bundle.TenantID, "subject_agent_id": bundle.SubjectAgentID, "key_id": bundle.KeyID,
	} {
		if err := validateIdentifier(name, value); err != nil {
			return err
		}
	}
	if bundle.Revision == 0 || bundle.RevocationEpoch == 0 {
		return fmt.Errorf("decision: mandate bundle revision and revocation epoch must be positive")
	}
	if len(bundle.Mandates) > MaxBundleMandates {
		return fmt.Errorf("decision: mandate bundle has more than %d mandates", MaxBundleMandates)
	}
	if bundle.IssuedAt <= 0 || bundle.ExpiresAt <= bundle.IssuedAt || bundle.ExpiresAt-bundle.IssuedAt > int64(MaxMandateBundleTTL/time.Second) {
		return fmt.Errorf("decision: mandate bundle validity window is invalid")
	}
	seen := make(map[string]struct{}, len(bundle.Mandates))
	for _, mandate := range bundle.Mandates {
		if err := mandate.Validate(); err != nil {
			return fmt.Errorf("decision: invalid bundled mandate: %w", err)
		}
		if mandate.TenantID != bundle.TenantID || mandate.SubjectAgentID != bundle.SubjectAgentID {
			return fmt.Errorf("decision: bundled mandate scope does not match bundle")
		}
		if mandate.RevocationEpoch < bundle.RevocationEpoch {
			return fmt.Errorf("decision: bundled mandate %q is below bundle revocation epoch", mandate.ID)
		}
		if _, found := seen[mandate.ID]; found {
			return fmt.Errorf("decision: duplicate bundled mandate %q", mandate.ID)
		}
		seen[mandate.ID] = struct{}{}
	}
	return nil
}

func (bundle MandateBundle) Canonical() ([]byte, error) {
	if err := bundle.Validate(); err != nil {
		return nil, err
	}
	mandates := append([]Mandate(nil), bundle.Mandates...)
	sort.Slice(mandates, func(left, right int) bool { return mandates[left].ID < mandates[right].ID })
	writer := canonicalWriter{}
	writer.string(MandateBundleDomain)
	writer.u16(bundle.Version)
	writer.string(bundle.TenantID)
	writer.string(bundle.SubjectAgentID)
	writer.u64(bundle.Revision)
	writer.u64(bundle.RevocationEpoch)
	writer.u16(uint16(len(mandates)))
	for _, mandate := range mandates {
		hash, err := mandate.Hash()
		if err != nil {
			return nil, err
		}
		writer.string(mandate.ID)
		writer.string(hash)
	}
	writer.i64(bundle.IssuedAt)
	writer.i64(bundle.ExpiresAt)
	writer.string(bundle.KeyID)
	return writer.Bytes(), nil
}

// Hash identifies the exact revisioned delegation snapshot for idempotent
// publication and durable anti-rollback records.
func (bundle MandateBundle) Hash() (string, error) {
	canonical, err := bundle.Canonical()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func (bundle *MandateBundle) Sign(privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("decision: invalid mandate bundle private key length")
	}
	canonical, err := bundle.Canonical()
	if err != nil {
		return err
	}
	bundle.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical))
	return nil
}

// Verify verifies the snapshot issuer and every contained mandate at the same
// point in time. A caller must still compare Revision to its durable local
// floor before replacing an installed snapshot.
func (bundle MandateBundle) Verify(ctx context.Context, publicKey ed25519.PublicKey, mandateKey MandateKeyResolver, now time.Time) error {
	canonical, err := bundle.Canonical()
	if err != nil {
		return err
	}
	if err := verifyFresh("mandate bundle", bundle.IssuedAt, bundle.ExpiresAt, now); err != nil {
		return err
	}
	if err := verifySignature("mandate bundle", publicKey, canonical, bundle.Signature); err != nil {
		return err
	}
	if mandateKey == nil {
		return fmt.Errorf("decision: mandate bundle key resolver is required")
	}
	for _, mandate := range bundle.Mandates {
		issuer, keyErr := mandateKey.MandateKey(ctx, bundle.TenantID, mandate.KeyID)
		if keyErr != nil {
			return fmt.Errorf("decision: resolve bundled mandate %q issuer: %w", mandate.ID, keyErr)
		}
		if verifyErr := mandate.Verify(issuer, now); verifyErr != nil {
			return fmt.Errorf("decision: verify bundled mandate %q: %w", mandate.ID, verifyErr)
		}
	}
	return nil
}
