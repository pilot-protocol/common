// SPDX-License-Identifier: AGPL-3.0-or-later

// Package badgeverify defines the canonical wire format for a Pilot
// "verified address" badge and an offline verifier for it.
//
// A badge is a detached Ed25519-signed credential, bound to a single
// node_id, that asserts the address was verified through an external
// identity provider (GitHub / Google / WorkOS). It deliberately carries
// NO raw external identity (no GitHub login, no email) — only which
// provider vouched and when. An app certifies a badge is genuine by
// verifying the issuer signature against a pinned public key, entirely
// offline: no network round-trip and no trust in the registry that
// served the badge.
//
// THE BINDING RULE (read this before using Verify):
//
// A badge is public — anyone can fetch any node's badge. A badge is only
// meaningful when checked against the node_id that the secure/handshake
// layer has *cryptographically authenticated* for the connection. Always
// confirm Badge.NodeID equals the authenticated peer's node_id, or use
// VerifyForNode which does it for you. Verifying the signature alone lets
// an attacker replay another node's valid badge.
package badgeverify

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Version is the canonical-format version tag carried in every badge. A
// future incompatible format change bumps this and adds a parser branch.
const Version = "v1"

// Domain-separation prefixes. Every credential type the issuer signs gets
// a distinct, unspoofable prefix as the first field of its canonical
// signed bytes, so a signature over one type can NEVER validate as
// another (a badge cannot be replayed as a recovery authorization). Each
// parser rejects a wrong prefix. This is the primary cross-statement
// defense; the two-key split (badge kid vs recovery kid) is layered on top.
const (
	prefixBadge   = "pilotbadge"
	prefixEnroll  = "pilotenroll"
	prefixRecover = "pilotrecover"
)

// keyringB64 maps key-id -> base64 Ed25519 public key, encoded as
// comma-separated "kid=base64" entries. It holds the ONLINE issuer keys
// that sign badges and enrollments. A statement's Kid selects which key
// verifies it, so a key can be rotated without invalidating already-issued
// credentials: ship the new key alongside the old, issue under the new
// kid, retire the old once its credentials expire.
//
// The compiled-in default pins the production badge issuer key (kid bdg-v1),
// whose private half lives only in Cloud KMS (EC_SIGN_ED25519, key ring
// pilot-badges/badge-issuer). The public key is non-secret by design — it is
// meant to be embedded in every verifier. Overridable at build time for
// rotation:
//
//	-ldflags "-X github.com/pilot-protocol/common/badgeverify.keyringB64=bdg-v2=<b64>"
var keyringB64 = "bdg-v1=Y2jjSAS+J6LVXAguY4P51vMGhHl7qgy5qBJZGS0Cmms="

// recoveryKeyringB64 is a SEPARATE pinned keyring holding only the COLD
// recovery-authority keys, which sign nothing but recovery authorizations.
// Recovery statements verify against this keyring exclusively — so even a
// total compromise of the online badge keyring above cannot forge a
// recovery (and thus cannot seize any address). The default pins rec-v1,
// whose private half lives only in Cloud KMS (key ring pilot-recovery /
// recovery-authority, Ed25519, non-exportable) with signing locked to the
// sole custodian. Overridable at build time for rotation:
//
//	-ldflags "-X github.com/pilot-protocol/common/badgeverify.recoveryKeyringB64=rec-v2=<b64>"
var recoveryKeyringB64 = "rec-v1=EGQ7F/NGzCIPekBo1jx+eUQUfOBFQU/hyhiZd3xumTY="

var (
	// ErrNoKey is returned when no pinned key matches the badge's kid (or
	// the keyring is malformed). Fail-closed: with no trust anchor,
	// nothing verifies.
	ErrNoKey = errors.New("badgeverify: no pinned issuer key for badge kid")
	// ErrBadSignature is returned when the signature does not verify.
	ErrBadSignature = errors.New("badgeverify: badge signature verification failed")
	// ErrMalformed is returned when the badge string is not well-formed.
	ErrMalformed = errors.New("badgeverify: malformed badge")
	// ErrExpired is returned when the badge's exp is in the past.
	ErrExpired = errors.New("badgeverify: badge expired")
	// ErrNodeMismatch is returned by VerifyForNode when the badge is for
	// a different node than the authenticated peer.
	ErrNodeMismatch = errors.New("badgeverify: badge node_id does not match peer")
)

// Badge is the decoded, structured form of a verified-address credential.
type Badge struct {
	NodeID     uint32 // the address this badge is bound to
	Provider   string // identity authority that vouched: "github" | "google" | "workos"
	VerifiedAt int64  // unix seconds, coarsened to day granularity at issue time
	Exp        int64  // unix seconds; 0 means no expiry
	Kid        string // issuer key-id that signed this badge (selects the verify key)
	Subject    string // OPTIONAL public label (Tier 1); empty for Tier 0 (provider-only)
}

// noColon rejects values that would break the ':'-delimited canonical
// encoding. provider/kid/subject are constrained; everything else is
// numeric.
func noColon(field, v string) error {
	if strings.ContainsRune(v, ':') {
		return fmt.Errorf("%w: %s must not contain ':'", ErrMalformed, field)
	}
	return nil
}

// Canonical returns the exact byte string that is signed and that travels
// on the wire as the "badge" field. The issuer signs these bytes; the
// verifier checks the signature over the bytes it received and only then
// trusts the parsed fields.
//
// Layout: pilotbadge:v1:<node_id>:<provider>:<verified_at>:<exp>:<kid>:<subject>
func Canonical(b Badge) (string, error) {
	if b.Provider == "" {
		return "", fmt.Errorf("%w: provider is required", ErrMalformed)
	}
	if b.Kid == "" {
		return "", fmt.Errorf("%w: kid is required", ErrMalformed)
	}
	for _, c := range []struct{ name, v string }{
		{"provider", b.Provider}, {"kid", b.Kid}, {"subject", b.Subject},
	} {
		if err := noColon(c.name, c.v); err != nil {
			return "", err
		}
	}
	return fmt.Sprintf("%s:%s:%d:%s:%d:%d:%s:%s",
		prefixBadge, Version, b.NodeID, b.Provider, b.VerifiedAt, b.Exp, b.Kid, b.Subject), nil
}

// Parse decodes a canonical badge string WITHOUT verifying its signature.
// Use Verify/VerifyForNode for anything trust-bearing.
func Parse(s string) (Badge, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 8 {
		return Badge{}, fmt.Errorf("%w: want 8 fields, got %d", ErrMalformed, len(parts))
	}
	if parts[0] != prefixBadge {
		return Badge{}, fmt.Errorf("%w: bad prefix %q", ErrMalformed, parts[0])
	}
	if parts[1] != Version {
		return Badge{}, fmt.Errorf("%w: unsupported version %q", ErrMalformed, parts[1])
	}
	nodeID, err := strconv.ParseUint(parts[2], 10, 32)
	if err != nil {
		return Badge{}, fmt.Errorf("%w: node_id: %v", ErrMalformed, err)
	}
	verifiedAt, err := strconv.ParseInt(parts[4], 10, 64)
	if err != nil {
		return Badge{}, fmt.Errorf("%w: verified_at: %v", ErrMalformed, err)
	}
	exp, err := strconv.ParseInt(parts[5], 10, 64)
	if err != nil {
		return Badge{}, fmt.Errorf("%w: exp: %v", ErrMalformed, err)
	}
	if parts[3] == "" {
		return Badge{}, fmt.Errorf("%w: provider is required", ErrMalformed)
	}
	if parts[6] == "" {
		return Badge{}, fmt.Errorf("%w: kid is required", ErrMalformed)
	}
	return Badge{
		NodeID:     uint32(nodeID),
		Provider:   parts[3],
		VerifiedAt: verifiedAt,
		Exp:        exp,
		Kid:        parts[6],
		Subject:    parts[7],
	}, nil
}

// isAllZero reports whether b is entirely zero bytes. The compiled-in
// placeholder key is all zeros; an all-zero Ed25519 public key is also a
// low-order point that can verify crafted signatures, so we treat it as
// "no key" and fail closed. This guards against shipping a binary whose
// -ldflags issuer-key override was forgotten.
func isAllZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// lookupKey returns the pinned public key for kid within the given keyring
// string, or nil if absent/malformed/all-zero (fail-closed).
func lookupKey(keyring, kid string) ed25519.PublicKey {
	for _, entry := range strings.Split(keyring, ",") {
		entry = strings.TrimSpace(entry)
		k, v, ok := strings.Cut(entry, "=")
		if !ok || k != kid {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(v)
		if err != nil || len(raw) != ed25519.PublicKeySize || isAllZero(raw) {
			return nil
		}
		return ed25519.PublicKey(raw)
	}
	return nil
}

// keyFor selects an online badge/enrollment key; recoveryKeyFor selects a
// cold recovery-authority key. The two keyrings never overlap, which is
// what enforces the two-key split.
func keyFor(kid string) ed25519.PublicKey         { return lookupKey(keyringB64, kid) }
func recoveryKeyFor(kid string) ed25519.PublicKey { return lookupKey(recoveryKeyringB64, kid) }

// Verify parses badgeStr, then checks that sigB64 is a valid Ed25519
// signature over the EXACT received bytes, made with the pinned issuer
// key named by the badge's kid, and that the badge has not expired.
//
// It does NOT check the binding to a node — see the package doc and
// VerifyForNode. Callers that already hold the authenticated peer node_id
// should prefer VerifyForNode.
func Verify(badgeStr, sigB64 string) (Badge, error) {
	return verifyAt(badgeStr, sigB64, time.Now())
}

// VerifyForNode is Verify plus the binding rule: it additionally requires
// the badge to be bound to peerNodeID (the node_id the secure/handshake
// layer authenticated for this connection). This is the safe entry point
// for apps.
func VerifyForNode(badgeStr, sigB64 string, peerNodeID uint32) (Badge, error) {
	b, err := verifyAt(badgeStr, sigB64, time.Now())
	if err != nil {
		return b, err
	}
	if b.NodeID != peerNodeID {
		return b, fmt.Errorf("%w: badge=%d peer=%d", ErrNodeMismatch, b.NodeID, peerNodeID)
	}
	return b, nil
}

func verifyAt(badgeStr, sigB64 string, now time.Time) (Badge, error) {
	b, err := Parse(badgeStr)
	if err != nil {
		return Badge{}, err
	}
	if err := verifyDetached(badgeStr, sigB64, b.Kid); err != nil {
		return b, err
	}
	if b.Exp != 0 && now.Unix() > b.Exp {
		return b, fmt.Errorf("%w: exp=%d now=%d", ErrExpired, b.Exp, now.Unix())
	}
	return b, nil
}

// verifyDetached is the signature-verification path for badges and
// enrollments (online keyring). verifyDetachedRecovery is the equivalent
// for recovery authorizations (cold keyring). Both go through verifyKeyed,
// the single auditable place where fail-closed key selection and the
// length/verify checks live. signed is the exact canonical string.
func verifyDetached(signed, sigB64, kid string) error {
	return verifyKeyed(keyFor, signed, sigB64, kid)
}

func verifyDetachedRecovery(signed, sigB64, kid string) error {
	return verifyKeyed(recoveryKeyFor, signed, sigB64, kid)
}

func verifyKeyed(lookup func(string) ed25519.PublicKey, signed, sigB64, kid string) error {
	pk := lookup(kid)
	if pk == nil {
		return fmt.Errorf("%w: kid=%q", ErrNoKey, kid)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("%w: signature is not valid base64", ErrBadSignature)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: wrong signature length %d (want %d)", ErrBadSignature, len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(pk, []byte(signed), sig) {
		return ErrBadSignature
	}
	return nil
}
