// SPDX-License-Identifier: AGPL-3.0-or-later

package reqsig

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// Verdict is the registry's signed answer to a verification request. It
// binds the verified envelope (by hash) to the registry's assessment so a
// consumer can cache the verdict, forward it as proof, or check it offline
// without trusting the transport it arrived over.
//
// Canonical form:
//
//	pilot-verdict-v1|envhash|aaaaaaaaaaaa|v|o|m|last_seen|keygen|verified_at
//
//	envhash      64 lowercase hex, sha256 of the canonical envelope string
//	aaaa…        12 lowercase hex, the address the verdict is about
//	v/o/m        single chars '0'/'1': valid, online, network_member
//	last_seen    canonical decimal unix seconds (0 when unknown/invalid)
//	keygen       canonical decimal key generation (rotate count; 0 unknown)
//	verified_at  canonical decimal unix seconds of the verification
//
// The verdict-issuer keyring follows the badgeverify pattern: kid→pubkey
// entries baked at build time, overridable via
//
//	-ldflags "-X github.com/pilot-protocol/common/reqsig.verdictKeyringB64=vfy-v1=<b64pub>"
//
// Unknown kid or empty keyring fails closed.
type Verdict struct {
	EnvHash       string // sha256 hex of the canonical envelope
	Network       uint16
	Node          uint32
	Valid         bool
	Online        bool
	NetworkMember bool
	LastSeenUnix  int64
	KeyGeneration int64
	VerifiedAt    int64 // unix seconds
}

// VerdictDomain is the verdict domain-separation prefix.
const VerdictDomain = "pilot-verdict-v1"

const verdictFieldCount = 9

// verdictKeyringB64 holds comma-separated kid=base64pubkey entries for
// verdict issuers. Empty by default: offline verdict verification is
// unavailable unless a keyring is baked at build time or supplied via
// VerifyVerdictWithKey. Fail-closed, same as badgeverify.
var verdictKeyringB64 = ""

// HashEnvelope returns the canonical envelope-hash field for a canonical
// envelope string.
func HashEnvelope(canonical string) string {
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}

// Canonical validates the verdict fields and returns the canonical string.
func (v Verdict) Canonical() (string, error) {
	if !isLowerHex(v.EnvHash, 64) {
		return "", fmt.Errorf("reqsig: verdict env hash must be 64 lowercase hex chars")
	}
	if v.LastSeenUnix < 0 || v.KeyGeneration < 0 || v.VerifiedAt < 0 {
		return "", fmt.Errorf("reqsig: verdict fields must be non-negative")
	}
	return VerdictDomain + "|" +
		v.EnvHash + "|" +
		addrHex(v.Network, v.Node) + "|" +
		boolChar(v.Valid) + "|" +
		boolChar(v.Online) + "|" +
		boolChar(v.NetworkMember) + "|" +
		strconv.FormatInt(v.LastSeenUnix, 10) + "|" +
		strconv.FormatInt(v.KeyGeneration, 10) + "|" +
		strconv.FormatInt(v.VerifiedAt, 10), nil
}

// ParseVerdict parses and validates a canonical verdict string.
func ParseVerdict(s string) (Verdict, error) {
	parts := strings.Split(s, "|")
	if len(parts) != verdictFieldCount {
		return Verdict{}, fmt.Errorf("reqsig: verdict wants %d fields, got %d", verdictFieldCount, len(parts))
	}
	if parts[0] != VerdictDomain {
		return Verdict{}, fmt.Errorf("reqsig: bad verdict domain %q", parts[0])
	}
	network, node, err := parseAddrHex(parts[2])
	if err != nil {
		return Verdict{}, err
	}
	valid, err := parseBoolChar(parts[3])
	if err != nil {
		return Verdict{}, err
	}
	online, err := parseBoolChar(parts[4])
	if err != nil {
		return Verdict{}, err
	}
	member, err := parseBoolChar(parts[5])
	if err != nil {
		return Verdict{}, err
	}
	lastSeen, err := parseCanonicalDecimal(parts[6])
	if err != nil {
		return Verdict{}, fmt.Errorf("reqsig: verdict last_seen: %w", err)
	}
	keyGen, err := parseCanonicalDecimal(parts[7])
	if err != nil {
		return Verdict{}, fmt.Errorf("reqsig: verdict key generation: %w", err)
	}
	verifiedAt, err := parseCanonicalDecimal(parts[8])
	if err != nil {
		return Verdict{}, fmt.Errorf("reqsig: verdict verified_at: %w", err)
	}
	v := Verdict{
		EnvHash:       parts[1],
		Network:       network,
		Node:          node,
		Valid:         valid,
		Online:        online,
		NetworkMember: member,
		LastSeenUnix:  lastSeen,
		KeyGeneration: keyGen,
		VerifiedAt:    verifiedAt,
	}
	canon, err := v.Canonical()
	if err != nil {
		return Verdict{}, err
	}
	if canon != s {
		return Verdict{}, fmt.Errorf("reqsig: non-canonical verdict encoding")
	}
	return v, nil
}

// SignVerdict validates the verdict, builds its canonical form, and signs it.
func SignVerdict(priv ed25519.PrivateKey, v Verdict) (canonical, sigB64 string, err error) {
	canonical, err = v.Canonical()
	if err != nil {
		return "", "", err
	}
	sig := ed25519.Sign(priv, []byte(canonical))
	return canonical, base64.StdEncoding.EncodeToString(sig), nil
}

// VerifyVerdict verifies a verdict signature using the build-embedded
// keyring, selecting the issuer key by kid. Fails closed on unknown kid.
func VerifyVerdict(kid, canonical, sigB64 string) (Verdict, error) {
	pub := verdictKeyFor(kid)
	if pub == nil {
		return Verdict{}, fmt.Errorf("reqsig: no verdict key for kid %q", kid)
	}
	return VerifyVerdictWithKey(pub, canonical, sigB64)
}

// VerifyVerdictWithKey verifies a verdict signature with an explicit issuer
// public key (e.g. one fetched from the registry's verify-keys endpoint).
func VerifyVerdictWithKey(pub ed25519.PublicKey, canonical, sigB64 string) (Verdict, error) {
	v, err := ParseVerdict(canonical)
	if err != nil {
		return Verdict{}, err
	}
	if len(pub) != ed25519.PublicKeySize {
		return Verdict{}, fmt.Errorf("reqsig: bad verdict public key size %d", len(pub))
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return Verdict{}, fmt.Errorf("reqsig: verdict signature not base64: %w", err)
	}
	if !ed25519.Verify(pub, []byte(canonical), sig) {
		return Verdict{}, fmt.Errorf("reqsig: verdict signature verification failed")
	}
	return v, nil
}

func verdictKeyFor(kid string) ed25519.PublicKey {
	if kid == "" || verdictKeyringB64 == "" {
		return nil
	}
	for _, entry := range strings.Split(verdictKeyringB64, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(entry), "=")
		if !ok || k != kid {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(v)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil
		}
		if isAllZero(raw) {
			return nil
		}
		return ed25519.PublicKey(raw)
	}
	return nil
}

func isAllZero(b []byte) bool {
	var acc byte
	for _, c := range b {
		acc |= c
	}
	return acc == 0
}

func boolChar(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func parseBoolChar(s string) (bool, error) {
	switch s {
	case "0":
		return false, nil
	case "1":
		return true, nil
	}
	return false, fmt.Errorf("reqsig: bool field must be '0' or '1'")
}
