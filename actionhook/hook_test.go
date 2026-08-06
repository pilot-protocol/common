// SPDX-License-Identifier: AGPL-3.0-or-later

package actionhook

import (
	"errors"
	"testing"
	"time"

	"github.com/pilot-protocol/common/decision"
)

func TestEnvelopeAndMetadataHashAreStableAndPrivacyBounded(t *testing.T) {
	first := HashMetadata(map[string]string{"peer_id": "42", "reason": "mutual"})
	second := HashMetadata(map[string]string{"reason": "mutual", "peer_id": "42"})
	if first != second {
		t.Fatal("metadata hash changed with map iteration order")
	}
	envelope, err := NewEnvelope("trust.auto_accept", "agent:42", first, "pilot.handshake", map[string]string{"reason": "mutual"}, time.Unix(1785700000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if envelope.ID == "" || envelope.Attributes["reason"] != "mutual" {
		t.Fatalf("unexpected envelope: %+v", envelope)
	}
	if _, err := NewEnvelope("trust.auto_accept", "agent:42", first, "pilot.handshake", map[string]string{"prompt": "line\nsecret"}, time.Now()); err == nil {
		t.Fatal("control characters must not enter metadata")
	}
}

func TestPreflightBlocksEverythingExceptExplicitAllow(t *testing.T) {
	for _, outcome := range []decision.Outcome{decision.Deny, decision.ApprovalRequired, decision.Constrain} {
		err := (Preflight{Outcome: outcome}).RequireUnconstrained()
		var blocked *BlockedError
		if !errors.As(err, &blocked) || blocked.Outcome != outcome {
			t.Fatalf("outcome %q was not safely blocked: %v", outcome, err)
		}
	}
	if err := (Preflight{Outcome: decision.Allow}).RequireUnconstrained(); err != nil {
		t.Fatalf("allow was blocked: %v", err)
	}
	if err := (Preflight{Outcome: decision.Deny, ObserveOnly: true}).RequireUnconstrained(); err != nil {
		t.Fatalf("observe-only result blocked execution: %v", err)
	}
}
