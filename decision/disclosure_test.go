// SPDX-License-Identifier: AGPL-3.0-or-later

package decision

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func validDisclosureBinding() DisclosureBinding {
	return DisclosureBinding{
		Version: DisclosureBindingVersion, ContentHash: strings.Repeat("a", 64), DeclaredBytes: 42,
		ContentType: "application/json", Labels: []string{"finance", "pii"}, Recipient: "agent:finance",
		Purpose: "invoice-payment", Residency: "eu-west-1", Filename: "invoice.json", TransferID: "transfer-1",
	}
}

func TestDisclosureBindingCanonicalAndIntentBinding(t *testing.T) {
	binding := validDisclosureBinding()
	hash, err := binding.Hash()
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	intent := Intent{
		Version: SchemaVersion, ID: "intent-disclosure-1", TenantID: "tenant-a", AgentID: "agent-a", Action: "file.share",
		Resource: "agent:finance/inbox", Audience: binding.Recipient, Purpose: binding.Purpose, PayloadHash: hash, Risk: RiskHigh,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(), Nonce: strings.Repeat("b", 32), KeyID: "intent-key-1",
	}
	if err := intent.Sign(privateKey); err != nil {
		t.Fatal(err)
	}
	if err := intent.Verify(publicKey, now); err != nil {
		t.Fatal(err)
	}
	if err := binding.VerifyIntent(intent); err != nil {
		t.Fatal(err)
	}
	tampered := binding
	tampered.Residency = "us-east-1"
	if err := tampered.VerifyIntent(intent); err == nil {
		t.Fatal("residency mutation retained intent binding")
	}
}

func TestDisclosureBindingV2RetentionClassBindsWithoutChangingV1(t *testing.T) {
	v1 := validDisclosureBinding()
	v1Canonical, err := v1.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	v2 := v1
	v2.Version = DisclosureBindingRetentionVersion
	v2.RetentionClass = "finance-7y"
	v2Canonical, err := v2.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if string(v1Canonical) == string(v2Canonical) {
		t.Fatal("V2 retention metadata reused V1 canonical bytes")
	}
	hash, err := v2.Hash()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	intent := Intent{
		Version: SchemaVersion, ID: "intent-disclosure-v2", TenantID: "tenant-a", AgentID: "agent-a", Action: "file.share",
		Resource: "agent:finance/inbox", Audience: v2.Recipient, Purpose: v2.Purpose, PayloadHash: hash, Risk: RiskHigh,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(), Nonce: strings.Repeat("c", 32), KeyID: "intent-key-1",
	}
	if err := v2.VerifyIntent(intent); err != nil {
		t.Fatal(err)
	}
	mutated := v2
	mutated.RetentionClass = "finance-30d"
	if err := mutated.VerifyIntent(intent); err == nil {
		t.Fatal("retention class mutation retained intent binding")
	}
	v1.RetentionClass = "finance-7y"
	if err := v1.Validate(); err == nil || !strings.Contains(err.Error(), "requires version") {
		t.Fatalf("V1 retention class validation error=%v", err)
	}
}

func TestDisclosureBindingFailsClosed(t *testing.T) {
	for name, mutate := range map[string]func(*DisclosureBinding){
		"unsorted labels":            func(binding *DisclosureBinding) { binding.Labels = []string{"pii", "finance"} },
		"duplicate labels":           func(binding *DisclosureBinding) { binding.Labels = []string{"finance", "finance"} },
		"parameterized content type": func(binding *DisclosureBinding) { binding.ContentType = "application/json; charset=utf-8" },
		"upper content type":         func(binding *DisclosureBinding) { binding.ContentType = "Application/json" },
		"bad residency":              func(binding *DisclosureBinding) { binding.Residency = "EU West" },
		"path filename":              func(binding *DisclosureBinding) { binding.Filename = "private/invoice.json" },
	} {
		t.Run(name, func(t *testing.T) {
			binding := validDisclosureBinding()
			mutate(&binding)
			if err := binding.Validate(); err == nil {
				t.Fatalf("invalid disclosure binding accepted: %+v", binding)
			}
		})
	}
}
