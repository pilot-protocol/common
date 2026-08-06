// SPDX-License-Identifier: AGPL-3.0-or-later

package decision

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func journalReceipt(t *testing.T, observedAt int64, result EnforcementResult) Receipt {
	t.Helper()
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(1785500000, 0)
	intent := testIntent(t, now)
	intentHash, _ := intent.Hash()
	decisionResult := Decision{
		Version: SchemaVersion, ID: "journal-decision", IntentHash: intentHash,
		TenantID: intent.TenantID, AgentID: intent.AgentID, Outcome: Allow,
		ProviderID: "journal", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(), KeyID: "issuer-1",
	}
	receipt, err := NewReceipt(intent, decisionResult, "wallet-journal", "receipt-key-1", observedAt, result)
	if err != nil {
		t.Fatal(err)
	}
	if err := receipt.Sign(privateKey); err != nil {
		t.Fatal(err)
	}
	return receipt
}

func TestReceiptJournalIsDurableIdempotentAndConflictSafe(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	journal, err := OpenReceiptJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	receipt := journalReceipt(t, 1785500000, Enforced)
	if err := journal.AppendReceipt(context.Background(), receipt); err != nil {
		t.Fatal(err)
	}
	if err := journal.AppendReceipt(context.Background(), receipt); err != nil {
		t.Fatalf("idempotent append: %v", err)
	}
	reopened, err := OpenReceiptJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.AppendReceipt(context.Background(), receipt); err != nil {
		t.Fatalf("restart idempotency: %v", err)
	}
	conflict := receipt
	conflict.ObservedAt++
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	_ = conflict.Sign(privateKey)
	if err := reopened.AppendReceipt(context.Background(), conflict); err == nil {
		t.Fatal("conflicting receipt ID was accepted")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := 0
	for _, character := range body {
		if character == '\n' {
			lines++
		}
	}
	if lines != 1 {
		t.Fatalf("journal lines=%d, want 1", lines)
	}
}

func TestReceiptJournalRejectsUnsignedCorruptAndUnsafeFiles(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	path := filepath.Join(directory, "receipts.jsonl")
	journal, err := OpenReceiptJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := journalReceipt(t, 1785500000, Enforced)
	unsigned.Signature = ""
	if err := journal.AppendReceipt(context.Background(), unsigned); err == nil {
		t.Fatal("unsigned receipt was accepted")
	}
	unsafe := filepath.Join(directory, "unsafe.jsonl")
	if err := os.WriteFile(unsafe, []byte("not-json\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenReceiptJournal(unsafe); err == nil {
		t.Fatal("unsafe/corrupt journal was accepted")
	}
	realPath := filepath.Join(directory, "real.jsonl")
	if err := os.WriteFile(realPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realPath, filepath.Join(directory, "link.jsonl")); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenReceiptJournal(filepath.Join(directory, "link.jsonl")); err == nil {
		t.Fatal("symlink journal was accepted")
	}
}
