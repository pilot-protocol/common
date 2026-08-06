// SPDX-License-Identifier: AGPL-3.0-or-later

package decision

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/pilot-protocol/common/fsutil"
)

const MaxReceiptJournalLineBytes = 1 << 20

// ReceiptJournal is an append-only, fsync-before-return local evidence sink.
// Receipt IDs make retries idempotent; conflicting content for one ID fails.
type ReceiptJournal struct {
	path     string
	mu       sync.Mutex
	seen     map[string]string
	receipts []Receipt
}

func OpenReceiptJournal(path string) (*ReceiptJournal, error) {
	if path == "" {
		return nil, fmt.Errorf("decision: receipt journal path is required")
	}
	absolute, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("decision: resolve receipt journal: %w", err)
	}
	if info, statErr := os.Lstat(absolute); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("decision: receipt journal must not be a symlink")
	} else if statErr != nil && !os.IsNotExist(statErr) {
		return nil, fmt.Errorf("decision: inspect receipt journal: %w", statErr)
	}
	if err := os.MkdirAll(filepath.Dir(absolute), 0o700); err != nil {
		return nil, fmt.Errorf("decision: create receipt journal directory: %w", err)
	}
	journal := &ReceiptJournal{path: absolute, seen: make(map[string]string)}
	if err := journal.load(); err != nil {
		return nil, err
	}
	return journal, nil
}

func (journal *ReceiptJournal) AppendReceipt(ctx context.Context, receipt Receipt) error {
	if journal == nil || journal.path == "" {
		return fmt.Errorf("decision: receipt journal is not initialized")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := receipt.Validate(); err != nil {
		return err
	}
	if !validJournalSignature(receipt.Signature) {
		return fmt.Errorf("decision: receipt journal requires a signed receipt")
	}
	hash, err := receipt.Hash()
	if err != nil {
		return err
	}
	body, err := json.Marshal(receipt)
	if err != nil {
		return fmt.Errorf("decision: encode receipt: %w", err)
	}
	if len(body) > MaxReceiptJournalLineBytes {
		return fmt.Errorf("decision: receipt exceeds journal line limit")
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if existing, exists := journal.seen[receipt.ID]; exists {
		if existing != hash {
			return fmt.Errorf("decision: conflicting receipt for id %q", receipt.ID)
		}
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := fsutil.AppendSync(journal.path, append(body, '\n')); err != nil {
		return fmt.Errorf("decision: append receipt journal: %w", err)
	}
	journal.seen[receipt.ID] = hash
	journal.receipts = append(journal.receipts, receipt)
	return nil
}

// Receipts returns a stable snapshot in journal append order. Exporters use
// this read-only view outside authorization and enforcement paths; the journal
// itself remains the durable idempotency authority.
func (journal *ReceiptJournal) Receipts() []Receipt {
	if journal == nil {
		return nil
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	return append([]Receipt(nil), journal.receipts...)
}

func (journal *ReceiptJournal) load() error {
	file, err := os.Open(journal.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("decision: open receipt journal: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("decision: receipt journal must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("decision: receipt journal permissions must be owner-only")
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), MaxReceiptJournalLineBytes+1)
	line := 0
	for scanner.Scan() {
		line++
		decoder := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		decoder.DisallowUnknownFields()
		var receipt Receipt
		if err := decoder.Decode(&receipt); err != nil {
			return fmt.Errorf("decision: decode receipt journal line %d: %w", line, err)
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			return fmt.Errorf("decision: receipt journal line %d has trailing JSON", line)
		}
		if err := receipt.Validate(); err != nil {
			return fmt.Errorf("decision: validate receipt journal line %d: %w", line, err)
		}
		if !validJournalSignature(receipt.Signature) {
			return fmt.Errorf("decision: receipt journal line %d is unsigned", line)
		}
		hash, _ := receipt.Hash()
		if existing, exists := journal.seen[receipt.ID]; exists && existing != hash {
			return fmt.Errorf("decision: conflicting receipt journal id %q", receipt.ID)
		}
		journal.seen[receipt.ID] = hash
		journal.receipts = append(journal.receipts, receipt)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("decision: scan receipt journal: %w", err)
	}
	return nil
}

func validJournalSignature(encoded string) bool {
	signature, err := base64.StdEncoding.DecodeString(encoded)
	return err == nil && len(signature) == ed25519.SignatureSize
}
