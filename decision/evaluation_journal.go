// SPDX-License-Identifier: AGPL-3.0-or-later

package decision

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/pilot-protocol/common/fsutil"
)

// EvaluationJournalStore is the durable observation/read contract used by
// semantic enforcement, usage delivery, and the operator console. File-backed
// single-node deployments and shared PostgreSQL fleets implement the same
// interface.
type EvaluationJournalStore interface {
	EvaluationObserver
	EvaluationRecords(context.Context, int) ([]EvaluationRecord, error)
}

// EvaluationLookupStore is the indexed correlation contract used by an action
// trace. It remains optional so external append-only journals stay compatible.
type EvaluationLookupStore interface {
	EvaluationRecordForIntent(context.Context, string, string) (EvaluationRecord, bool, error)
}

type EvaluationJournal struct {
	path    string
	mu      sync.Mutex
	seen    map[string]EvaluationRecord
	records []EvaluationRecord
}

func OpenEvaluationJournal(path string) (*EvaluationJournal, error) {
	if path == "" {
		return nil, fmt.Errorf("decision: evaluation journal path is required")
	}
	absolute, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	if info, statErr := os.Lstat(absolute); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("decision: evaluation journal must be an owner-only regular file")
		}
	} else if !os.IsNotExist(statErr) {
		return nil, statErr
	}
	if err := os.MkdirAll(filepath.Dir(absolute), 0o700); err != nil {
		return nil, err
	}
	journal := &EvaluationJournal{path: absolute, seen: make(map[string]EvaluationRecord)}
	if err := journal.load(); err != nil {
		return nil, err
	}
	return journal, nil
}

func (journal *EvaluationJournal) RecordEvaluation(ctx context.Context, record EvaluationRecord) error {
	if journal == nil || journal.path == "" {
		return fmt.Errorf("decision: evaluation journal is not initialized")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := record.Validate(); err != nil {
		return err
	}
	body, err := json.Marshal(record)
	if err != nil {
		return err
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if existing, exists := journal.seen[record.ID]; exists {
		if !evaluationRecordsEqual(existing, record) {
			return fmt.Errorf("decision: conflicting evaluation usage unit %q", record.ID)
		}
		return nil
	}
	if err := fsutil.AppendSync(journal.path, append(body, '\n')); err != nil {
		return fmt.Errorf("decision: append evaluation journal: %w", err)
	}
	journal.seen[record.ID] = record
	journal.records = append(journal.records, record)
	return nil
}

func (journal *EvaluationJournal) Records() []EvaluationRecord {
	records, _ := journal.EvaluationRecords(context.Background(), 0)
	return records
}

// EvaluationRecords returns records in chronological order. A zero limit
// returns the complete journal for backwards-compatible single-node usage;
// positive limits return the most recent bounded window.
func (journal *EvaluationJournal) EvaluationRecords(ctx context.Context, limit int) ([]EvaluationRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if journal == nil {
		return nil, fmt.Errorf("decision: evaluation journal is not initialized")
	}
	if limit < 0 {
		return nil, fmt.Errorf("decision: evaluation record limit cannot be negative")
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	start := 0
	if limit > 0 && len(journal.records) > limit {
		start = len(journal.records) - limit
	}
	return append([]EvaluationRecord(nil), journal.records[start:]...), nil
}

func (journal *EvaluationJournal) EvaluationRecordForIntent(ctx context.Context, tenantID, intentHash string) (EvaluationRecord, bool, error) {
	if err := ctx.Err(); err != nil {
		return EvaluationRecord{}, false, err
	}
	if journal == nil {
		return EvaluationRecord{}, false, fmt.Errorf("decision: evaluation journal is not initialized")
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	for index := len(journal.records) - 1; index >= 0; index-- {
		record := journal.records[index]
		if record.TenantID == tenantID && record.IntentHash == intentHash {
			return record, true, nil
		}
	}
	return EvaluationRecord{}, false, nil
}

func (journal *EvaluationJournal) load() error {
	file, err := os.Open(journal.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	line := 0
	for scanner.Scan() {
		line++
		decoder := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		decoder.DisallowUnknownFields()
		var record EvaluationRecord
		if err := decoder.Decode(&record); err != nil {
			return fmt.Errorf("decision: decode evaluation journal line %d: %w", line, err)
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			return fmt.Errorf("decision: evaluation journal line %d has trailing JSON", line)
		}
		if err := record.Validate(); err != nil {
			return fmt.Errorf("decision: validate evaluation journal line %d: %w", line, err)
		}
		if existing, exists := journal.seen[record.ID]; exists {
			if !evaluationRecordsEqual(existing, record) {
				return fmt.Errorf("decision: conflicting evaluation usage unit %q", record.ID)
			}
			continue
		}
		journal.seen[record.ID] = record
		journal.records = append(journal.records, record)
	}
	return scanner.Err()
}

func evaluationRecordsEqual(first, second EvaluationRecord) bool {
	firstJSON, _ := json.Marshal(first)
	secondJSON, _ := json.Marshal(second)
	return bytes.Equal(firstJSON, secondJSON)
}

var _ EvaluationObserver = (*EvaluationJournal)(nil)
var _ EvaluationJournalStore = (*EvaluationJournal)(nil)
var _ EvaluationLookupStore = (*EvaluationJournal)(nil)
