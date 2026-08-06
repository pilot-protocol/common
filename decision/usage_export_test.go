// SPDX-License-Identifier: AGPL-3.0-or-later

package decision

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type durableUsageJournalStub struct {
	mu       sync.Mutex
	record   EvaluationRecord
	exported bool
}

func (journal *durableUsageJournalStub) RecordEvaluation(_ context.Context, record EvaluationRecord) error {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	journal.record = record
	return nil
}

func (journal *durableUsageJournalStub) EvaluationRecords(context.Context, int) ([]EvaluationRecord, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	return []EvaluationRecord{journal.record}, nil
}

func (journal *durableUsageJournalStub) PendingEvaluationRecords(context.Context, int) ([]EvaluationRecord, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.exported {
		return nil, nil
	}
	return []EvaluationRecord{journal.record}, nil
}

func (journal *durableUsageJournalStub) MarkEvaluationExported(_ context.Context, unitID string) error {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if unitID == journal.record.ID {
		journal.exported = true
	}
	return nil
}

func (journal *durableUsageJournalStub) PendingEvaluationCount(context.Context) (int, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.exported {
		return 0, nil
	}
	return 1, nil
}

func usageRecord() EvaluationRecord {
	return EvaluationRecord{
		Version: SchemaVersion, ID: strings.Repeat("a", 64), IntentHash: strings.Repeat("b", 64),
		TenantID: "tenant-a", AgentID: "agent-1", Mode: EvaluationShadow,
		Identity: evaluatorIdentity(), BaseOutcome: Allow, SemanticOutcome: Deny, AppliedOutcome: Allow,
		ModelCalls: 1, InputTokens: 41, OutputTokens: 7, StartedAt: 1, CompletedAt: 2,
	}
}

func TestUsageExporterRetriesAndAcknowledgesIdempotently(t *testing.T) {
	t.Parallel()
	journal, err := OpenEvaluationJournal(filepath.Join(t.TempDir(), "evaluations.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.RecordEvaluation(context.Background(), usageRecord()); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		call := calls.Add(1)
		if request.Header.Get("Idempotency-Key") != usageRecord().ID {
			t.Errorf("idempotency key=%q", request.Header.Get("Idempotency-Key"))
		}
		if call == 1 {
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var event UsageEvent
		if err := json.NewDecoder(request.Body).Decode(&event); err != nil {
			t.Errorf("decode usage event: %v", err)
		} else if event.ModelCalls != 1 || event.InputTokens != 41 || event.OutputTokens != 7 {
			t.Errorf("usage event=%+v", event)
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]string{"accepted_unit_id": usageRecord().ID})
	}))
	defer server.Close()
	ackPath := filepath.Join(t.TempDir(), "usage.acks")
	exporter, err := NewUsageExporter(UsageExporterConfig{Journal: journal, Endpoint: server.URL, AckPath: ackPath})
	if err != nil {
		t.Fatal(err)
	}
	if err := exporter.ExportOnce(context.Background()); err == nil || exporter.Pending() != 1 {
		t.Fatalf("failed export err=%v pending=%d", err, exporter.Pending())
	}
	failed := exporter.Status()
	if failed.Pending != 1 || failed.LastFailureAt == 0 || failed.LastFailureCode != UsageExportFailureRemoteRejected || failed.LastSuccessAt != 0 {
		t.Fatalf("failed export status=%+v", failed)
	}
	if err := exporter.ExportOnce(context.Background()); err != nil || exporter.Pending() != 0 {
		t.Fatalf("successful retry err=%v pending=%d", err, exporter.Pending())
	}
	succeeded := exporter.Status()
	if succeeded.Pending != 0 || succeeded.LastAttemptAt == 0 || succeeded.LastSuccessAt == 0 || succeeded.LastFailureCode != "" {
		t.Fatalf("successful export status=%+v", succeeded)
	}
	restarted, err := NewUsageExporter(UsageExporterConfig{Journal: journal, Endpoint: server.URL, AckPath: ackPath})
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.ExportOnce(context.Background()); err != nil || calls.Load() != 2 {
		t.Fatalf("restart resent acknowledged usage: calls=%d err=%v", calls.Load(), err)
	}
}

func TestUsageExporterRejectsWrongAcknowledgementAndInsecureEndpoint(t *testing.T) {
	t.Parallel()
	journal, _ := OpenEvaluationJournal(filepath.Join(t.TempDir(), "evaluations.jsonl"))
	_ = journal.RecordEvaluation(context.Background(), usageRecord())
	if _, err := NewUsageExporter(UsageExporterConfig{Journal: journal, Endpoint: "http://example.com/usage", AckPath: filepath.Join(t.TempDir(), "acks")}); err == nil {
		t.Fatal("non-loopback plaintext usage endpoint was accepted")
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_ = json.NewEncoder(writer).Encode(map[string]string{"accepted_unit_id": strings.Repeat("c", 64)})
	}))
	defer server.Close()
	exporter, err := NewUsageExporter(UsageExporterConfig{Journal: journal, Endpoint: server.URL, AckPath: filepath.Join(t.TempDir(), "acks")})
	if err != nil {
		t.Fatal(err)
	}
	if err := exporter.ExportOnce(context.Background()); err == nil || exporter.Pending() != 1 {
		t.Fatalf("wrong acknowledgement err=%v pending=%d", err, exporter.Pending())
	}
	if status := exporter.Status(); status.LastFailureCode != UsageExportFailureInvalidAcknowledged || status.LastFailureAt == 0 {
		t.Fatalf("wrong acknowledgement status=%+v", status)
	}
}

func TestUsageExporterUsesSharedDurableAcknowledgement(t *testing.T) {
	t.Parallel()
	journal := &durableUsageJournalStub{record: usageRecord()}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]string{"accepted_unit_id": usageRecord().ID})
	}))
	defer server.Close()
	exporter, err := NewUsageExporter(UsageExporterConfig{Journal: journal, Endpoint: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if err := exporter.ExportOnce(context.Background()); err != nil || exporter.Pending() != 0 {
		t.Fatalf("durable export err=%v pending=%d", err, exporter.Pending())
	}
}

func TestUsageExportStatusRejectsMalformedRemoteState(t *testing.T) {
	t.Parallel()
	for name, status := range map[string]UsageExportStatus{
		"negative backlog":          {Pending: -1},
		"unknown failure":           {LastFailureAt: 1, LastFailureCode: "network detail"},
		"failure without timestamp": {LastFailureCode: UsageExportFailureTransport},
	} {
		t.Run(name, func(t *testing.T) {
			if err := status.Validate(); err == nil {
				t.Fatalf("invalid usage export status accepted: %+v", status)
			}
		})
	}
}
