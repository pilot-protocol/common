// SPDX-License-Identifier: AGPL-3.0-or-later

package decision

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestReceiptExporterDiscoversEvidenceAppendedByAnotherProcess(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	exporterJournal, err := OpenReceiptJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	writerJournal, err := OpenReceiptJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	receipt := journalReceipt(t, 1785500000, Enforced)
	if err := writerJournal.AppendReceipt(context.Background(), receipt); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if request.Header.Get("Idempotency-Key") != receipt.ID {
			t.Errorf("idempotency key=%q", request.Header.Get("Idempotency-Key"))
		}
		_ = json.NewEncoder(writer).Encode(map[string]string{"accepted_receipt_id": receipt.ID})
	}))
	defer server.Close()
	exporter, err := NewReceiptExporter(ReceiptExporterConfig{
		Journal: exporterJournal, Endpoint: server.URL, AckPath: filepath.Join(t.TempDir(), "acks"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := exporter.ExportOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || exporter.Pending() != 0 {
		t.Fatalf("external receipt calls=%d pending=%d", calls.Load(), exporter.Pending())
	}
}

func TestReceiptExporterRetriesAndAcknowledgesSignedEvidence(t *testing.T) {
	t.Parallel()
	journal, err := OpenReceiptJournal(filepath.Join(t.TempDir(), "receipts.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	receipt := journalReceipt(t, 1785500000, Enforced)
	if err := journal.AppendReceipt(context.Background(), receipt); err != nil {
		t.Fatal(err)
	}
	if records := journal.Receipts(); len(records) != 1 || records[0].ID != receipt.ID {
		t.Fatalf("journal records = %+v", records)
	}
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		call := calls.Add(1)
		if request.Method != http.MethodPost || request.Header.Get("Idempotency-Key") != receipt.ID {
			t.Errorf("request method=%s idempotency=%q", request.Method, request.Header.Get("Idempotency-Key"))
		}
		var received Receipt
		if err := json.NewDecoder(request.Body).Decode(&received); err != nil || received.ID != receipt.ID || received.Signature == "" {
			t.Errorf("receipt payload=%+v err=%v", received, err)
		}
		if call == 1 {
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(writer).Encode(map[string]string{"accepted_receipt_id": receipt.ID})
	}))
	defer server.Close()
	ackPath := filepath.Join(t.TempDir(), "receipt-export.acks")
	exporter, err := NewReceiptExporter(ReceiptExporterConfig{Journal: journal, Endpoint: server.URL, AckPath: ackPath})
	if err != nil {
		t.Fatal(err)
	}
	if err := exporter.ExportOnce(context.Background()); err == nil || exporter.Pending() != 1 {
		t.Fatalf("failed receipt export err=%v pending=%d", err, exporter.Pending())
	}
	if err := exporter.ExportOnce(context.Background()); err != nil || exporter.Pending() != 0 {
		t.Fatalf("successful receipt retry err=%v pending=%d", err, exporter.Pending())
	}
	restarted, err := NewReceiptExporter(ReceiptExporterConfig{Journal: journal, Endpoint: server.URL, AckPath: ackPath})
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.ExportOnce(context.Background()); err != nil || calls.Load() != 2 {
		t.Fatalf("restart resent acknowledged receipt: calls=%d err=%v", calls.Load(), err)
	}
}

func TestReceiptExporterRejectsInsecureEndpointAndBadAcknowledgement(t *testing.T) {
	t.Parallel()
	journal, err := OpenReceiptJournal(filepath.Join(t.TempDir(), "receipts.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	receipt := journalReceipt(t, 1785500000, Enforced)
	if err := journal.AppendReceipt(context.Background(), receipt); err != nil {
		t.Fatal(err)
	}
	if _, err := NewReceiptExporter(ReceiptExporterConfig{Journal: journal, Endpoint: "http://example.com/receipts", AckPath: filepath.Join(t.TempDir(), "acks")}); err == nil {
		t.Fatal("plaintext non-loopback receipt endpoint was accepted")
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(writer).Encode(map[string]string{"accepted_receipt_id": "wrong"})
	}))
	defer server.Close()
	exporter, err := NewReceiptExporter(ReceiptExporterConfig{Journal: journal, Endpoint: server.URL, AckPath: filepath.Join(t.TempDir(), "acks")})
	if err != nil {
		t.Fatal(err)
	}
	if err := exporter.ExportOnce(context.Background()); err == nil || exporter.Pending() != 1 {
		t.Fatalf("bad receipt acknowledgement err=%v pending=%d", err, exporter.Pending())
	}
}
