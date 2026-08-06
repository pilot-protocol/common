// SPDX-License-Identifier: AGPL-3.0-or-later

package decision

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pilot-protocol/common/fsutil"
)

// ReceiptExporterConfig configures asynchronous delivery of already-signed
// enforcement evidence to a customer retention, SIEM, or billing collector.
// It is intentionally independent from Enforcer and cannot allow, deny, or
// delay an action.
type ReceiptExporterConfig struct {
	Journal     *ReceiptJournal
	Endpoint    string
	AckPath     string
	BearerToken string
	HTTPClient  *http.Client
	Interval    time.Duration
	BatchSize   int
}

// ReceiptExporter retries signed evidence until a collector echoes the exact
// receipt ID. Its locally fsynced acknowledgement makes retries idempotent
// across restarts; a collector outage leaves enforcement unaffected.
type ReceiptExporter struct {
	journal     *ReceiptJournal
	endpoint    *url.URL
	ackPath     string
	bearerToken string
	httpClient  *http.Client
	interval    time.Duration
	batchSize   int

	mu    sync.Mutex
	acked map[string]struct{}
}

func NewReceiptExporter(config ReceiptExporterConfig) (*ReceiptExporter, error) {
	if config.Journal == nil || config.Endpoint == "" || config.AckPath == "" {
		return nil, fmt.Errorf("decision: receipt journal, endpoint, and acknowledgement path are required")
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, fmt.Errorf("decision: invalid receipt export endpoint")
	}
	if endpoint.Scheme != "https" && !(endpoint.Scheme == "http" && usageLoopback(endpoint.Hostname())) {
		return nil, fmt.Errorf("decision: receipt export endpoint must use HTTPS")
	}
	ackPath, err := receiptExportAckPath(config.AckPath)
	if err != nil {
		return nil, err
	}
	if config.HTTPClient == nil {
		config.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if config.Interval <= 0 {
		config.Interval = 30 * time.Second
	}
	if config.BatchSize <= 0 {
		config.BatchSize = 100
	}
	exporter := &ReceiptExporter{
		journal: config.Journal, endpoint: endpoint, ackPath: ackPath,
		bearerToken: config.BearerToken, httpClient: config.HTTPClient,
		interval: config.Interval, batchSize: config.BatchSize, acked: make(map[string]struct{}),
	}
	if err := exporter.loadAcks(); err != nil {
		return nil, err
	}
	return exporter, nil
}

func receiptExportAckPath(path string) (string, error) {
	absolute, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	if info, statErr := os.Lstat(absolute); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return "", fmt.Errorf("decision: receipt export acknowledgement path must be an owner-only regular file")
		}
	} else if !os.IsNotExist(statErr) {
		return "", statErr
	}
	if err := os.MkdirAll(filepath.Dir(absolute), 0o700); err != nil {
		return "", err
	}
	return absolute, nil
}

func (exporter *ReceiptExporter) Run(ctx context.Context) error {
	ticker := time.NewTicker(exporter.interval)
	defer ticker.Stop()
	for {
		_ = exporter.ExportOnce(ctx)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (exporter *ReceiptExporter) ExportOnce(ctx context.Context) error {
	if exporter == nil || exporter.journal == nil {
		return fmt.Errorf("decision: receipt exporter is not initialized")
	}
	exporter.mu.Lock()
	defer exporter.mu.Unlock()
	attempted := 0
	var firstErr error
	for _, receipt := range exporter.journal.Receipts() {
		if _, exists := exporter.acked[receipt.ID]; exists {
			continue
		}
		if attempted >= exporter.batchSize {
			break
		}
		attempted++
		if err := exporter.send(ctx, receipt); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err := fsutil.AppendSync(exporter.ackPath, []byte(receipt.ID+"\n")); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("decision: persist receipt export acknowledgement: %w", err)
			}
			continue
		}
		exporter.acked[receipt.ID] = struct{}{}
	}
	return firstErr
}

func (exporter *ReceiptExporter) Pending() int {
	if exporter == nil || exporter.journal == nil {
		return 0
	}
	exporter.mu.Lock()
	defer exporter.mu.Unlock()
	pending := 0
	for _, receipt := range exporter.journal.Receipts() {
		if _, exists := exporter.acked[receipt.ID]; !exists {
			pending++
		}
	}
	return pending
}

func (exporter *ReceiptExporter) send(ctx context.Context, receipt Receipt) error {
	if err := receipt.Validate(); err != nil || !validJournalSignature(receipt.Signature) {
		return fmt.Errorf("decision: invalid signed receipt for export")
	}
	body, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, exporter.endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Idempotency-Key", receipt.ID)
	if exporter.bearerToken != "" {
		request.Header.Set("Authorization", "Bearer "+exporter.bearerToken)
	}
	response, err := exporter.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("decision: export receipt: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
		return fmt.Errorf("decision: receipt endpoint returned HTTP %d", response.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 4<<10))
	decoder.DisallowUnknownFields()
	var acknowledgement struct {
		AcceptedReceiptID string `json:"accepted_receipt_id"`
	}
	if err := decoder.Decode(&acknowledgement); err != nil || acknowledgement.AcceptedReceiptID != receipt.ID {
		return fmt.Errorf("decision: receipt endpoint returned invalid acknowledgement")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("decision: receipt endpoint returned trailing data")
	}
	return nil
}

func (exporter *ReceiptExporter) loadAcks() error {
	file, err := os.Open(exporter.ackPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		receiptID := scanner.Text()
		if !lowerHex(receiptID, 64) {
			return fmt.Errorf("decision: invalid receipt export acknowledgement %q", receiptID)
		}
		exporter.acked[receiptID] = struct{}{}
	}
	return scanner.Err()
}
