// SPDX-License-Identifier: AGPL-3.0-or-later

package decision

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pilot-protocol/common/fsutil"
)

const UsageKindSemanticEvaluation = "semantic_evaluation"

const (
	UsageExportFailureTransport           = "transport"
	UsageExportFailureRemoteRejected      = "remote_rejected"
	UsageExportFailureInvalidAcknowledged = "invalid_acknowledgement"
	UsageExportFailureAckPersistence      = "ack_persistence"
)

type UsageEvent struct {
	Version         uint16            `json:"version"`
	UnitID          string            `json:"unit_id"`
	Kind            string            `json:"kind"`
	TenantID        string            `json:"tenant_id"`
	AgentID         string            `json:"agent_id"`
	Quantity        uint64            `json:"quantity"`
	OccurredAt      int64             `json:"occurred_at_unix_nano"`
	Evaluator       EvaluatorIdentity `json:"evaluator"`
	Mode            EvaluationMode    `json:"mode"`
	Applied         bool              `json:"applied"`
	BaseOutcome     Outcome           `json:"base_outcome"`
	SemanticOutcome Outcome           `json:"semantic_outcome,omitempty"`
	AppliedOutcome  Outcome           `json:"applied_outcome"`
	ModelCalls      uint64            `json:"model_calls,omitempty"`
	InputTokens     uint64            `json:"input_tokens,omitempty"`
	OutputTokens    uint64            `json:"output_tokens,omitempty"`
}

func (record EvaluationRecord) UsageEvent() UsageEvent {
	return UsageEvent{
		Version: SchemaVersion, UnitID: record.UsageUnitID(), Kind: UsageKindSemanticEvaluation,
		TenantID: record.TenantID, AgentID: record.AgentID, Quantity: 1,
		OccurredAt: record.CompletedAt, Evaluator: record.Identity, Mode: record.Mode,
		Applied: record.Applied, BaseOutcome: record.BaseOutcome,
		SemanticOutcome: record.SemanticOutcome, AppliedOutcome: record.AppliedOutcome,
		ModelCalls: record.ModelCalls, InputTokens: record.InputTokens, OutputTokens: record.OutputTokens,
	}
}

func (event UsageEvent) Validate() error {
	if event.Version != SchemaVersion || !lowerHex(event.UnitID, 64) || event.Kind != UsageKindSemanticEvaluation || event.Quantity != 1 || event.OccurredAt <= 0 {
		return fmt.Errorf("decision: invalid usage event")
	}
	record := EvaluationRecord{
		Version: SchemaVersion, ID: event.UnitID, IntentHash: strings.Repeat("0", 64),
		TenantID: event.TenantID, AgentID: event.AgentID, Mode: event.Mode,
		Identity: event.Evaluator, BaseOutcome: event.BaseOutcome,
		SemanticOutcome: event.SemanticOutcome, AppliedOutcome: event.AppliedOutcome,
		Applied: event.Applied, StartedAt: event.OccurredAt, CompletedAt: event.OccurredAt,
		ModelCalls: event.ModelCalls, InputTokens: event.InputTokens, OutputTokens: event.OutputTokens,
	}
	return record.Validate()
}

type UsageExporterConfig struct {
	Journal     EvaluationJournalStore
	Endpoint    string
	AckPath     string
	BearerToken string
	HTTPClient  *http.Client
	Interval    time.Duration
	BatchSize   int
}

// DurableEvaluationUsageStore keeps delivery state beside shared evaluation
// records. It removes local acknowledgement files from multi-replica fleets;
// duplicate concurrent delivery remains safe through the required remote
// idempotency key.
type DurableEvaluationUsageStore interface {
	EvaluationJournalStore
	PendingEvaluationRecords(context.Context, int) ([]EvaluationRecord, error)
	MarkEvaluationExported(context.Context, string) error
	PendingEvaluationCount(context.Context) (int, error)
}

// BatchEvaluationUsageStore atomically acknowledges a delivered cohort. It is
// optional so file-backed and third-party durable stores retain the original
// per-unit contract.
type BatchEvaluationUsageStore interface {
	DurableEvaluationUsageStore
	MarkEvaluationsExported(context.Context, []string) error
}

// UsageExportStatus is a bounded operational snapshot. It deliberately
// exposes no usage payload, endpoint, token, or raw network error: operators
// need to know whether export is keeping up without turning diagnostics into a
// second source of sensitive decision context.
type UsageExportStatus struct {
	Pending         int    `json:"pending"`
	LastAttemptAt   int64  `json:"last_attempt_at,omitempty"`
	LastSuccessAt   int64  `json:"last_success_at,omitempty"`
	LastFailureAt   int64  `json:"last_failure_at,omitempty"`
	LastFailureCode string `json:"last_failure_code,omitempty"`
}

func (status UsageExportStatus) Validate() error {
	if status.Pending < 0 || status.LastAttemptAt < 0 || status.LastSuccessAt < 0 || status.LastFailureAt < 0 {
		return fmt.Errorf("decision: invalid usage export status")
	}
	switch status.LastFailureCode {
	case "", UsageExportFailureTransport, UsageExportFailureRemoteRejected, UsageExportFailureInvalidAcknowledged, UsageExportFailureAckPersistence:
	default:
		return fmt.Errorf("decision: invalid usage export failure code")
	}
	if status.LastFailureCode != "" && status.LastFailureAt == 0 {
		return fmt.Errorf("decision: usage export failure code requires observation time")
	}
	return nil
}

// UsageExporter runs outside the authorization call path. It acknowledges a
// unit locally only after the remote endpoint returns the same unit ID; local
// ack failure causes a safe idempotent resend.
type UsageExporter struct {
	journal     EvaluationJournalStore
	endpoint    *url.URL
	ackPath     string
	bearerToken string
	httpClient  *http.Client
	interval    time.Duration
	batchSize   int

	mu     sync.Mutex
	acked  map[string]struct{}
	status UsageExportStatus
}

func NewUsageExporter(config UsageExporterConfig) (*UsageExporter, error) {
	if config.Journal == nil || config.Endpoint == "" {
		return nil, fmt.Errorf("decision: usage journal and endpoint are required")
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, fmt.Errorf("decision: invalid usage endpoint")
	}
	if endpoint.Scheme != "https" && !(endpoint.Scheme == "http" && usageLoopback(endpoint.Hostname())) {
		return nil, fmt.Errorf("decision: usage endpoint must use HTTPS")
	}
	ackPath := ""
	if _, durable := config.Journal.(DurableEvaluationUsageStore); !durable {
		if config.AckPath == "" {
			return nil, fmt.Errorf("decision: file-backed usage journal requires an ack path")
		}
		ackPath, err = filepath.Abs(filepath.Clean(config.AckPath))
		if err != nil {
			return nil, err
		}
		if info, statErr := os.Lstat(ackPath); statErr == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
				return nil, fmt.Errorf("decision: usage ack path must be an owner-only regular file")
			}
		} else if !os.IsNotExist(statErr) {
			return nil, statErr
		}
		if err := os.MkdirAll(filepath.Dir(ackPath), 0o700); err != nil {
			return nil, err
		}
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
	exporter := &UsageExporter{
		journal: config.Journal, endpoint: endpoint, ackPath: ackPath,
		bearerToken: config.BearerToken, httpClient: config.HTTPClient,
		interval: config.Interval, batchSize: config.BatchSize, acked: make(map[string]struct{}),
	}
	if err := exporter.loadAcks(); err != nil {
		return nil, err
	}
	return exporter, nil
}

func (exporter *UsageExporter) Run(ctx context.Context) error {
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

func (exporter *UsageExporter) ExportOnce(ctx context.Context) error {
	exporter.mu.Lock()
	defer exporter.mu.Unlock()
	var (
		records []EvaluationRecord
		err     error
	)
	durable, durableJournal := exporter.journal.(DurableEvaluationUsageStore)
	if durableJournal {
		records, err = durable.PendingEvaluationRecords(ctx, exporter.batchSize)
	} else {
		records, err = exporter.journal.EvaluationRecords(ctx, 0)
	}
	if err != nil {
		return fmt.Errorf("decision: load pending usage: %w", err)
	}
	attempted := 0
	var firstErr error
	failureCode := ""
	batchedAcknowledgements := make([]string, 0, len(records))
	_, batchDurable := exporter.journal.(BatchEvaluationUsageStore)
	for _, record := range records {
		if !durableJournal {
			if _, exists := exporter.acked[record.ID]; exists {
				continue
			}
		}
		if attempted >= exporter.batchSize {
			break
		}
		attempted++
		event := record.UsageEvent()
		if err := exporter.send(ctx, event); err != nil {
			if firstErr == nil {
				firstErr = err
				failureCode = usageExportFailureCode(err)
			}
			continue
		}
		if durableJournal {
			if batchDurable {
				batchedAcknowledgements = append(batchedAcknowledgements, event.UnitID)
				continue
			}
			if err := durable.MarkEvaluationExported(ctx, event.UnitID); err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("decision: persist usage acknowledgement: %w", err)
					failureCode = UsageExportFailureAckPersistence
				}
				continue
			}
			exporter.acked[event.UnitID] = struct{}{}
			continue
		}
		if err := fsutil.AppendSync(exporter.ackPath, []byte(event.UnitID+"\n")); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("decision: persist usage acknowledgement: %w", err)
				failureCode = UsageExportFailureAckPersistence
			}
			continue
		}
		exporter.acked[event.UnitID] = struct{}{}
	}
	if len(batchedAcknowledgements) > 0 {
		batchStore := exporter.journal.(BatchEvaluationUsageStore)
		if err := batchStore.MarkEvaluationsExported(ctx, batchedAcknowledgements); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("decision: persist usage acknowledgements: %w", err)
				failureCode = UsageExportFailureAckPersistence
			}
		} else {
			for _, unitID := range batchedAcknowledgements {
				exporter.acked[unitID] = struct{}{}
			}
		}
	}
	if attempted > 0 {
		now := time.Now().UTC().Unix()
		exporter.status.LastAttemptAt = now
		if firstErr != nil {
			exporter.status.LastFailureAt = now
			exporter.status.LastFailureCode = failureCode
		} else {
			exporter.status.LastSuccessAt = now
			exporter.status.LastFailureCode = ""
		}
	}
	return firstErr
}

func (exporter *UsageExporter) Pending() int {
	exporter.mu.Lock()
	defer exporter.mu.Unlock()
	return exporter.pendingLocked()
}

// Status returns the current delivery backlog and generic health markers. It
// is safe to expose on a management read path and never affects evaluation or
// authorization.
func (exporter *UsageExporter) Status() UsageExportStatus {
	if exporter == nil {
		return UsageExportStatus{}
	}
	exporter.mu.Lock()
	defer exporter.mu.Unlock()
	status := exporter.status
	status.Pending = exporter.pendingLocked()
	return status
}

func (exporter *UsageExporter) pendingLocked() int {
	if durable, ok := exporter.journal.(DurableEvaluationUsageStore); ok {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		pending, err := durable.PendingEvaluationCount(ctx)
		if err == nil {
			return pending
		}
		return exporter.status.Pending
	}
	records, err := exporter.journal.EvaluationRecords(context.Background(), 0)
	if err != nil {
		return exporter.status.Pending
	}
	pending := 0
	for _, record := range records {
		if _, exists := exporter.acked[record.ID]; !exists {
			pending++
		}
	}
	return pending
}

func usageExportFailureCode(err error) string {
	if err == nil {
		return ""
	}
	message := err.Error()
	switch {
	case strings.Contains(message, "returned HTTP"):
		return UsageExportFailureRemoteRejected
	case strings.Contains(message, "invalid acknowledgement"):
		return UsageExportFailureInvalidAcknowledged
	default:
		return UsageExportFailureTransport
	}
}

func (exporter *UsageExporter) send(ctx context.Context, event UsageEvent) error {
	if err := event.Validate(); err != nil {
		return err
	}
	body, _ := json.Marshal(event)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, exporter.endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Idempotency-Key", event.UnitID)
	if exporter.bearerToken != "" {
		request.Header.Set("Authorization", "Bearer "+exporter.bearerToken)
	}
	response, err := exporter.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("decision: export usage: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
		return fmt.Errorf("decision: usage endpoint returned HTTP %d", response.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 4<<10))
	decoder.DisallowUnknownFields()
	var acknowledgement struct {
		AcceptedUnitID string `json:"accepted_unit_id"`
	}
	if err := decoder.Decode(&acknowledgement); err != nil || acknowledgement.AcceptedUnitID != event.UnitID {
		return fmt.Errorf("decision: usage endpoint returned invalid acknowledgement")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("decision: usage endpoint returned trailing data")
	}
	return nil
}

func (exporter *UsageExporter) loadAcks() error {
	if _, durable := exporter.journal.(DurableEvaluationUsageStore); durable {
		return nil
	}
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
		unitID := scanner.Text()
		if !lowerHex(unitID, 64) {
			return fmt.Errorf("decision: invalid usage acknowledgement %q", unitID)
		}
		exporter.acked[unitID] = struct{}{}
	}
	return scanner.Err()
}

func usageLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
