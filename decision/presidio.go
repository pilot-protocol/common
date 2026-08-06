// SPDX-License-Identifier: AGPL-3.0-or-later

package decision

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// DefaultPresidioMaxBytes bounds the local buffering needed to call
	// Presidio's JSON API. Larger governed objects should be scanned by a
	// streaming local implementation rather than silently truncated.
	DefaultPresidioMaxBytes int64 = 1 << 20
	maxPresidioBytes        int64 = 8 << 20
	defaultPresidioScore          = 0.7
)

// PresidioInspector implements DisclosureContentInspector using a local
// Presidio Analyzer service. Endpoint is the base service URL; the inspector
// calls its /analyze endpoint. Run this service on the enforcement host or a
// private tenant network with transport authentication. It is deliberately an
// inspection-only hook: any detector result or service failure rejects the
// delivery, but a clean result never expands the signed Decision.
//
// The adapter accepts only textual and structured-text content types. A
// required profile consequently fails closed for binary or image files unless
// the operator provides an appropriate local inspector for those formats.
type PresidioInspector struct {
	Endpoint       string
	HTTPClient     *http.Client
	Language       string
	Entities       []string
	ScoreThreshold float64
	MaxBytes       int64
}

type presidioAnalysisRequest struct {
	Text     string   `json:"text"`
	Language string   `json:"language"`
	Entities []string `json:"entities,omitempty"`
}

type presidioFinding struct {
	EntityType string  `json:"entity_type"`
	Score      float64 `json:"score"`
}

// Validate checks the static inspector configuration before a transport starts.
// It intentionally does not make a network call; service availability remains
// a delivery-time fail-closed condition.
func (inspector PresidioInspector) Validate() error {
	if _, err := inspector.analyzeURL(); err != nil {
		return err
	}
	if _, err := inspector.maxBytes(); err != nil {
		return err
	}
	_, err := inspector.scoreThreshold()
	return err
}

// InspectDisclosureContent rejects the content when Presidio reports any
// finding at or above the configured score threshold. Its errors contain no
// inspected content or detection spans.
func (inspector PresidioInspector) InspectDisclosureContent(ctx context.Context, _ Intent, _ *DisclosureBinding, contentType, _ string, content io.Reader) error {
	analyzeURL, err := inspector.analyzeURL()
	if err != nil {
		return err
	}
	if !presidioTextContentType(contentType) {
		return fmt.Errorf("presidio: content type %q cannot be inspected as text", contentType)
	}
	maxBytes, err := inspector.maxBytes()
	if err != nil {
		return err
	}
	body, err := io.ReadAll(io.LimitReader(content, maxBytes+1))
	if err != nil {
		return fmt.Errorf("presidio: read content: %w", err)
	}
	if int64(len(body)) > maxBytes {
		return fmt.Errorf("presidio: content exceeds local inspection limit")
	}
	language := inspector.Language
	if language == "" {
		language = "en"
	}
	encoded, err := json.Marshal(presidioAnalysisRequest{Text: string(body), Language: language, Entities: inspector.Entities})
	if err != nil {
		return fmt.Errorf("presidio: encode analysis request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, analyzeURL, bytes.NewReader(encoded))
	if err != nil {
		return fmt.Errorf("presidio: create analysis request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := inspector.httpClient().Do(request)
	if err != nil {
		return fmt.Errorf("presidio: analysis request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 8<<10))
		return fmt.Errorf("presidio: analyzer returned status %d", response.StatusCode)
	}
	var findings []presidioFinding
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&findings); err != nil {
		return fmt.Errorf("presidio: decode analysis response: %w", err)
	}
	threshold, err := inspector.scoreThreshold()
	if err != nil {
		return err
	}
	for _, finding := range findings {
		if finding.Score >= threshold {
			return fmt.Errorf("presidio: sensitive content detected")
		}
	}
	return nil
}

func (inspector PresidioInspector) analyzeURL() (string, error) {
	base := strings.TrimSpace(inspector.Endpoint)
	if base == "" {
		return "", fmt.Errorf("presidio: endpoint is required")
	}
	parsed, err := url.Parse(base)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil {
		return "", fmt.Errorf("presidio: endpoint must be an absolute HTTP(S) URL without credentials")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/analyze"
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func (inspector PresidioInspector) maxBytes() (int64, error) {
	if inspector.MaxBytes == 0 {
		return DefaultPresidioMaxBytes, nil
	}
	if inspector.MaxBytes < 1 || inspector.MaxBytes > maxPresidioBytes {
		return 0, fmt.Errorf("presidio: max bytes must be 1-%d", maxPresidioBytes)
	}
	return inspector.MaxBytes, nil
}

func (inspector PresidioInspector) scoreThreshold() (float64, error) {
	if inspector.ScoreThreshold == 0 {
		return defaultPresidioScore, nil
	}
	if inspector.ScoreThreshold < 0 || inspector.ScoreThreshold > 1 {
		return 0, fmt.Errorf("presidio: score threshold must be within 0-1")
	}
	return inspector.ScoreThreshold, nil
}

func (inspector PresidioInspector) httpClient() *http.Client {
	if inspector.HTTPClient != nil {
		return inspector.HTTPClient
	}
	return &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func presidioTextContentType(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	if strings.HasPrefix(mediaType, "text/") {
		return true
	}
	switch mediaType {
	case "application/json", "application/ld+json", "application/xml", "application/x-www-form-urlencoded", "application/yaml", "application/x-yaml":
		return true
	default:
		return false
	}
}
