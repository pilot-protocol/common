// SPDX-License-Identifier: AGPL-3.0-or-later

package netproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// apiServer is an HTTPS server reachable only as apiHost through the test
// proxy. It answers "<method> <body>" and records what it received.
type apiServer struct {
	ip, port string
	pool     *x509.CertPool

	mu   sync.Mutex
	seen []string // "<method> <body>" per request
}

func newAPIServer(t *testing.T) *apiServer {
	t.Helper()
	cert, pool := genCert(t, []string{apiHost}, nil)
	s := &apiServer{pool: pool}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		line := r.Method + " " + string(body)
		s.mu.Lock()
		s.seen = append(s.seen, line)
		s.mu.Unlock()
		io.WriteString(w, line)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	// A tunnel the client abandons before TLS (a vetoed CONNECT) makes the
	// server log a handshake EOF; it is expected noise.
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	s.ip, s.port, _ = net.SplitHostPort(srv.Listener.Addr().String())
	return s
}

func (s *apiServer) url(path string) string {
	return "https://" + net.JoinHostPort(apiHost, s.port) + path
}

func (s *apiServer) requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.seen...)
}

func (s *apiServer) base() *http.Transport {
	return &http.Transport{TLSClientConfig: &tls.Config{RootCAs: s.pool}}
}

func do(t *testing.T, c *http.Client, method, rawURL string, body io.Reader) (string, error) {
	t.Helper()
	req, err := http.NewRequest(method, rawURL, body)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s %s: status %d", method, rawURL, resp.StatusCode)
	}
	return string(b), nil
}

// Pins what net/http itself reports when a proxy refuses CONNECT: only the
// proxy's reason phrase as a plain error — no status code, "unknown status
// code" without a phrase, the proxy's own words otherwise, and "malformed
// HTTP status code" for a status line it cannot parse. Matching on that
// text cannot tell a 407 apart, which is why RefreshingTransport reads the
// status from OnProxyConnectResponse instead.
func TestNetHTTPReportsRefusedCONNECTWithoutStatusCode(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		line string
		want string
	}{
		{"HTTP/1.1 407 Proxy Authentication Required", "Proxy Authentication Required"},
		{"HTTP/1.1 407", "unknown status code"},
		{"HTTP/1.1 407 Denied muse-agent:hunter2", "Denied muse-agent:hunter2"},
		{"HTTP/1.1 407Proxy Authentication Required", `malformed HTTP status code "407Proxy"`},
	} {
		proxy := newTestProxy(t, nil, withAuth("u", "p"), withRejectLine(tc.line))
		pu, _ := url.Parse(proxy.url("u:stale"))
		tr := &http.Transport{Proxy: http.ProxyURL(pu)}
		req, _ := http.NewRequest(http.MethodGet, "https://api.pilot.invalid/", nil)
		_, err := tr.RoundTrip(req)
		if err == nil || err.Error() != tc.want {
			t.Fatalf("%q: net/http error = %v, want %q", tc.line, err, tc.want)
		}
		var ce *ConnectError
		if errors.As(err, &ce) {
			t.Fatalf("%q: plain net/http error unexpectedly typed", tc.line)
		}
		tr.CloseIdleConnections()
	}
}

// A GET survives a rotation: a pooled tunnel keeps working without a new
// CONNECT, and the next new connection is refused, refreshed and retried.
func TestRefreshingTransportRetriesGETAfterRotation(t *testing.T) {
	t.Parallel()
	api := newAPIServer(t)
	proxy := newTestProxy(t, map[string]string{apiHost: api.ip})
	creds := newCredSource(t, proxy)
	r, err := NewResolver(proxy.url("launch:time"), WithRefreshCommand(creds.command()), WithRefreshInterval(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: RefreshingTransport(api.base(), r), Timeout: 10 * time.Second}
	defer client.CloseIdleConnections()

	if got, err := do(t, client, http.MethodGet, api.url("/1"), nil); err != nil || got != "GET " {
		t.Fatalf("GET 1 = %q, %v", got, err)
	}
	creds.rotate()
	// The idle tunnel from GET 1 was opened with the old credentials and is
	// still up: no new CONNECT, no refresh.
	if got, err := do(t, client, http.MethodGet, api.url("/2"), nil); err != nil || got != "GET " {
		t.Fatalf("GET 2 on the pooled tunnel = %q, %v", got, err)
	}
	if targets, _, _ := proxy.seen(); len(targets) != 1 || creds.runs() != 1 {
		t.Fatalf("pooled request opened %d CONNECTs, ran the command %d times", len(targets), creds.runs())
	}

	client.CloseIdleConnections()
	if got, err := do(t, client, http.MethodGet, api.url("/3"), nil); err != nil || got != "GET " {
		t.Fatalf("GET 3 after a rotation = %q, %v", got, err)
	}
	if got := proxy.rejected.Load(); got != 1 {
		t.Fatalf("proxy rejected %d CONNECTs, want 1", got)
	}
	if got := creds.runs(); got != 2 {
		t.Fatalf("command ran %d times, want 2", got)
	}
	if got := api.requests(); len(got) != 3 {
		t.Fatalf("server saw %d requests, want 3: %q", len(got), got)
	}
}

// A POST whose body cannot be rewound is not retried, but the refresh still
// happens, so the next request goes out with fresh credentials. With
// GetBody, the POST is retried: the proxy refused the tunnel, so the server
// never saw the first attempt, and it sees the body exactly once.
func TestRefreshingTransportPOST(t *testing.T) {
	t.Parallel()
	api := newAPIServer(t)
	proxy := newTestProxy(t, map[string]string{apiHost: api.ip})
	creds := newCredSource(t, proxy)
	r, err := NewResolver(proxy.url("launch:time"), WithRefreshCommand(creds.command()), WithRefreshInterval(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	base := api.base()
	base.DisableKeepAlives = true // every request opens a new tunnel
	client := &http.Client{Transport: RefreshingTransport(base, r), Timeout: 10 * time.Second}

	creds.rotate()
	oneShot := io.NopCloser(strings.NewReader("not rewindable")) // no GetBody
	_, err = do(t, client, http.MethodPost, api.url("/post"), oneShot)
	var ce *ConnectError
	if !errors.As(err, &ce) || ce.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("POST without GetBody: error = %v, want a 407 ConnectError", err)
	}
	if got := proxy.rejected.Load(); got != 1 {
		t.Fatalf("POST without GetBody was retried: %d rejected CONNECTs", got)
	}
	if got := api.requests(); len(got) != 0 {
		t.Fatalf("server saw %q", got)
	}
	if got := creds.runs(); got != 2 {
		t.Fatalf("command ran %d times, want 2: the refresh happens even without a retry", got)
	}
	if got, err := do(t, client, http.MethodGet, api.url("/after"), nil); err != nil || got != "GET " {
		t.Fatalf("GET after the refused POST = %q, %v", got, err)
	}
	if got, runs := proxy.rejected.Load(), creds.runs(); got != 1 || runs != 2 {
		t.Fatalf("GET after the refresh: rejected %d, runs %d; want 1 and 2", got, runs)
	}

	creds.rotate()
	got, err := do(t, client, http.MethodPost, api.url("/post"), strings.NewReader("rewindable")) // GetBody set
	if err != nil || got != "POST rewindable" {
		t.Fatalf("POST with GetBody = %q, %v", got, err)
	}
	if n := proxy.rejected.Load(); n != 2 {
		t.Fatalf("rejected %d CONNECTs, want 2", n)
	}
	posts := 0
	for _, line := range api.requests() {
		if strings.HasPrefix(line, "POST") {
			posts++
		}
	}
	if posts != 1 {
		t.Fatalf("server saw %d POSTs, want exactly 1: %q", posts, api.requests())
	}
}

// Every refused CONNECT becomes a *ConnectError whose message carries none
// of the proxy's text; statuses other than 407 are not retried.
func TestRefreshingTransportConnectErrorsAreTypedAndRedacted(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusProxyAuthRequired, http.StatusForbidden} {
		proxy := newTestProxy(t, nil, withReject(status, "Denied muse-agent:hunter2"))
		r, err := fromEnv(envMap(map[string]string{"HTTPS_PROXY": proxy.url("muse-agent:hunter2")}))
		if err != nil {
			t.Fatal(err)
		}
		client := &http.Client{Transport: RefreshingTransport(nil, r), Timeout: 10 * time.Second}
		_, err = do(t, client, http.MethodGet, "https://api.pilot.invalid/", nil)
		var ce *ConnectError
		if !errors.As(err, &ce) || ce.StatusCode != status || ce.Target != "api.pilot.invalid:443" {
			t.Fatalf("status %d: error = %v", status, err)
		}
		if strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "Denied") {
			t.Fatalf("status %d: error leaks proxy text: %q", status, err)
		}
		// 407: the environment was re-read, unchanged, so no retry.
		if targets, _, _ := proxy.seen(); len(targets) != 1 {
			t.Fatalf("status %d: %d CONNECTs, want 1", status, len(targets))
		}
		client.CloseIdleConnections()
	}
}

// A garbled rejection also refreshes; the GET is retried, a POST (even
// with GetBody) is not, since such an error could have come from the
// server.
func TestRefreshingTransportMalformedRejection(t *testing.T) {
	t.Parallel()
	api := newAPIServer(t)
	proxy := newTestProxy(t, map[string]string{apiHost: api.ip}, withRejectLine("HTTP/1.1 407Proxy Authentication Required"))
	creds := newCredSource(t, proxy)
	r, err := NewResolver(proxy.url("launch:time"), WithRefreshCommand(creds.command()), WithRefreshInterval(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	base := api.base()
	base.DisableKeepAlives = true
	client := &http.Client{Transport: RefreshingTransport(base, r), Timeout: 10 * time.Second}

	creds.rotate()
	if got, err := do(t, client, http.MethodGet, api.url("/"), nil); err != nil || got != "GET " {
		t.Fatalf("GET after a garbled 407 = %q, %v", got, err)
	}
	creds.rotate()
	_, err = do(t, client, http.MethodPost, api.url("/"), strings.NewReader("x"))
	if err == nil || !strings.Contains(err.Error(), "malformed HTTP status code") {
		t.Fatalf("POST after a garbled 407: error = %v", err)
	}
	if got, runs := proxy.rejected.Load(), creds.runs(); got != 2 || runs != 3 {
		t.Fatalf("rejected %d, runs %d; want 2 and 3 (POST refreshed, not retried)", got, runs)
	}
}

// base's own OnProxyConnectResponse runs first and can veto the tunnel.
func TestRefreshingTransportChainsBaseHook(t *testing.T) {
	t.Parallel()
	api := newAPIServer(t)
	proxy := newTestProxy(t, map[string]string{apiHost: api.ip})
	base := api.base()
	var hooked []int
	var mu sync.Mutex
	veto := errors.New("vetoed by base hook")
	base.OnProxyConnectResponse = func(_ context.Context, _ *url.URL, _ *http.Request, res *http.Response) error {
		mu.Lock()
		defer mu.Unlock()
		hooked = append(hooked, res.StatusCode)
		if len(hooked) > 1 {
			return veto
		}
		return nil
	}
	client := &http.Client{Transport: RefreshingTransport(base, mustExplicit(t, proxy.url(""))), Timeout: 10 * time.Second}
	if _, err := do(t, client, http.MethodGet, api.url("/"), nil); err != nil {
		t.Fatalf("GET: %v", err)
	}
	client.CloseIdleConnections() // reaches the transport's copy of base
	if _, err := do(t, client, http.MethodGet, api.url("/"), nil); !errors.Is(err, veto) {
		t.Fatalf("GET 2: error = %v, want the base hook's", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(hooked) != 2 || hooked[0] != http.StatusOK {
		t.Fatalf("base hook saw %v", hooked)
	}
}

func TestCanReplay(t *testing.T) {
	t.Parallel()
	req := func(method string, body io.Reader, hdr ...string) *http.Request {
		r, _ := http.NewRequest(method, "https://x.invalid/", body)
		for _, h := range hdr {
			r.Header.Set(h, "k")
		}
		return r
	}
	oneShot := func() io.Reader { return io.NopCloser(strings.NewReader("b")) }
	for _, tc := range []struct {
		name      string
		req       *http.Request
		neverSent bool
		want      bool
	}{
		{"GET", req(http.MethodGet, nil), false, true},
		{"HEAD", req(http.MethodHead, nil), false, true},
		{"OPTIONS", req(http.MethodOptions, nil), false, true},
		{"GET with one-shot body", req(http.MethodGet, oneShot()), true, false},
		{"POST no body", req(http.MethodPost, nil), true, false},
		{"POST one-shot body", req(http.MethodPost, oneShot()), true, false},
		{"POST GetBody, refused tunnel", req(http.MethodPost, strings.NewReader("b")), true, true},
		{"POST GetBody, maybe sent", req(http.MethodPost, strings.NewReader("b")), false, false},
		{"POST Idempotency-Key", req(http.MethodPost, strings.NewReader("b"), "Idempotency-Key"), false, true},
		{"PUT X-Idempotency-Key no body", req(http.MethodPut, nil, "X-Idempotency-Key"), false, true},
		{"DELETE", req(http.MethodDelete, nil), false, false},
	} {
		if got := canReplay(tc.req, tc.neverSent); got != tc.want {
			t.Errorf("%s: canReplay = %v, want %v", tc.name, got, tc.want)
		}
	}
}
