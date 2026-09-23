// SPDX-License-Identifier: AGPL-3.0-or-later

package netproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// Targets use the reserved .invalid TLD (RFC 2606): they cannot resolve
// locally, so a successful round-trip proves the dialer handed the proxy
// the host name instead of resolving it.
const (
	echoHost   = "echo.pilot.invalid"
	bypassHost = "bypass.pilot.invalid"
	apiHost    = "api.pilot.invalid"
)

// recordingForward is a Dialer.Forward that records every address it is
// asked to dial and maps the fake host names to loopback.
type recordingForward struct {
	mu    sync.Mutex
	addrs []string
	hosts map[string]string
}

func (f *recordingForward) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	f.mu.Lock()
	f.addrs = append(f.addrs, addr)
	f.mu.Unlock()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if real, ok := f.hosts[host]; ok {
		addr = net.JoinHostPort(real, port)
	}
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

func (f *recordingForward) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.addrs...)
}

func roundTrip(t *testing.T, c net.Conn, msg string) {
	t.Helper()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("echo mismatch: got %q want %q", buf, msg)
	}
}

func TestDialerTunnelsByHostnameAndNeverResolvesTarget(t *testing.T) {
	t.Parallel()
	echoIP, echoPort := newEchoServer(t)
	proxy := newTestProxy(t, map[string]string{echoHost: echoIP})
	fwd := &recordingForward{}
	d := &Dialer{Resolver: mustExplicit(t, proxy.url("")), Forward: fwd.dial}

	target := net.JoinHostPort(echoHost, echoPort)
	c, err := d.DialContext(context.Background(), "tcp", target)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer c.Close()
	roundTrip(t, c, "ping through the tunnel")

	targets, hostHdrs, auths := proxy.seen()
	if len(targets) != 1 || targets[0] != target {
		t.Fatalf("CONNECT targets = %q, want [%q]", targets, target)
	}
	if hostHdrs[0] != target {
		t.Fatalf("Host header = %q, want %q", hostHdrs[0], target)
	}
	if auths[0] != "" {
		t.Fatalf("unexpected Proxy-Authorization %q for a proxy URL without userinfo", auths[0])
	}
	// The only address dialed locally is the proxy's: the target host name
	// is never looked up or connected to directly.
	if got := fwd.seen(); len(got) != 1 || got[0] != proxy.addr() {
		t.Fatalf("local dials = %q, want only the proxy %q", got, proxy.addr())
	}
}

func TestDialerSendsBasicProxyAuthorization(t *testing.T) {
	t.Parallel()
	echoIP, echoPort := newEchoServer(t)
	const user, pass = "muse-agent", "s3cr3t:with@chars/and%"
	proxy := newTestProxy(t, map[string]string{echoHost: echoIP}, withAuth(user, pass))
	userinfo := url.UserPassword(user, pass).String()
	d := NewDialer(mustExplicit(t, proxy.url(userinfo)))

	c, err := d.DialContext(context.Background(), "tcp", net.JoinHostPort(echoHost, echoPort))
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer c.Close()
	roundTrip(t, c, "authenticated")

	_, _, auths := proxy.seen()
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
	if len(auths) != 1 || auths[0] != want {
		t.Fatalf("Proxy-Authorization = %q, want %q", auths, want)
	}
}

func TestDialerRejectedCONNECTNeverLeaksCredentials(t *testing.T) {
	t.Parallel()
	const user, pass = "leaky-user", "hunter2-password"
	encoded := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
	// The proxy echoes the password and the encoded header in its reason
	// phrase; none of it may reach the error.
	proxy := newTestProxy(t, nil, withReject(http.StatusProxyAuthRequired, "Denied "+user+" "+pass+" "+encoded))
	d := NewDialer(mustExplicit(t, proxy.url(user+":"+pass)))

	target := net.JoinHostPort(echoHost, "443")
	_, err := d.DialContext(context.Background(), "tcp", target)
	if err == nil {
		t.Fatal("expected an error for a 407 response")
	}
	want := "proxy CONNECT " + target + ": 407 Proxy Authentication Required"
	if err.Error() != want {
		t.Fatalf("error = %q, want %q", err.Error(), want)
	}
	var ce *ConnectError
	if !errors.As(err, &ce) || ce.StatusCode != http.StatusProxyAuthRequired || ce.Target != target {
		t.Fatalf("error %#v is not a ConnectError{407, %q}", err, target)
	}
	for _, secret := range []string{user, pass, encoded} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error %q leaks %q", err.Error(), secret)
		}
	}
	waitFor(t, "client to close the rejected conn", func() bool { return proxy.clientClosed.Load() == 1 })
}

func TestDialerNon2xxStatuses(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		status int
		want   string
	}{
		{http.StatusForbidden, "403 Forbidden"},
		{http.StatusBadGateway, "502 Bad Gateway"},
		{599, "599"},
	} {
		proxy := newTestProxy(t, nil, withReject(tc.status, "whatever the proxy says"))
		_, err := NewDialer(mustExplicit(t, proxy.url(""))).Dial("tcp", "registry.pilot.invalid:443")
		if err == nil || err.Error() != "proxy CONNECT registry.pilot.invalid:443: "+tc.want {
			t.Fatalf("status %d: error = %v, want suffix %q", tc.status, err, tc.want)
		}
	}
}

func TestDialerProxyUnreachableNeverLeaksCredentials(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	ln.Close()

	d := NewDialer(mustExplicit(t, "http://someone:topsecret@"+dead))
	_, err = d.DialContext(context.Background(), "tcp", "registry.pilot.invalid:443")
	if err == nil {
		t.Fatal("expected a dial error")
	}
	msg := err.Error()
	if strings.Contains(msg, "someone") || strings.Contains(msg, "topsecret") {
		t.Fatalf("error leaks credentials: %q", msg)
	}
	if !strings.Contains(msg, "http://***@"+dead) || !strings.Contains(msg, "registry.pilot.invalid:443") {
		t.Fatalf("error should name the redacted proxy and the target: %q", msg)
	}
}

func TestDialerHonorsNoProxy(t *testing.T) {
	t.Parallel()
	echoIP, echoPort := newEchoServer(t)
	proxy := newTestProxy(t, map[string]string{echoHost: echoIP})
	r, err := fromEnv(envMap(map[string]string{
		"HTTPS_PROXY": proxy.url("u:p"),
		"NO_PROXY":    "localhost, " + bypassHost,
	}))
	if err != nil {
		t.Fatalf("fromEnv: %v", err)
	}
	fwd := &recordingForward{hosts: map[string]string{bypassHost: echoIP, "api." + bypassHost: echoIP}}
	d := &Dialer{Resolver: r, Forward: fwd.dial}

	for _, host := range []string{bypassHost, "api." + bypassHost} {
		c, err := d.DialContext(context.Background(), "tcp", net.JoinHostPort(host, echoPort))
		if err != nil {
			t.Fatalf("direct dial %s: %v", host, err)
		}
		roundTrip(t, c, "direct")
		c.Close()
	}
	if targets, _, _ := proxy.seen(); len(targets) != 0 {
		t.Fatalf("NO_PROXY targets went through the proxy: %q", targets)
	}

	c, err := d.DialContext(context.Background(), "tcp", net.JoinHostPort(echoHost, echoPort))
	if err != nil {
		t.Fatalf("proxied dial: %v", err)
	}
	roundTrip(t, c, "proxied")
	c.Close()
	targets, _, _ := proxy.seen()
	if len(targets) != 1 || targets[0] != net.JoinHostPort(echoHost, echoPort) {
		t.Fatalf("proxy targets = %q", targets)
	}
	want := []string{
		net.JoinHostPort(bypassHost, echoPort),
		net.JoinHostPort("api."+bypassHost, echoPort),
		proxy.addr(),
	}
	if got := fwd.seen(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("local dials = %q, want %q", got, want)
	}
}

func TestDialerHTTPSProxy(t *testing.T) {
	t.Parallel()
	echoIP, echoPort := newEchoServer(t)
	cert, pool := genCert(t, []string{"proxy.pilot.invalid"}, []net.IP{net.ParseIP("127.0.0.1")})
	proxy := newTestProxy(t, map[string]string{echoHost: echoIP}, withTLS(cert), withAuth("u", "p"))
	target := net.JoinHostPort(echoHost, echoPort)

	// ServerName defaults to the proxy host (here the IP in the URL).
	d := &Dialer{
		Resolver:  mustExplicit(t, "https://u:p@"+proxy.addr()),
		TLSConfig: &tls.Config{RootCAs: pool},
	}
	c, err := d.DialContext(context.Background(), "tcp", target)
	if err != nil {
		t.Fatalf("DialContext via https proxy: %v", err)
	}
	roundTrip(t, c, "tls to the proxy, then a tunnel")
	c.Close()

	// A proxy certificate the client does not trust fails closed, and the
	// error still carries no credentials.
	d.TLSConfig = nil
	_, err = d.DialContext(context.Background(), "tcp", target)
	if err == nil {
		t.Fatal("expected an x509 error without the test root")
	}
	var cve *tls.CertificateVerificationError
	if !errors.As(err, &cve) {
		t.Fatalf("expected a certificate verification error, got %v", err)
	}
	if strings.Contains(err.Error(), "u:p") {
		t.Fatalf("error leaks credentials: %v", err)
	}
}

func TestDialerContextDeadline(t *testing.T) {
	t.Parallel()
	proxy := newTestProxy(t, nil, withHang())
	d := NewDialer(mustExplicit(t, proxy.url("")))

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := d.DialContext(ctx, "tcp", "registry.pilot.invalid:443")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("deadline not honoured: took %v", elapsed)
	}
	waitFor(t, "client to close the timed-out conn", func() bool { return proxy.clientClosed.Load() == 1 })
}

func TestDialerContextCancel(t *testing.T) {
	t.Parallel()
	proxy := newTestProxy(t, nil, withHang())
	d := NewDialer(mustExplicit(t, proxy.url("")))

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	_, err := d.DialContext(ctx, "tcp", "registry.pilot.invalid:443")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	waitFor(t, "client to close the cancelled conn", func() bool { return proxy.clientClosed.Load() == 1 })
}

func TestDialerTimeoutField(t *testing.T) {
	t.Parallel()
	proxy := newTestProxy(t, nil, withHang())
	d := &Dialer{Resolver: mustExplicit(t, proxy.url("")), Timeout: 150 * time.Millisecond}
	start := time.Now()
	_, err := d.Dial("tcp", "registry.pilot.invalid:443")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("Timeout not honoured: took %v", elapsed)
	}
}

func TestDialerAlreadyCancelledContext(t *testing.T) {
	t.Parallel()
	proxy := newTestProxy(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewDialer(mustExplicit(t, proxy.url(""))).DialContext(ctx, "tcp", "registry.pilot.invalid:443")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

// TestDialerPreservesBytesReadAheadOfCONNECTResponse uses net.Pipe so the
// proxy's response and the first tunnel bytes arrive in one read,
// deterministically: the bufio reader behind http.ReadResponse swallows
// them and the returned conn must hand them back.
func TestDialerPreservesBytesReadAheadOfCONNECTResponse(t *testing.T) {
	t.Parallel()
	clientEnd, proxyEnd := net.Pipe()
	defer proxyEnd.Close()
	go func() {
		br := bufio.NewReader(proxyEnd)
		req, err := http.ReadRequest(br)
		if err != nil || req.Method != http.MethodConnect {
			proxyEnd.Close()
			return
		}
		// One write: response head immediately followed by a server greeting.
		io.WriteString(proxyEnd, "HTTP/1.1 200 Connection established\r\n\r\nHELLO")
		io.Copy(proxyEnd, br) // then echo
	}()
	d := &Dialer{
		Resolver: mustExplicit(t, "http://proxy.pilot.invalid:3128"),
		Forward: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr != "proxy.pilot.invalid:3128" {
				t.Errorf("forward dial to %q, want the proxy", addr)
			}
			return clientEnd, nil
		},
	}
	c, err := d.DialContext(context.Background(), "tcp", "server-speaks-first.pilot.invalid:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer c.Close()
	if _, ok := c.(*bufferedConn); !ok {
		t.Fatalf("conn type %T, want *bufferedConn when bytes were read ahead", c)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	greeting := make([]byte, 5)
	if _, err := io.ReadFull(c, greeting); err != nil || string(greeting) != "HELLO" {
		t.Fatalf("greeting = %q, %v; want HELLO", greeting, err)
	}
	roundTrip(t, c, "and the stream continues")
}

func TestDialerReturnsRawConnWithoutReadAhead(t *testing.T) {
	t.Parallel()
	echoIP, echoPort := newEchoServer(t)
	proxy := newTestProxy(t, map[string]string{echoHost: echoIP})
	c, err := NewDialer(mustExplicit(t, proxy.url(""))).Dial("tcp", net.JoinHostPort(echoHost, echoPort))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()
	if _, ok := c.(*net.TCPConn); !ok {
		t.Fatalf("conn type %T, want the raw *net.TCPConn", c)
	}
	if dl := deadlineCleared(t, c); !dl {
		t.Fatal("handshake deadline was left on the conn")
	}
}

// deadlineCleared checks that a blocking read is not cut short by a stale
// handshake deadline (the echo server sends nothing unprompted).
func deadlineCleared(t *testing.T, c net.Conn) bool {
	t.Helper()
	errc := make(chan error, 1)
	go func() {
		_, err := c.Read(make([]byte, 1))
		errc <- err
	}()
	select {
	case err := <-errc:
		t.Logf("read returned early: %v", err)
		return false
	case <-time.After(200 * time.Millisecond):
		c.SetReadDeadline(time.Now()) // unblock the reader
		<-errc
		return true
	}
}

func TestDialerDirectWithoutProxy(t *testing.T) {
	t.Parallel()
	for name, r := range map[string]*Resolver{"nil": nil, "off": Off()} {
		fwd := &recordingForward{hosts: map[string]string{"direct.pilot.invalid": "127.0.0.1"}}
		echoIP, echoPort := newEchoServer(t)
		fwd.hosts["direct.pilot.invalid"] = echoIP
		d := &Dialer{Resolver: r, Forward: fwd.dial}
		c, err := d.Dial("tcp", net.JoinHostPort("direct.pilot.invalid", echoPort))
		if err != nil {
			t.Fatalf("%s: Dial: %v", name, err)
		}
		roundTrip(t, c, "direct")
		c.Close()
		if got := fwd.seen(); len(got) != 1 || got[0] != net.JoinHostPort("direct.pilot.invalid", echoPort) {
			t.Fatalf("%s: forward dials = %q", name, got)
		}
	}

	// A nil *Dialer dials directly too.
	echoIP, echoPort := newEchoServer(t)
	var nd *Dialer
	c, err := nd.Dial("tcp", net.JoinHostPort(echoIP, echoPort))
	if err != nil {
		t.Fatalf("nil Dialer: %v", err)
	}
	c.Close()
}

func TestDialerRejectsBadTargetsBeforeDialing(t *testing.T) {
	t.Parallel()
	d := &Dialer{
		Resolver: mustExplicit(t, "http://proxy.pilot.invalid:3128"),
		Forward: func(context.Context, string, string) (net.Conn, error) {
			t.Error("forward dialer must not be called for a rejected target")
			return nil, errors.New("unreachable")
		},
	}
	for _, addr := range []string{
		"no-port.pilot.invalid",
		":443",
		"evil.pilot.invalid:443\r\nX-Injected: 1",
		"evil.pilot.invalid:443 HTTP/1.0",
	} {
		if _, err := d.Dial("tcp", addr); err == nil || !strings.Contains(err.Error(), "invalid target address") {
			t.Fatalf("Dial(%q) error = %v, want invalid target address", addr, err)
		}
	}
	if _, err := d.Dial("udp", "dns.pilot.invalid:53"); err == nil || !strings.Contains(err.Error(), `cannot tunnel network "udp"`) {
		t.Fatalf("udp through proxy: error = %v", err)
	}
}

// TestProxyForRequestDrivesHTTPTransport shows that an http.Transport using
// ProxyForRequest takes the same path as the Dialer: CONNECT by host name,
// Basic credentials from the URL, TLS end-to-end with the real server.
func TestProxyForRequestDrivesHTTPTransport(t *testing.T) {
	t.Parallel()
	cert, pool := genCert(t, []string{apiHost}, nil)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello "+r.Host)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	defer srv.Close()
	srvIP, srvPort, _ := net.SplitHostPort(srv.Listener.Addr().String())

	proxy := newTestProxy(t, map[string]string{apiHost: srvIP}, withAuth("agent", "pw"))
	r, err := fromEnv(envMap(map[string]string{"HTTPS_PROXY": proxy.url("agent:pw")}))
	if err != nil {
		t.Fatalf("fromEnv: %v", err)
	}
	tr := &http.Transport{Proxy: r.ProxyForRequest, TLSClientConfig: &tls.Config{RootCAs: pool}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	target := net.JoinHostPort(apiHost, srvPort)
	resp, err := client.Get("https://" + target + "/v1")
	if err != nil {
		t.Fatalf("GET via proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "hello "+target {
		t.Fatalf("response %d %q", resp.StatusCode, body)
	}
	targets, _, auths := proxy.seen()
	if len(targets) != 1 || targets[0] != target {
		t.Fatalf("CONNECT targets = %q, want [%q]", targets, target)
	}
	if auths[0] != basicAuth("agent", "pw") {
		t.Fatalf("Proxy-Authorization = %q", auths[0])
	}
	// Same decision the Dialer would make for the same target.
	fromAddr, _ := r.ProxyForAddr(target)
	req, _ := http.NewRequest(http.MethodGet, "https://"+target, nil)
	fromReq, _ := r.ProxyForRequest(req)
	if fromAddr.String() != fromReq.String() {
		t.Fatalf("ProxyForAddr %v != ProxyForRequest %v", fromAddr, fromReq)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
