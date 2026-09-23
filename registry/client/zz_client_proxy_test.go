// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pilot-protocol/common/netproxy"
	"github.com/pilot-protocol/common/registry/wire"
)

// Registry dials through an HTTP CONNECT proxy (WithDialer + netproxy).
//
// The registry is only reachable as registry.pilot.invalid — a reserved TLD
// that never resolves locally — and only through the test proxy, which maps
// that name to the loopback listener. A successful round-trip therefore
// proves the client handed the proxy the host name, and every CONNECT the
// proxy records must name registry.pilot.invalid, never an IP.

const proxiedRegistryHost = "registry.pilot.invalid"

// --- CONNECT proxy ----------------------------------------------------------

type regTestProxy struct {
	ln       net.Listener
	realHost string // what proxiedRegistryHost maps to
	wantAuth string

	mu      sync.Mutex
	targets []string
	live    []net.Conn
	wg      sync.WaitGroup
}

func newRegTestProxy(t *testing.T, realHost, user, pass string) *regTestProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	p := &regTestProxy{ln: ln, realHost: realHost}
	if user != "" {
		req := &http.Request{Header: http.Header{}}
		req.SetBasicAuth(user, pass)
		p.wantAuth = req.Header.Get("Authorization")
	}
	p.wg.Add(1)
	go p.accept()
	t.Cleanup(func() {
		ln.Close()
		p.mu.Lock()
		for _, c := range p.live {
			c.Close()
		}
		p.mu.Unlock()
		p.wg.Wait()
	})
	return p
}

func (p *regTestProxy) track(c net.Conn) {
	p.mu.Lock()
	p.live = append(p.live, c)
	p.mu.Unlock()
}

func (p *regTestProxy) connects() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.targets...)
}

func (p *regTestProxy) accept() {
	defer p.wg.Done()
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.track(conn)
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			p.serve(conn)
		}()
	}
}

func (p *regTestProxy) serve(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	p.mu.Lock()
	p.targets = append(p.targets, req.RequestURI)
	p.mu.Unlock()
	if req.Method != http.MethodConnect {
		fmt.Fprint(conn, "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
		return
	}
	if p.wantAuth != "" && req.Header.Get("Proxy-Authorization") != p.wantAuth {
		fmt.Fprint(conn, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
		return
	}
	host, port, err := net.SplitHostPort(req.RequestURI)
	if err != nil || host != proxiedRegistryHost {
		fmt.Fprint(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	up, err := net.DialTimeout("tcp", net.JoinHostPort(p.realHost, port), 5*time.Second)
	if err != nil {
		fmt.Fprint(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	p.track(up)
	defer up.Close()
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, br); up.Close(); done <- struct{}{} }()
	go func() { io.Copy(conn, up); conn.Close(); done <- struct{}{} }()
	<-done
	<-done
}

// --- registry-like servers ---------------------------------------------------

// genProxiedRegistryCert issues a self-signed certificate for
// registry.pilot.invalid only (no IP SANs), plus a pool trusting it and the
// DER-encoded leaf for pin fingerprints.
func genProxiedRegistryCert(t *testing.T) (tls.Certificate, *x509.CertPool, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: proxiedRegistryHost},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{proxiedRegistryHost},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool, der
}

// proxiedRegistry is a JSON-wire registry stand-in (TLS or plain TCP) on
// loopback. Its handler closes the connection without answering the first
// {"type":"drop"} request, which forces the client down its reconnect path.
type proxiedRegistry struct {
	ln      net.Listener
	pool    *x509.CertPool
	der     []byte
	conns   atomic.Int32
	dropped atomic.Bool

	mu   sync.Mutex
	snis []string
	live []net.Conn
	wg   sync.WaitGroup
}

func newProxiedRegistry(t *testing.T, useTLS bool) *proxiedRegistry {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &proxiedRegistry{}
	if useTLS {
		cert, pool, der := genProxiedRegistryCert(t)
		s.pool, s.der = pool, der
		ln = tls.NewListener(ln, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				s.mu.Lock()
				s.snis = append(s.snis, hello.ServerName)
				s.mu.Unlock()
				return nil, nil
			},
		})
	}
	s.ln = ln
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			s.conns.Add(1)
			s.mu.Lock()
			s.live = append(s.live, conn)
			s.mu.Unlock()
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				handleJSONOverConn(conn, s.handle)
			}()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		s.mu.Lock()
		for _, c := range s.live {
			c.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
	})
	return s
}

func (s *proxiedRegistry) handle(req map[string]interface{}) map[string]interface{} {
	if req["type"] == "drop" && s.dropped.CompareAndSwap(false, true) {
		return nil // close without answering
	}
	return map[string]interface{}{"type": "ok", "echo": req}
}

// target is the only address the client is given: the unresolvable name
// plus the real listener's port.
func (s *proxiedRegistry) target() string {
	_, port, _ := net.SplitHostPort(s.ln.Addr().String())
	return net.JoinHostPort(proxiedRegistryHost, port)
}

func (s *proxiedRegistry) realHost() string {
	host, _, _ := net.SplitHostPort(s.ln.Addr().String())
	return host
}

func (s *proxiedRegistry) fingerprint() string {
	sum := sha256.Sum256(s.der)
	return hex.EncodeToString(sum[:])
}

func (s *proxiedRegistry) serverNames() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.snis...)
}

// proxyDialer is the production wiring: a netproxy.Dialer for an explicit
// authenticated proxy URL, passed as a method value.
func proxyDialer(t *testing.T, p *regTestProxy) DialOption {
	t.Helper()
	r, err := netproxy.Explicit("http://muse:s3cret@" + p.ln.Addr().String())
	if err != nil {
		t.Fatalf("netproxy.Explicit: %v", err)
	}
	return WithDialer(netproxy.NewDialer(r).DialContext)
}

func mustSendOK(t *testing.T, c *Client, typ string) {
	t.Helper()
	resp, err := c.Send(map[string]interface{}{"type": typ})
	if err != nil {
		t.Fatalf("Send(%s): %v", typ, err)
	}
	if resp["type"] != "ok" {
		t.Fatalf("Send(%s) type = %v", typ, resp["type"])
	}
}

// assertConnects checks that the proxy saw exactly n CONNECTs, all for the
// registry host name.
func assertConnects(t *testing.T, p *regTestProxy, s *proxiedRegistry, n int) {
	t.Helper()
	got := p.connects()
	if len(got) != n {
		t.Fatalf("proxy saw %d CONNECTs %q, want %d", len(got), got, n)
	}
	for _, target := range got {
		if target != s.target() {
			t.Fatalf("CONNECT target %q, want %q (host name, never an IP)", target, s.target())
		}
	}
}

// --- TLS: primary, pinned, pools, reconnects --------------------------------

func TestDialTLSThroughProxyVerifiesRegistryHostname(t *testing.T) {
	t.Parallel()
	srv := newProxiedRegistry(t, true)
	proxy := newRegTestProxy(t, srv.realHost(), "muse", "s3cret")

	// No ServerName: it must come from the registry address, as with a
	// direct tls.Dial, and the caller's config must not be mutated.
	cfg := &tls.Config{RootCAs: srv.pool, MinVersion: tls.VersionTLS12}
	c, err := DialTLS(srv.target(), cfg, proxyDialer(t, proxy))
	if err != nil {
		t.Fatalf("DialTLS via proxy: %v", err)
	}
	defer c.Close()
	mustSendOK(t, c, "hello")

	if cfg.ServerName != "" {
		t.Fatalf("caller tls.Config mutated: ServerName=%q", cfg.ServerName)
	}
	if _, ok := c.conn.(*tls.Conn); !ok {
		t.Fatalf("conn type %T, want *tls.Conn", c.conn)
	}
	if snis := srv.serverNames(); len(snis) != 1 || snis[0] != proxiedRegistryHost {
		t.Fatalf("registry saw SNI %q, want %q", snis, proxiedRegistryHost)
	}
	assertConnects(t, proxy, srv, 1)
}

func TestDialTLSThroughProxyRejectsUntrustedCert(t *testing.T) {
	t.Parallel()
	srv := newProxiedRegistry(t, true)
	proxy := newRegTestProxy(t, srv.realHost(), "muse", "s3cret")
	_, err := DialTLS(srv.target(), &tls.Config{MinVersion: tls.VersionTLS12}, proxyDialer(t, proxy))
	// UnknownAuthorityError, or SystemRootsError on a host without a CA
	// bundle; crypto/tls wraps both in CertificateVerificationError.
	var cve *tls.CertificateVerificationError
	if !errors.As(err, &cve) {
		t.Fatalf("DialTLS with system roots against a self-signed registry: %v, want a certificate verification error", err)
	}
}

func TestDialTLSPinnedThroughProxy(t *testing.T) {
	t.Parallel()
	srv := newProxiedRegistry(t, true)
	proxy := newRegTestProxy(t, srv.realHost(), "muse", "s3cret")

	c, err := DialTLSPinned(srv.target(), srv.fingerprint(), proxyDialer(t, proxy))
	if err != nil {
		t.Fatalf("DialTLSPinned via proxy: %v", err)
	}
	mustSendOK(t, c, "hello")
	c.Close()
	// Pinned mode still sends SNI, so an SNI-routed :443 front end works.
	if snis := srv.serverNames(); len(snis) != 1 || snis[0] != proxiedRegistryHost {
		t.Fatalf("registry saw SNI %q, want %q", snis, proxiedRegistryHost)
	}

	wrong := strings.Repeat("00", sha256.Size)
	_, err = DialTLSPinned(srv.target(), wrong, proxyDialer(t, proxy))
	if err == nil || !strings.Contains(err.Error(), "certificate fingerprint mismatch") {
		t.Fatalf("wrong pin: err = %v, want fingerprint mismatch", err)
	}
	assertConnects(t, proxy, srv, 2)
}

func TestDialTLSPoolThroughProxy(t *testing.T) {
	t.Parallel()
	srv := newProxiedRegistry(t, true)
	proxy := newRegTestProxy(t, srv.realHost(), "muse", "s3cret")

	c, err := DialTLSPool(srv.target(), &tls.Config{RootCAs: srv.pool, MinVersion: tls.VersionTLS12}, 3, proxyDialer(t, proxy))
	if err != nil {
		t.Fatalf("DialTLSPool via proxy: %v", err)
	}
	defer c.Close()
	if len(c.pool.entries) != 3 {
		t.Fatalf("pool entries = %d, want 3", len(c.pool.entries))
	}
	var wg sync.WaitGroup
	errs := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := c.Send(map[string]interface{}{"type": fmt.Sprintf("q%d", i)}); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent Send over proxied pool: %v", err)
	}
	assertConnects(t, proxy, srv, 3)
	if got := srv.conns.Load(); got != 3 {
		t.Fatalf("registry accepted %d conns, want 3", got)
	}
}

func TestDialTLSPinnedPoolThroughProxy(t *testing.T) {
	t.Parallel()
	srv := newProxiedRegistry(t, true)
	proxy := newRegTestProxy(t, srv.realHost(), "muse", "s3cret")

	c, err := DialTLSPinnedPool(srv.target(), srv.fingerprint(), 2, proxyDialer(t, proxy))
	if err != nil {
		t.Fatalf("DialTLSPinnedPool via proxy: %v", err)
	}
	defer c.Close()
	mustSendOK(t, c, "hello")
	assertConnects(t, proxy, srv, 2)

	_, err = DialTLSPinnedPool(srv.target(), strings.Repeat("ab", sha256.Size), 2, proxyDialer(t, proxy))
	if err == nil || !strings.Contains(err.Error(), "dial registry TLS pinned") {
		t.Fatalf("wrong pin: err = %v", err)
	}
}

func TestReconnectTLSThroughProxy(t *testing.T) {
	t.Parallel()
	srv := newProxiedRegistry(t, true)
	proxy := newRegTestProxy(t, srv.realHost(), "muse", "s3cret")

	c, err := DialTLS(srv.target(), &tls.Config{RootCAs: srv.pool, MinVersion: tls.VersionTLS12}, proxyDialer(t, proxy))
	if err != nil {
		t.Fatalf("DialTLS: %v", err)
	}
	defer c.Close()
	// The server drops the conn on "drop"; Send must reconnect through the
	// proxy (not directly) and retry.
	mustSendOK(t, c, "drop")
	mustSendOK(t, c, "after")
	assertConnects(t, proxy, srv, 2)
	if got := srv.conns.Load(); got != 2 {
		t.Fatalf("registry accepted %d conns, want 2", got)
	}
}

func TestReconnectPinnedThroughProxy(t *testing.T) {
	t.Parallel()
	srv := newProxiedRegistry(t, true)
	proxy := newRegTestProxy(t, srv.realHost(), "muse", "s3cret")

	c, err := DialTLSPinned(srv.target(), srv.fingerprint(), proxyDialer(t, proxy))
	if err != nil {
		t.Fatalf("DialTLSPinned: %v", err)
	}
	defer c.Close()
	mustSendOK(t, c, "drop")
	assertConnects(t, proxy, srv, 2)
}

func TestPoolReconnectTLSThroughProxy(t *testing.T) {
	t.Parallel()
	srv := newProxiedRegistry(t, true)
	proxy := newRegTestProxy(t, srv.realHost(), "muse", "s3cret")

	c, err := DialTLSPool(srv.target(), &tls.Config{RootCAs: srv.pool, MinVersion: tls.VersionTLS12}, 2, proxyDialer(t, proxy))
	if err != nil {
		t.Fatalf("DialTLSPool: %v", err)
	}
	defer c.Close()
	// reconnectEntry redials only the broken entry, through the proxy.
	// Hold the other entry so the dropped request cannot be served by it
	// and must redial.
	release := holdIdleEntries(t, c, 1)
	mustSendOK(t, c, "drop")
	release()
	mustSendOK(t, c, "after")
	assertConnects(t, proxy, srv, 3)
	if got := srv.conns.Load(); got != 3 {
		t.Fatalf("registry accepted %d conns, want 3", got)
	}
	// Every pool entry is a TLS conn to the registry host.
	for i, e := range c.pool.entries {
		tc, ok := e.conn.(*tls.Conn)
		if !ok {
			t.Fatalf("entry %d conn %T, want *tls.Conn", i, e.conn)
		}
		if sn := tc.ConnectionState().ServerName; sn != proxiedRegistryHost {
			t.Fatalf("entry %d ServerName %q", i, sn)
		}
	}
}

// --- plain TCP and binary clients -------------------------------------------

func TestDialAndDialPoolThroughProxy(t *testing.T) {
	t.Parallel()
	srv := newProxiedRegistry(t, false)
	proxy := newRegTestProxy(t, srv.realHost(), "muse", "s3cret")

	c, err := Dial(srv.target(), proxyDialer(t, proxy))
	if err != nil {
		t.Fatalf("Dial via proxy: %v", err)
	}
	mustSendOK(t, c, "drop") // primary reconnect through the proxy
	c.Close()
	assertConnects(t, proxy, srv, 2)

	pc, err := DialPool(srv.target(), 3, proxyDialer(t, proxy))
	if err != nil {
		t.Fatalf("DialPool via proxy: %v", err)
	}
	defer pc.Close()
	mustSendOK(t, pc, "hello")
	assertConnects(t, proxy, srv, 5)
}

func TestDialBinaryThroughProxy(t *testing.T) {
	t.Parallel()
	srv := newFakeBinaryServer(t, func(msgType byte, payload []byte) (byte, []byte) {
		body, _ := json.Marshal(map[string]interface{}{"type": "ok"})
		return wire.MsgJSON, body
	})
	host, port, _ := net.SplitHostPort(srv.addr())
	proxy := newRegTestProxy(t, host, "muse", "s3cret")
	target := net.JoinHostPort(proxiedRegistryHost, port)

	c, err := DialBinary(target, proxyDialer(t, proxy))
	if err != nil {
		t.Fatalf("DialBinary via proxy: %v", err)
	}
	defer c.Close()
	if resp, err := c.SendJSON(map[string]interface{}{"type": "x"}); err != nil || resp["type"] != "ok" {
		t.Fatalf("SendJSON: %v %v", resp, err)
	}
	// Break the conn; the reconnect must go through the proxy again.
	c.mu.Lock()
	c.conn.Close()
	c.mu.Unlock()
	if resp, err := c.SendJSON(map[string]interface{}{"type": "y"}); err != nil || resp["type"] != "ok" {
		t.Fatalf("SendJSON after reconnect: %v %v", resp, err)
	}
	got := proxy.connects()
	if len(got) != 2 || got[0] != target || got[1] != target {
		t.Fatalf("CONNECTs = %q, want 2 x %q", got, target)
	}
	if n := srv.handshakes.Load(); n != 2 {
		t.Fatalf("binary handshakes = %d, want 2", n)
	}
}

// --- WithDialer contract ------------------------------------------------------

func TestWithDialerReceivesUnresolvedAddrAndBoundedContext(t *testing.T) {
	t.Parallel()
	srv := newProxiedRegistry(t, false)
	var calls atomic.Int32
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		calls.Add(1)
		if network != "tcp" || addr != srv.target() {
			return nil, fmt.Errorf("dial(%q, %q): want tcp and the unresolved registry address", network, addr)
		}
		dl, ok := ctx.Deadline()
		if !ok || time.Until(dl) > dialTimeout {
			return nil, fmt.Errorf("dial ctx deadline %v (set=%v), want within %v", dl, ok, dialTimeout)
		}
		var d net.Dialer
		return d.DialContext(ctx, network, net.JoinHostPort(srv.realHost(), strings.TrimPrefix(addr, proxiedRegistryHost+":")))
	}
	c, err := DialPool(srv.target(), 2, WithDialer(dial))
	if err != nil {
		t.Fatalf("DialPool: %v", err)
	}
	defer c.Close()
	release := holdIdleEntries(t, c, 1) // force the redial path
	mustSendOK(t, c, "drop")
	release()
	if got := calls.Load(); got != 3 {
		t.Fatalf("dialer called %d times, want 3 (2 pool conns + 1 reconnect)", got)
	}
}

func TestWithDialerErrorsPropagate(t *testing.T) {
	t.Parallel()
	boom := errors.New("egress denied")
	dial := func(context.Context, string, string) (net.Conn, error) { return nil, boom }
	for name, fn := range map[string]func() error{
		"Dial":              func() error { _, err := Dial("r.invalid:1", WithDialer(dial)); return err },
		"DialPool":          func() error { _, err := DialPool("r.invalid:1", 2, WithDialer(dial)); return err },
		"DialTLS":           func() error { _, err := DialTLS("r.invalid:1", &tls.Config{}, WithDialer(dial)); return err },
		"DialTLSPool":       func() error { _, err := DialTLSPool("r.invalid:1", &tls.Config{}, 2, WithDialer(dial)); return err },
		"DialTLSPinned":     func() error { _, err := DialTLSPinned("r.invalid:1", "00", WithDialer(dial)); return err },
		"DialTLSPinnedPool": func() error { _, err := DialTLSPinnedPool("r.invalid:1", "00", 2, WithDialer(dial)); return err },
		"DialBinary":        func() error { _, err := DialBinary("r.invalid:1", WithDialer(dial)); return err },
	} {
		if err := fn(); !errors.Is(err, boom) {
			t.Fatalf("%s: err = %v, want wrapped %v", name, err, boom)
		}
	}
}

// closeRecordingConn records Close so tests can prove a failed TLS
// handshake does not leak the dialer's conn.
type closeRecordingConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *closeRecordingConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

func TestWithDialerClosesConnOnTLSHandshakeFailure(t *testing.T) {
	t.Parallel()
	srv := newProxiedRegistry(t, false) // plain TCP: a TLS handshake cannot succeed
	var rec *closeRecordingConn
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		raw, err := d.DialContext(ctx, network, srv.ln.Addr().String())
		if err != nil {
			return nil, err
		}
		rec = &closeRecordingConn{Conn: raw}
		return rec, nil
	}
	_, err := DialTLS(srv.target(), &tls.Config{MinVersion: tls.VersionTLS12}, WithDialer(dial))
	if err == nil {
		t.Fatal("expected a TLS handshake error against a plain TCP server")
	}
	if rec == nil || !rec.closed.Load() {
		t.Fatal("dialer conn was not closed after the failed handshake")
	}
}

func TestWithDialerNilKeepsDirectDial(t *testing.T) {
	t.Parallel()
	srv := newProxiedRegistry(t, false)
	c, err := Dial(srv.ln.Addr().String(), WithDialer(nil), nil)
	if err != nil {
		t.Fatalf("Dial with nil dialer/option: %v", err)
	}
	defer c.Close()
	if c.dial != nil {
		t.Fatal("nil WithDialer should leave the default direct dial")
	}
	mustSendOK(t, c, "hello")
}
