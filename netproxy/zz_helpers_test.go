// SPDX-License-Identifier: AGPL-3.0-or-later

package netproxy

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Test fixtures shared by the netproxy tests: an in-process HTTP CONNECT
// proxy that maps made-up host names (which never resolve locally) to
// loopback, an echo server, and a throwaway certificate generator.

// testProxy is a minimal CONNECT proxy. Targets are only reachable under
// the names in hosts, which is how the tests prove that the client asked
// for a host name and never resolved it itself.
type testProxy struct {
	ln    net.Listener
	hosts map[string]string // target host name -> real host to dial

	// wantAuth, when set, is the only Proxy-Authorization value accepted;
	// anything else gets rejectStatus (407 by default) with rejectReason.
	// Guarded by mu: setAuth rotates it while the proxy runs.
	wantAuth     string
	rejectStatus int
	rejectReason string
	// rejectLine, when set, replaces the whole status line of a rejection
	// (to send one net/http cannot parse).
	rejectLine string
	// rejected counts CONNECTs refused for their credentials.
	rejected atomic.Int32
	// hang makes the proxy read the CONNECT request and never answer.
	hang bool

	mu       sync.Mutex
	targets  []string // CONNECT request-targets, in arrival order
	hostHdrs []string // Host header values, in arrival order
	auths    []string // Proxy-Authorization values, in arrival order

	// clientClosed counts rejected/hung requests after which the client
	// closed its side of the connection.
	clientClosed atomic.Int32
	wg           sync.WaitGroup
	live         map[net.Conn]struct{} // guarded by mu; closed on cleanup
}

type proxyOpt func(*testProxy)

func withAuth(user, pass string) proxyOpt {
	return func(p *testProxy) { p.wantAuth = basicAuth(user, pass) }
}

func withReject(status int, reason string) proxyOpt {
	return func(p *testProxy) { p.wantAuth = "never-matches"; p.rejectStatus = status; p.rejectReason = reason }
}

func withHang() proxyOpt { return func(p *testProxy) { p.hang = true } }

// withRejectLine makes credential rejections use line as the status line.
func withRejectLine(line string) proxyOpt {
	return func(p *testProxy) { p.rejectLine = line }
}

// setAuth rotates the credentials the proxy accepts. Tunnels already open
// are not affected, as with a real rotating proxy.
func (p *testProxy) setAuth(user, pass string) {
	p.mu.Lock()
	p.wantAuth = basicAuth(user, pass)
	p.mu.Unlock()
}

func withTLS(cert tls.Certificate) proxyOpt {
	return func(p *testProxy) {
		p.ln = tls.NewListener(p.ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	}
}

func newTestProxy(t *testing.T, hosts map[string]string, opts ...proxyOpt) *testProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	p := &testProxy{ln: ln, hosts: hosts, rejectStatus: http.StatusProxyAuthRequired, rejectReason: "Proxy Authentication Required"}
	for _, o := range opts {
		o(p)
	}
	p.wg.Add(1)
	go p.acceptLoop()
	t.Cleanup(func() {
		p.ln.Close()
		p.mu.Lock()
		for c := range p.live {
			c.Close()
		}
		p.mu.Unlock()
		p.wg.Wait()
	})
	return p
}

func (p *testProxy) track(c net.Conn) {
	p.mu.Lock()
	if p.live == nil {
		p.live = make(map[net.Conn]struct{})
	}
	p.live[c] = struct{}{}
	p.mu.Unlock()
}

func (p *testProxy) addr() string { return p.ln.Addr().String() }

func (p *testProxy) url(userinfo string) string {
	if userinfo != "" {
		return "http://" + userinfo + "@" + p.addr()
	}
	return "http://" + p.addr()
}

func (p *testProxy) seen() (targets, hostHdrs, auths []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.targets...), append([]string(nil), p.hostHdrs...), append([]string(nil), p.auths...)
}

func (p *testProxy) acceptLoop() {
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

func (p *testProxy) serve(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	p.mu.Lock()
	p.targets = append(p.targets, req.RequestURI)
	p.hostHdrs = append(p.hostHdrs, req.Host)
	p.auths = append(p.auths, req.Header.Get("Proxy-Authorization"))
	wantAuth := p.wantAuth
	p.mu.Unlock()

	waitClientClose := func() {
		if _, err := br.ReadByte(); err == io.EOF {
			p.clientClosed.Add(1)
		}
	}
	if p.hang {
		waitClientClose()
		return
	}
	if req.Method != http.MethodConnect {
		fmt.Fprintf(conn, "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
		return
	}
	if wantAuth != "" && req.Header.Get("Proxy-Authorization") != wantAuth {
		p.rejected.Add(1)
		line := fmt.Sprintf("HTTP/1.1 %d %s", p.rejectStatus, p.rejectReason)
		if p.rejectLine != "" {
			line = p.rejectLine
		}
		fmt.Fprintf(conn, "%s\r\nProxy-Authenticate: Basic realm=\"test\"\r\nContent-Length: 0\r\n\r\n", line)
		waitClientClose()
		return
	}
	host, port, err := net.SplitHostPort(req.RequestURI)
	real, ok := p.hosts[host]
	if err != nil || !ok {
		fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	up, err := net.DialTimeout("tcp", net.JoinHostPort(real, port), 5*time.Second)
	if err != nil {
		fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer up.Close()
	p.track(up)
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	conn.SetDeadline(time.Time{})
	pipe(conn, br, up)
}

// pipe copies client<->upstream until either side closes. clientR carries
// any bytes already buffered from the client.
func pipe(client net.Conn, clientR io.Reader, up net.Conn) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, clientR); closeWrite(up); done <- struct{}{} }()
	go func() { io.Copy(client, up); closeWrite(client); done <- struct{}{} }()
	<-done
	<-done
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
		return
	}
	c.Close()
}

// newEchoServer echoes every byte back on each connection.
func newEchoServer(t *testing.T) (host, port string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()
	t.Cleanup(func() { ln.Close(); wg.Wait() })
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	return h, p
}

// genCert returns a self-signed leaf for the given names/IPs plus a pool
// that trusts it.
func genCert(t *testing.T, dnsNames []string, ips []net.IP) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "netproxy-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

func basicAuth(user, pass string) string {
	req := &http.Request{Header: http.Header{}}
	req.SetBasicAuth(user, pass)
	return req.Header.Get("Authorization")
}

// mustExplicit is Explicit for tests.
func mustExplicit(t *testing.T, raw string) *Resolver {
	t.Helper()
	r, err := Explicit(raw)
	if err != nil {
		t.Fatalf("Explicit: %v", err)
	}
	return r
}

// envMap turns a map into a getenv function for fromEnv.
func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}
