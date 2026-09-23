// SPDX-License-Identifier: AGPL-3.0-or-later

package netproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// DefaultTimeout bounds a Dialer's connection establishment when neither
// Dialer.Timeout nor the context sets a tighter limit.
const DefaultTimeout = 30 * time.Second

// Dialer opens stream connections, tunnelling them through the HTTP CONNECT
// proxy its Resolver picks for each target and dialing directly when there
// is none. The zero value (or a nil *Dialer) always dials directly.
//
// DialContext has the signature of (*net.Dialer).DialContext, so a Dialer
// drops into anything that accepts a dial function:
//
//	d := netproxy.NewDialer(resolver)
//	conn, err := d.DialContext(ctx, "tcp", "registry.example.net:443")
//
// The target address is sent to the proxy verbatim ("CONNECT host:port") and
// never resolved locally, so it works when local DNS for the target is
// broken or poisoned. Callers that want TLS wrap the returned conn with
// tls.Client themselves; TLS then runs end-to-end with the real server.
//
// When the proxy rejects the credentials (407 Proxy Authentication
// Required, or a CONNECT response so garbled it cannot be parsed, which is
// how some proxies' rejections arrive), the Dialer refreshes the Resolver
// (see Resolver.Refresh) and, if that produced different credentials,
// retries once on a new connection. Tunnels opened earlier are never
// touched. A Resolver with nothing to refresh gets no retry.
type Dialer struct {
	// Resolver picks the proxy per target. nil never proxies.
	Resolver *Resolver

	// Timeout bounds the whole establishment: the TCP connect to the proxy
	// (or to the target when dialing directly), the TLS handshake with an
	// https:// proxy, and the CONNECT exchange, including a credential
	// refresh and the one retry after a rejection. Zero means
	// DefaultTimeout. An earlier deadline on the DialContext context wins.
	Timeout time.Duration

	// Forward dials the proxy itself, and the target when no proxy applies.
	// nil uses a net.Dialer.
	Forward func(ctx context.Context, network, addr string) (net.Conn, error)

	// TLSConfig configures the TLS session with an https:// proxy (not with
	// the target). nil uses defaults; ServerName defaults to the proxy host.
	TLSConfig *tls.Config
}

// NewDialer returns a Dialer that routes connections as r decides.
func NewDialer(r *Resolver) *Dialer { return &Dialer{Resolver: r} }

// ConnectError is returned when the proxy answers CONNECT with a non-2xx
// status. Its message never includes credentials or proxy-supplied text.
type ConnectError struct {
	// Target is the "host:port" the CONNECT asked for.
	Target string
	// StatusCode is the proxy's HTTP status, e.g. 407 or 403.
	StatusCode int
}

func (e *ConnectError) Error() string {
	// Deliberately not the proxy's reason phrase: a hostile or buggy proxy
	// could reflect request headers (credentials) into it.
	status := fmt.Sprintf("%d", e.StatusCode)
	if text := http.StatusText(e.StatusCode); text != "" {
		status += " " + text
	}
	return fmt.Sprintf("proxy CONNECT %s: %s", e.Target, status)
}

// Dial is DialContext with a background context.
func (d *Dialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

// DialContext connects to addr ("host:port") on network, through the proxy
// the Resolver selects for addr or directly when it selects none. Only
// "tcp", "tcp4" and "tcp6" can be tunnelled.
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	var resolver *Resolver
	timeout := DefaultTimeout
	if d != nil {
		resolver = d.Resolver
		if d.Timeout > 0 {
			timeout = d.Timeout
		}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Noted before the pick, so a refresh the pick itself runs counts as
	// having happened after it.
	start := resolver.attemptCount()
	proxyURL, err := resolver.proxyForAddr(ctx, addr)
	if err != nil {
		return nil, err
	}
	if proxyURL == nil {
		return d.forward(ctx, network, addr)
	}
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("netproxy: cannot tunnel network %q through proxy %s", network, Redact(proxyURL))
	}
	conn, err := d.dialConnect(ctx, proxyURL, addr)
	if err == nil || !credentialsRejected(err) {
		return conn, err
	}
	next, retry, refreshErr := resolver.reauth(ctx, start, proxyURL, func(st *proxyState) *url.URL {
		u, _ := resolver.pickAddr(st, addr) // addr already parsed once
		return u
	})
	if !retry {
		return nil, withRefreshError(err, refreshErr)
	}
	if next == nil {
		// The refreshed settings no longer proxy this target.
		return d.forward(ctx, network, addr)
	}
	return d.dialConnect(ctx, next, addr)
}

// credentialsRejected reports whether a CONNECT failed in a way stale
// credentials explain: a 407, or a response that could not be parsed.
func credentialsRejected(err error) bool {
	var ce *ConnectError
	if errors.As(err, &ce) {
		return ce.StatusCode == http.StatusProxyAuthRequired
	}
	var bad *badConnectResponse
	return errors.As(err, &bad)
}

// badConnectResponse is a CONNECT response http.ReadResponse rejected as
// malformed (as opposed to an I/O error while reading it).
type badConnectResponse struct{ err error }

func (e *badConnectResponse) Error() string { return "read CONNECT response: " + e.err.Error() }

func (e *badConnectResponse) Unwrap() error { return e.err }

// isMalformedResponse reports whether err is net/http's complaint about an
// unparseable response ("malformed HTTP status code", "malformed HTTP
// response", "malformed HTTP version", "malformed MIME header line").
func isMalformedResponse(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "malformed HTTP ") || strings.Contains(msg, "malformed MIME header")
}

func (d *Dialer) forward(ctx context.Context, network, addr string) (net.Conn, error) {
	if d != nil && d.Forward != nil {
		return d.Forward(ctx, network, addr)
	}
	var nd net.Dialer
	return nd.DialContext(ctx, network, addr)
}

// aLongTimeAgo is a deadline in the past, used to abort blocked I/O.
var aLongTimeAgo = time.Unix(1, 0)

// dialConnect opens a CONNECT tunnel to addr through proxyURL. ctx must
// carry a deadline; the conn is closed on every error path.
func (d *Dialer) dialConnect(ctx context.Context, proxyURL *url.URL, addr string) (net.Conn, error) {
	if err := validTarget(addr); err != nil {
		return nil, err
	}
	conn, err := d.forward(ctx, "tcp", proxyHostPort(proxyURL))
	if err != nil {
		return nil, fmt.Errorf("proxy CONNECT %s: dial proxy %s: %w", addr, Redact(proxyURL), err)
	}

	// The context bounds the handshake: its deadline becomes the conn
	// deadline, and cancellation poisons the deadline to unblock I/O.
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(aLongTimeAgo) })

	tunnel, err := d.connect(ctx, conn, proxyURL, addr)
	if !stop() && err == nil {
		// The context ended after the exchange completed but before the
		// deadline guard was disarmed; the conn's deadline is poisoned.
		err = ctx.Err()
	}
	if err != nil {
		conn.Close()
		var ce *ConnectError
		if errors.As(err, &ce) {
			return nil, err
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			err = ctxErr
		} else if errors.Is(err, os.ErrDeadlineExceeded) {
			err = context.DeadlineExceeded
		}
		return nil, fmt.Errorf("proxy CONNECT %s via %s: %w", addr, Redact(proxyURL), err)
	}
	conn.SetDeadline(time.Time{})
	return tunnel, nil
}

// connect runs the (optional) TLS handshake with the proxy and the CONNECT
// exchange on conn. It does not close conn; dialConnect does on error.
func (d *Dialer) connect(ctx context.Context, conn net.Conn, proxyURL *url.URL, addr string) (net.Conn, error) {
	if proxyURL.Scheme == "https" {
		var cfg *tls.Config
		if d != nil && d.TLSConfig != nil {
			cfg = d.TLSConfig.Clone()
		} else {
			cfg = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		if cfg.ServerName == "" {
			cfg.ServerName = proxyURL.Hostname()
		}
		tc := tls.Client(conn, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("TLS handshake with proxy: %w", err)
		}
		conn = tc
	}

	var req strings.Builder
	req.WriteString("CONNECT " + addr + " HTTP/1.1\r\n")
	req.WriteString("Host: " + addr + "\r\n")
	if u := proxyURL.User; u != nil {
		password, _ := u.Password()
		cred := base64.StdEncoding.EncodeToString([]byte(u.Username() + ":" + password))
		req.WriteString("Proxy-Authorization: Basic " + cred + "\r\n")
	}
	req.WriteString("\r\n")
	if _, err := io.WriteString(conn, req.String()); err != nil {
		return nil, fmt.Errorf("write CONNECT: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		if isMalformedResponse(err) {
			return nil, &badConnectResponse{err: err}
		}
		return nil, fmt.Errorf("read CONNECT response: %w", err)
	}
	// The body is never read: on success the rest of the stream belongs to
	// the tunnel, and on failure the conn is discarded.
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &ConnectError{Target: addr, StatusCode: resp.StatusCode}
	}
	if br.Buffered() > 0 {
		// The proxy sent tunnel bytes in the same packet as its response
		// (e.g. a server that speaks first); keep them.
		return &bufferedConn{Conn: conn, r: br}, nil
	}
	return conn, nil
}

// validTarget rejects addresses that are not host:port or that would
// corrupt the CONNECT request line (whitespace, control characters).
func validTarget(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" || port == "" {
		return fmt.Errorf("netproxy: invalid target address %q", addr)
	}
	for i := 0; i < len(addr); i++ {
		if c := addr[i]; c <= ' ' || c == 0x7f {
			return fmt.Errorf("netproxy: invalid target address %q", addr)
		}
	}
	return nil
}

// bufferedConn serves bytes the CONNECT response reader over-read before
// reading from the underlying conn again.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	if c.r != nil {
		if c.r.Buffered() > 0 {
			return c.r.Read(p)
		}
		c.r = nil
	}
	return c.Conn.Read(p)
}
