// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/pilot-protocol/common/registry/wire"
)

// ErrNoRegistry is returned from every exported *Client method when the
// receiver is a typed nil pointer. Callers (loadPolicyRunners,
// ManagedEngine.fetchMembers, Daemon.Info → nodeNetworks, etc.) sometimes
// invoke registry methods before the client is configured; returning this
// sentinel instead of panicking lets them treat "no registry" as a
// recoverable condition.
var ErrNoRegistry = errors.New("registry client not configured")

// dialTimeout bounds every TCP/TLS connection attempt to the registry so an
// unreachable or black-holed registry host cannot hang startup or any
// registry operation indefinitely. It matches the per-attempt timeout the
// reconnect paths already use.
const dialTimeout = 5 * time.Second

// Client talks to a registry server over TCP (optionally TLS).
// It automatically reconnects if the connection drops.
//
// By default a Client owns a single TCP connection (Dial / DialTLS /
// DialTLSPinned). Each Send takes c.mu and serialises the entire
// request/response round-trip on that one conn. Under heavy concurrent
// load (the §4.8 lock-graph stress harness — 250 heartbeat goroutines
// per daemon hammering Health / Info / SetTags / ResolveHostname plus
// the per-resolve prewarm goroutines and persistHostnameCache writers,
// all funnelling through regConn.Send) that single mutex becomes the
// bottleneck: in-flight calls cannot honour shutdown signals because
// they're queued behind the mutex.
//
// DialPool / DialTLSPool create a Client backed by a small pool of
// connections (the primary c.conn plus N-1 secondary conns). Each
// concurrent Send picks a free pooled conn (blocking only if every
// conn is in use), eliminating the head-of-line wait. The primary
// c.conn / c.mu / c.closed fields are retained for backward compatibility
// with tests that touch them directly.
//
// Every Dial* constructor accepts DialOptions; WithDialer routes all of the
// client's connections (initial, pool and reconnect) through a custom
// dialer, e.g. an HTTP CONNECT proxy from the netproxy package.
type Client struct {
	// Primary connection. nil only while a dropped connection waits for
	// its redial. Tests in this package read c.conn / c.mu / c.closed
	// directly so the field set must stay stable.
	conn      net.Conn
	mu        sync.Mutex
	addr      string // registry address for reconnection
	closed    bool
	tlsConfig *tls.Config
	signer    func(challenge string) string // H3 fix: optional message signer
	// dial, when non-nil, opens every connection (initial, pool, reconnect)
	// instead of a direct net.Dialer — see WithDialer. Immutable after
	// construction.
	dial DialContextFunc
	// connDialedAt is when c.conn was established (single-conn path; guarded
	// by c.mu). Its age tells a rate-limit close from an idle one.
	connDialedAt time.Time

	// Optional pool of secondary connections used to parallelise Send.
	// nil / empty when DialPool was not used.
	pool poolState

	// closeOnce makes Close idempotent: the teardown (closing done and every
	// connection) runs exactly once however many goroutines call Close.
	closeOnce sync.Once
	// done is closed by Close. It wakes goroutines parked on the pool's
	// free list or in a reconnect backoff. Created lazily by doneCh so the
	// zero-value Client works.
	doneOnce sync.Once
	done     chan struct{}

	// reconn holds the reconnect backoff streaks and log counters shared by
	// every connection of this client.
	reconn reconnectTracker
	// logger overrides slog.Default() (tests only).
	logger *slog.Logger
}

// poolState holds the secondary-conn pool. The primary slot (c.conn / c.mu)
// is also represented here as the first entry, so acquireEntry /
// releaseEntry can pick uniformly across all conns.
type poolState struct {
	// entries is the full set of conns including the primary at index 0.
	// Each entry has its own mu — taking entry.mu lets one Send proceed
	// without blocking other Sends on different entries. Closed when the
	// Client is closed.
	entries []*pooledConn
	// free is a buffered channel of pointers to entries currently free.
	// Capacity equals len(entries). Send: <-free; defer free<-entry.
	// nil means "no pool" (legacy single-conn path via c.mu).
	// It is never closed: Close closes c.done instead, which avoids the
	// race between close(free) and concurrent sends on free.
	free chan *pooledConn
}

// pooledConn wraps one registry connection plus its own mutex. The Send
// that took the entry off the free list holds mu for its whole round trip
// (including any redial). conn is written only with both mu and the
// client's c.mu held, so Close can snapshot it under c.mu alone.
type pooledConn struct {
	mu   sync.Mutex
	conn net.Conn
	// dialedAt is when conn was established (guarded by mu).
	dialedAt time.Time
	// broken, when non-nil, is the error that dropped conn; the entry must
	// be redialed before reuse (guarded by mu).
	broken error
}

// healthy reports whether the entry can be used without a redial. The
// caller must own the entry (it came off the free list).
func (e *pooledConn) healthy() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.broken == nil && e.conn != nil
}

// SetSigner sets a signing function for authenticated registry operations (H3 fix).
// The signer receives a challenge string and returns a base64-encoded Ed25519 signature.
//
// Issue #93: when the regConn is pooled (DialPool), multiple Send goroutines
// may call sign() concurrently while a parallel RotateKey path calls
// SetSigner. We guard the field with c.mu to keep that race-free; reads via
// sign() take the same lock so the loaded function pointer is consistent.
func (c *Client) SetSigner(fn func(challenge string) string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.signer = fn
	c.mu.Unlock()
}

// sign returns a signature for the challenge. It returns an error when the
// signer is unavailable or returns an empty signature. A nil receiver returns
// ErrNoRegistry so callers can rely on errors.Is.
func (c *Client) sign(challenge string) (string, error) {
	if c == nil {
		return "", ErrNoRegistry
	}
	c.mu.Lock()
	fn := c.signer
	c.mu.Unlock()
	if fn == nil {
		return "", fmt.Errorf("registry client: no signer configured (call SetSigner first)")
	}
	sig := fn(challenge)
	if sig == "" {
		return "", fmt.Errorf("registry client: signer returned empty signature for %q", challenge)
	}
	return sig, nil
}

// Dial connects to a registry server over plain TCP. Pass WithDialer to
// route the connection (and every reconnect) through a custom dialer such
// as an HTTP CONNECT proxy.
func Dial(addr string, opts ...DialOption) (*Client, error) {
	o := applyDialOptions(opts)
	conn, err := dialConn(context.Background(), o.dial, addr, nil)
	if err != nil {
		return nil, fmt.Errorf("dial registry: %w", err)
	}
	return newClient(conn, addr, nil, o.dial), nil
}

// newClient wraps an established primary connection.
func newClient(conn net.Conn, addr string, tlsConfig *tls.Config, dial DialContextFunc) *Client {
	return &Client{conn: conn, addr: addr, tlsConfig: tlsConfig, dial: dial, connDialedAt: time.Now()}
}

// DialPool connects to a registry server over plain TCP and pre-warms a
// pool of `size` connections (size >= 1). When size == 1 this is identical
// to Dial. When size > 1, additional secondary conns are dialed; concurrent
// Send calls then run in parallel up to `size` at a time, instead of all
// queueing on a single mutex.
//
// DialPool exists to fix #93 (regConn fairness under sustained load): the
// daemon's IPC handlers spawn goroutines that all call regConn.Send and
// previously serialised on c.mu. With DialPool the daemon can keep the
// same code path while letting up to `size` registry round-trips run
// concurrently.
//
// On any pool conn dial failure DialPool closes the conns it had already
// opened and returns an error.
func DialPool(addr string, size int, opts ...DialOption) (*Client, error) {
	if size <= 0 {
		size = 1
	}
	o := applyDialOptions(opts)
	primary, err := dialConn(context.Background(), o.dial, addr, nil)
	if err != nil {
		return nil, fmt.Errorf("dial registry: %w", err)
	}
	c := newClient(primary, addr, nil, o.dial)
	if err := c.initPool(size, nil); err != nil {
		primary.Close()
		return nil, err
	}
	return c, nil
}

// DialTLS connects to a registry server over TLS.
// A non-nil tlsConfig is required. For certificate pinning, use DialTLSPinned.
func DialTLS(addr string, tlsConfig *tls.Config, opts ...DialOption) (*Client, error) {
	if tlsConfig == nil {
		return nil, fmt.Errorf("TLS config required; use DialTLSPinned for certificate pinning")
	}
	o := applyDialOptions(opts)
	conn, err := dialConn(context.Background(), o.dial, addr, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("dial registry TLS: %w", err)
	}
	return newClient(conn, addr, tlsConfig, o.dial), nil
}

// DialTLSPool is the TLS variant of DialPool.
func DialTLSPool(addr string, tlsConfig *tls.Config, size int, opts ...DialOption) (*Client, error) {
	if tlsConfig == nil {
		return nil, fmt.Errorf("TLS config required; use DialTLSPinnedPool for certificate pinning")
	}
	return dialTLSPool(addr, tlsConfig, size, "dial registry TLS", applyDialOptions(opts))
}

func dialTLSPool(addr string, tlsConfig *tls.Config, size int, errPrefix string, o dialOptions) (*Client, error) {
	if size <= 0 {
		size = 1
	}
	primary, err := dialConn(context.Background(), o.dial, addr, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", errPrefix, err)
	}
	c := newClient(primary, addr, tlsConfig, o.dial)
	if err := c.initPool(size, tlsConfig); err != nil {
		primary.Close()
		return nil, err
	}
	return c, nil
}

// initPool dials size-1 additional connections and registers them in c.pool.
// It assumes c.conn (primary) is already set. tlsCfg, when non-nil, is used
// for TLS dialing; otherwise plain TCP. Every conn goes through c.dial when
// one is configured.
func (c *Client) initPool(size int, tlsCfg *tls.Config) error {
	if size <= 1 {
		// No secondary conns — single-conn legacy path; pool stays empty.
		return nil
	}
	entries := make([]*pooledConn, 0, size)
	entries = append(entries, &pooledConn{conn: c.conn, dialedAt: c.connDialedAt})
	for i := 1; i < size; i++ {
		conn, err := dialConn(context.Background(), c.dial, c.addr, tlsCfg)
		if err != nil {
			// Close any conns we already opened (excluding primary —
			// caller closes that on failure).
			for _, e := range entries[1:] {
				e.conn.Close()
			}
			return fmt.Errorf("dial pool conn %d: %w", i, err)
		}
		entries = append(entries, &pooledConn{conn: conn, dialedAt: time.Now()})
	}
	free := make(chan *pooledConn, len(entries))
	for _, e := range entries {
		free <- e
	}
	c.pool.entries = entries
	c.pool.free = free
	return nil
}

// DialTLSPinned connects to a registry server over TLS with certificate pinning.
// The fingerprint is a hex-encoded SHA-256 hash of the server's DER-encoded certificate.
func DialTLSPinned(addr, fingerprint string, opts ...DialOption) (*Client, error) {
	o := applyDialOptions(opts)
	tlsConfig := pinnedTLSConfig(fingerprint)
	conn, err := dialConn(context.Background(), o.dial, addr, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("dial registry TLS pinned: %w", err)
	}
	return newClient(conn, addr, tlsConfig, o.dial), nil
}

// DialTLSPinnedPool is the pooled variant of DialTLSPinned (see DialPool).
func DialTLSPinnedPool(addr, fingerprint string, size int, opts ...DialOption) (*Client, error) {
	return dialTLSPool(addr, pinnedTLSConfig(fingerprint), size, "dial registry TLS pinned", applyDialOptions(opts))
}

// pinnedTLSConfig accepts exactly the server certificate whose DER SHA-256
// is the hex fingerprint, instead of verifying a CA chain.
func pinnedTLSConfig(fingerprint string) *tls.Config {
	return &tls.Config{
		// InsecureSkipVerify disables the default CA chain check so we can
		// use VerifyPeerCertificate for certificate pinning (SHA-256 fingerprint).
		// This is the standard Go pattern — the custom callback below provides
		// strictly stronger verification than CA-based trust.
		InsecureSkipVerify: true, //nolint:gosec // cert pinning via VerifyPeerCertificate
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no certificate presented")
			}
			hash := sha256.Sum256(rawCerts[0])
			got := hex.EncodeToString(hash[:])
			if got != fingerprint {
				return fmt.Errorf("certificate fingerprint mismatch: got %s, want %s", got, fingerprint)
			}
			return nil
		},
	}
}

// Close closes every registry connection of the client. It is idempotent
// and safe to call concurrently with itself and with in-flight requests:
// the teardown runs exactly once, later calls return nil, and every request
// that is in flight or starts afterwards fails with an error matching
// ErrClosed (and ErrNoRegistry) instead of panicking.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	var err error
	c.closeOnce.Do(func() { err = c.shutdown() })
	return err
}

// shutdown is Close's one-time teardown.
func (c *Client) shutdown() error {
	// Wake goroutines parked on the pool's free list or in a reconnect
	// backoff before taking c.mu: the single-conn path holds c.mu for its
	// whole round trip, reconnect waits included.
	close(c.doneCh())

	c.mu.Lock()
	c.closed = true
	// Snapshot every live conn. Entry conns are only replaced under c.mu,
	// and nothing closes a conn once closed is set, so each conn is closed
	// exactly once, here. In pool mode entries[0] shares the primary conn
	// with c.conn, so c.conn is not closed separately.
	var conns []net.Conn
	if len(c.pool.entries) > 0 {
		for _, e := range c.pool.entries {
			if e.conn != nil {
				conns = append(conns, e.conn)
			}
		}
	} else if c.conn != nil {
		conns = append(conns, c.conn)
	}
	c.mu.Unlock()

	// Closing a conn in use interrupts its Read/Write; that request then
	// sees the client closed and returns ErrClosed. Close does not wait
	// for in-flight pooled requests.
	var firstErr error
	for _, conn := range conns {
		if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) && firstErr == nil {
			firstErr = err
		}
	}
	c.logSummary(c.reconn.stop())
	return firstErr
}

// doneCh returns the channel Close closes, creating it on first use.
func (c *Client) doneCh() chan struct{} {
	c.doneOnce.Do(func() { c.done = make(chan struct{}) })
	return c.done
}

// closing reports whether Close has started. Unlike isClosed it takes no
// lock, so it is safe on the single-conn path, which holds c.mu.
func (c *Client) closing() bool {
	select {
	case <-c.doneCh():
		return true
	default:
		return false
	}
}

func (c *Client) log() *slog.Logger {
	if c.logger != nil {
		return c.logger
	}
	return slog.Default()
}

// logSummary emits the periodic reconnect summary (attrs from the
// tracker; nil means nothing to report).
func (c *Client) logSummary(attrs []any) {
	if attrs == nil {
		return
	}
	c.log().Info("registry reconnect summary", append([]any{"addr", c.addr}, attrs...)...)
}

// noteConnError records a connection-level failure of one transmission (the
// triggering error of the reconnect that follows) and logs it at Debug. A
// logical request extends the rapid-close backoff streak at most once:
// streakNoted says whether an earlier transmission of it already did, and
// the result says whether one has now.
func (c *Client) noteConnError(err error, age time.Duration, streakNoted bool) bool {
	rapid := c.reconn.connError(err, age, !streakNoted, c.logSummary)
	c.log().Debug("registry conn dropped", "addr", c.addr, "err", err,
		"conn_age", age.Round(time.Millisecond).String(), "rapid_close", rapid)
	return streakNoted || rapid
}

// dialWithBackoff opens a replacement connection after cause broke the old
// one. It first waits out the client-wide cooldown, which is zero until the
// registry keeps closing connections shortly after they are used (its rate
// limiter's signature) or whole reconnects keep failing. Then it makes up
// to maxReconnectAttempts dials with jittered exponential backoff between
// them. It returns early when ctx is done or the client is closed.
//
// It takes no lock, so the single-conn path may call it with c.mu held.
func (c *Client) dialWithBackoff(ctx context.Context, what string, cause error) (net.Conn, error) {
	// A caller that has given up (for example while the request was being
	// retried on another pooled conn) gets no redial, and its abandoned
	// dials are not counted against the registry.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := sleepCtx(ctx, c.doneCh(), c.reconn.cooldown()); err != nil {
		return nil, err
	}
	p := c.reconn.pol()
	backoff := p.dialBase
	var err error
	for attempt := 1; attempt <= maxReconnectAttempts; attempt++ {
		if c.closing() {
			return nil, ErrClosed
		}
		var conn net.Conn
		conn, err = dialConn(ctx, c.dial, c.addr, c.tlsConfig)
		if err == nil {
			return conn, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		c.log().Warn(what+" reconnect failed", "addr", c.addr, "attempt", attempt, "err", err, "cause", errText(cause))
		c.reconn.dialFailed(c.logSummary)
		if attempt == maxReconnectAttempts {
			break
		}
		if werr := sleepCtx(ctx, c.doneCh(), jitter(backoff)); werr != nil {
			return nil, werr
		}
		if backoff *= 2; backoff > p.dialMax {
			backoff = p.dialMax
		}
	}
	c.reconn.exhausted()
	return nil, fmt.Errorf("reconnect failed after %d attempts: %w", maxReconnectAttempts, err)
}

// noteReconnected logs one successful redial at Debug (with the error that
// triggered it) and feeds the periodic INFO summary.
func (c *Client) noteReconnected(what string, cause error) {
	c.reconn.reconnected(cause, c.logSummary)
	c.log().Debug(what+" reconnected", "addr", c.addr, "cause", errText(cause))
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// reconnectFailed builds the error for a request whose connection broke
// (cause) and could not be redialed (reconnErr). Both stay in the chain.
func reconnectFailed(cause, reconnErr error) error {
	if errors.Is(reconnErr, ErrClosed) {
		return closedDuring(cause)
	}
	if cause == nil {
		cause = errNotConnected
	}
	return fmt.Errorf("send failed and reconnect failed: %w (reconnect: %w)", cause, reconnErr)
}

// retriedAfter annotates the error of a retry that also failed at the
// connection level with the error that triggered the reconnect.
func retriedAfter(err, cause error) error {
	return fmt.Errorf("%w (retried after reconnect; first failure: %v)", err, cause)
}

// reconnect re-establishes the single-conn path's connection after cause
// broke it. Must be called with c.mu held.
func (c *Client) reconnect(ctx context.Context, cause error) error {
	if c.closed || c.closing() {
		return ErrClosed
	}
	if c.conn != nil {
		c.conn.Close()
		// Retired: a failed redial leaves no conn behind for Close to
		// close a second time.
		c.conn = nil
	}
	conn, err := c.dialWithBackoff(ctx, "registry", cause)
	if err != nil {
		return err
	}
	if c.closing() {
		// Close started while we were dialing and is waiting for c.mu;
		// do not hand it a conn to close, and do not retry on it.
		conn.Close()
		return ErrClosed
	}
	c.conn = conn
	c.connDialedAt = time.Now()
	c.noteReconnected("registry", cause)
	return nil
}

// Send sends a registry message without a deadline. For shutdown-safe use
// that respects context cancellation, prefer SendContext.
func (c *Client) Send(msg map[string]interface{}) (map[string]interface{}, error) {
	return c.SendContext(context.Background(), msg)
}

// SendContext sends a registry message with context propagation through
// reconnect retries. Callers should pass a context with deadline or
// cancellation (e.g. daemon shutdown context) so that reconnect backoff
// does not block graceful stop. ctx bounds the wait for a free pooled
// connection, the retry on another pooled connection and the reconnect;
// it does not interrupt a round trip on the request's own connection,
// which the 30 s read deadline bounds.
//
// A connection-level failure (no response) is retried:
//   - On a single-connection client the connection is redialed and the
//     request sent once more, so it reaches the registry at most twice.
//   - On a pooled client, when the connection was dropped (EOF, reset,
//     closed) the request is first retried on another idle, healthy
//     pooled connection, bounded by a short deadline and ctx. Only if that
//     fails too is the request's own connection redialed and the request
//     sent a third time. Other connection-level failures (timeouts) go
//     straight to the redial.
//
// So a request whose connections drop may reach the registry more than
// once (up to three times on a pooled client); an operation that is not
// safe to repeat may have been applied even when an error is returned.
// However many attempts fail, one request extends the rapid-close backoff
// streak at most once. An error response from the registry is returned as
// is, never retried. After Close every call returns an error matching
// ErrClosed.
func (c *Client) SendContext(ctx context.Context, msg map[string]interface{}) (map[string]interface{}, error) {
	// Nil receiver — return a sentinel rather than panicking. Every
	// exported wrapper method (Register, Lookup, Resolve, …) funnels
	// through Send, so this single guard turns "calling a registry
	// method on a nil client" into a recoverable error for every
	// caller (loadPolicyRunners, ManagedEngine.fetchMembers,
	// Daemon.Info → nodeNetworks, etc.).
	if c == nil {
		return nil, ErrNoRegistry
	}
	// Pool-enabled path (DialPool / DialTLSPool): pick a free conn and
	// run the round-trip on it without touching c.mu. Multiple Send
	// callers can run concurrently on different pooled conns.
	if c.pool.free != nil {
		return c.sendPool(ctx, msg)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.closing() {
		return nil, ErrClosed
	}

	resp, err := c.sendLocked(msg)
	if err != nil && resp == nil {
		// Connection-level failure (no response received) — reconnect and retry once.
		// Server error responses (resp != nil) do NOT trigger reconnection.
		if c.closing() {
			return nil, closedDuring(err)
		}
		cause := err
		c.noteConnError(cause, time.Since(c.connDialedAt), false)
		if reconnErr := c.reconnect(ctx, cause); reconnErr != nil {
			return nil, reconnectFailed(cause, reconnErr)
		}
		resp, err = c.sendLocked(msg)
		if err != nil && resp == nil {
			if c.closing() {
				return nil, closedDuring(err)
			}
			return nil, retriedAfter(err, cause)
		}
	}
	c.reconn.healthy(time.Since(c.connDialedAt))
	return resp, err
}

// sendPool runs Send on a free pooled connection. It blocks only when
// every pooled conn is busy (capacity exhausted) — one concurrent Send
// per pool entry can be in flight at a time.
func (c *Client) sendPool(ctx context.Context, msg map[string]interface{}) (map[string]interface{}, error) {
	// Cheap closed check — avoids a wedged caller waiting on a free
	// channel that nobody will ever return to once Close has run.
	if c.isClosed() {
		return nil, ErrClosed
	}
	entry, err := c.acquireEntry(ctx)
	if err != nil {
		return nil, err
	}
	defer c.releaseEntry(entry)
	entry.mu.Lock()
	defer entry.mu.Unlock()

	// An earlier request dropped this entry's conn (and was served
	// elsewhere, or its redial failed): redial before use.
	if entry.broken != nil || entry.conn == nil {
		if rerr := c.reconnectEntry(ctx, entry, entry.broken); rerr != nil {
			return nil, reconnectFailed(entry.broken, rerr)
		}
	}

	var st sendState
	resp, err := c.sendOnEntry(entry, msg, &st)
	if err == nil || resp != nil {
		return resp, err
	}
	if c.isClosed() {
		return nil, closedDuring(err)
	}
	cause := err

	// The connection was dropped (EOF, reset, closed). The other entries
	// were dialed at other times and may still be good, so retry once on
	// an idle healthy one before paying for a redial and any cooldown.
	// That retry is bounded by otherConnTimeout and ctx: the other conn
	// may be silently hung, and the redial below must still fit in the
	// caller's deadline. Timeouts are not retried this way: a half-open
	// conn already cost the caller the full read deadline.
	if isConnDropped(cause) {
		if resp, served, err := c.sendOnOtherEntry(ctx, msg, &st); served {
			return resp, err
		}
		if c.isClosed() {
			return nil, closedDuring(cause)
		}
	}

	// Redial this entry and retry once. dialWithBackoff gives up at once
	// when ctx ended during the retry above.
	if rerr := c.reconnectEntry(ctx, entry, cause); rerr != nil {
		return nil, reconnectFailed(cause, rerr)
	}
	resp, err = c.sendOnEntry(entry, msg, &st)
	if err != nil && resp == nil {
		if c.isClosed() {
			return nil, closedDuring(err)
		}
		return nil, retriedAfter(err, cause)
	}
	return resp, err
}

// acquireEntry takes a pool entry off the free list, preferring an idle
// healthy one and otherwise blocking until any entry is free, ctx is done
// or the client is closed.
func (c *Client) acquireEntry(ctx context.Context) (*pooledConn, error) {
	if e := c.tryAcquireHealthy(); e != nil {
		return e, nil
	}
	select {
	case e := <-c.pool.free:
		if c.closing() {
			c.releaseEntry(e)
			return nil, ErrClosed
		}
		return e, nil
	case <-c.doneCh():
		return nil, ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// tryAcquireHealthy takes an idle entry that needs no redial off the free
// list without blocking. It returns nil when none is free right now.
func (c *Client) tryAcquireHealthy() *pooledConn {
	var skipped []*pooledConn
	defer func() {
		for _, e := range skipped {
			c.releaseEntry(e)
		}
	}()
	for range len(c.pool.entries) {
		select {
		case e := <-c.pool.free:
			if e.healthy() {
				return e
			}
			skipped = append(skipped, e)
		default:
			return nil
		}
	}
	return nil
}

// releaseEntry returns an entry to the free list.
func (c *Client) releaseEntry(e *pooledConn) {
	select {
	case c.pool.free <- e:
	case <-c.doneCh():
		// pool is torn down; drop the entry
	}
}

// sendState is the bookkeeping of one logical request across its attempts
// on a pooled client.
type sendState struct {
	// streakNoted is set once a failed attempt of the request extended the
	// rapid-close streak; later failures only feed the summary.
	streakNoted bool
}

// sendOnOtherEntry retries msg once on another idle, healthy entry, with
// the exchange bounded by otherConnTimeout and ctx. served is false when
// no such entry is free or the retry also failed at the connection level,
// timed out or was abandoned for ctx (that entry is then marked broken and
// its conn retired, since a late reply could still arrive on it).
func (c *Client) sendOnOtherEntry(ctx context.Context, msg map[string]interface{}, st *sendState) (resp map[string]interface{}, served bool, err error) {
	if ctx.Err() != nil {
		return nil, false, nil
	}
	other := c.tryAcquireHealthy()
	if other == nil {
		return nil, false, nil
	}
	defer c.releaseEntry(other)
	other.mu.Lock()
	defer other.mu.Unlock()
	resp, err = boundedRoundTrip(ctx, other.conn, msg, c.reconn.pol().otherConnTimeout)
	resp, err = c.entryResult(other, st, resp, err)
	if err != nil && resp == nil {
		return nil, false, nil
	}
	if err == nil {
		c.reconn.servedByOther(c.logSummary)
	}
	return resp, true, err
}

// sendOnEntry writes the request and reads the response on entry.conn.
// Caller must hold entry.mu. A connection-level failure (no response)
// marks the entry broken and retires its conn.
func (c *Client) sendOnEntry(entry *pooledConn, msg map[string]interface{}, st *sendState) (map[string]interface{}, error) {
	resp, err := roundTrip(entry.conn, msg)
	return c.entryResult(entry, st, resp, err)
}

// entryResult records the outcome of one attempt on entry: a
// connection-level failure (no response) marks the entry broken and
// retires its conn; a response counts toward the rapid-close streak reset.
// Caller must hold entry.mu.
func (c *Client) entryResult(entry *pooledConn, st *sendState, resp map[string]interface{}, err error) (map[string]interface{}, error) {
	if err != nil && resp == nil {
		entry.broken = err
		if !c.isClosed() {
			st.streakNoted = c.noteConnError(err, time.Since(entry.dialedAt), st.streakNoted)
		}
		c.retireEntryConn(entry)
		return nil, err
	}
	c.reconn.healthy(time.Since(entry.dialedAt))
	return resp, err
}

// retireEntryConn closes a dropped entry's conn right away (rather than
// holding the fd until the entry is next used) and clears it, so Close
// never closes it a second time. Once Close has started, the conn belongs
// to Close and is left alone. Caller must hold entry.mu.
func (c *Client) retireEntryConn(entry *pooledConn) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	old := entry.conn
	entry.conn = nil
	if entry == c.pool.entries[0] {
		c.conn = nil
	}
	c.mu.Unlock()
	if old != nil {
		old.Close()
	}
}

// reconnectEntry redials a single pool entry after cause broke it (cause
// may be nil). Caller must hold entry.mu. This is the per-entry analogue
// of Client.reconnect.
func (c *Client) reconnectEntry(ctx context.Context, entry *pooledConn, cause error) error {
	if c.isClosed() {
		return ErrClosed
	}
	c.retireEntryConn(entry)

	conn, err := c.dialWithBackoff(ctx, "registry pool conn", cause)
	if err != nil {
		return err
	}
	c.mu.Lock()
	if c.closed {
		// Close ran while we were dialing and has already closed every
		// conn it could see; this one is ours to close.
		c.mu.Unlock()
		conn.Close()
		return ErrClosed
	}
	entry.conn = conn
	// Keep c.conn (primary) in sync if this is the primary entry.
	// Tests in this package read c.conn directly, so we must not
	// leave it pointing at a closed fd.
	if entry == c.pool.entries[0] {
		c.conn = conn
		c.connDialedAt = time.Now()
	}
	c.mu.Unlock()
	entry.dialedAt = time.Now()
	entry.broken = nil
	c.noteReconnected("registry pool conn", cause)
	return nil
}

// isClosed returns whether Close has been called. Cheap, lock-protected.
func (c *Client) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// sendLocked sends a message and reads the response. Must be called with c.mu held.
func (c *Client) sendLocked(msg map[string]interface{}) (map[string]interface{}, error) {
	return roundTrip(c.conn, msg)
}

// roundTrip writes msg on conn and reads the response. A nil response
// with a non-nil error is a connection-level failure; a non-nil response
// with an error is the registry's error reply.
func roundTrip(conn net.Conn, msg map[string]interface{}) (map[string]interface{}, error) {
	if conn == nil {
		return nil, errNotConnected
	}
	if err := wire.WriteMessage(conn, msg); err != nil {
		return nil, fmt.Errorf("send: %w", err)
	}
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	resp, err := wire.ReadMessage(conn)
	conn.SetReadDeadline(time.Time{})
	return checkResponse(resp, err)
}

// boundedRoundTrip is roundTrip with the whole exchange (write and read)
// limited to timeout and to ctx, both its deadline and its cancellation.
// When it gives up, the request may still be answered later on conn, so
// the caller must retire the conn.
func boundedRoundTrip(ctx context.Context, conn net.Conn, msg map[string]interface{}, timeout time.Duration) (map[string]interface{}, error) {
	if conn == nil {
		return nil, errNotConnected
	}
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn.SetDeadline(deadline)
	// Cancelling ctx interrupts the exchange by pulling the deadline in.
	// The watcher is joined before the deadline is cleared, so a
	// cancellation that races the end of the exchange cannot leave a
	// deadline on a conn that goes back to the pool.
	finished := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			conn.SetDeadline(time.Now())
		case <-finished:
		}
	}()
	var resp map[string]interface{}
	err := wire.WriteMessage(conn, msg)
	if err != nil {
		err = fmt.Errorf("send: %w", err)
	} else {
		resp, err = checkResponse(wire.ReadMessage(conn))
	}
	close(finished)
	<-watcherDone
	conn.SetDeadline(time.Time{})
	if err != nil && resp == nil && ctx.Err() != nil {
		err = fmt.Errorf("%w (%w)", err, ctx.Err())
	}
	return resp, err
}

// checkResponse turns the result of reading one response frame into
// roundTrip's result: a read error is a connection-level failure (nil
// response); an error reply or a malformed one keeps the response.
func checkResponse(resp map[string]interface{}, err error) (map[string]interface{}, error) {
	if err != nil {
		return nil, fmt.Errorf("recv: %w", err)
	}
	if errVal, ok := resp["error"]; ok {
		return resp, fmt.Errorf("registry: %v", errVal)
	}
	// PILOT-132: reject valid JSON that lacks the expected "type" envelope key.
	if _, hasType := resp["type"]; !hasType && len(resp) > 0 {
		return resp, fmt.Errorf("registry: malformed response (missing %q field)", "type")
	}
	return resp, nil
}

func (c *Client) Register(listenAddr string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "register",
		"listen_addr": listenAddr,
	})
}

// RegisterWithOwner registers a new node with an owner identifier (email/name)
// for key rotation recovery.
func (c *Client) RegisterWithOwner(listenAddr, owner string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "register",
		"listen_addr": listenAddr,
		"owner":       owner,
	})
}

// RegisterWithKey re-registers using an existing Ed25519 public key.
// The registry returns the same node_id if the key is known.
// lanAddrs are the node's LAN addresses for same-network peer detection.
func (c *Client) RegisterWithKey(listenAddr, publicKeyB64, owner string, lanAddrs []string, opts ...string) (map[string]interface{}, error) {
	return c.RegisterWithKeyOpts(RegisterOpts{
		ListenAddr: listenAddr,
		PublicKey:  publicKeyB64,
		Owner:      owner,
		LANAddrs:   lanAddrs,
		Version:    firstNonEmpty(opts...),
	})
}

// RegisterOpts is the full set of registration options. Lets us add
// fields (like RelayOnly for task 32) without breaking the variadic
// signature of RegisterWithKey.
type RegisterOpts struct {
	ListenAddr string
	PublicKey  string // base64 Ed25519
	Owner      string
	LANAddrs   []string
	Version    string
	RelayOnly  bool // task 32: hide real_addr from peers
}

// RegisterWithKeyOpts is the structured-form register call. Existing
// callers keep using RegisterWithKey; new flags go here.
func (c *Client) RegisterWithKeyOpts(o RegisterOpts) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":        "register",
		"listen_addr": o.ListenAddr,
		"public_key":  o.PublicKey,
	}
	if o.Owner != "" {
		msg["owner"] = o.Owner
	}
	if len(o.LANAddrs) > 0 {
		msg["lan_addrs"] = o.LANAddrs
	}
	if o.Version != "" {
		msg["version"] = o.Version
	}
	if o.RelayOnly {
		msg["relay_only"] = true
	}
	if o.PublicKey != "" {
		if sig, err := c.sign(fmt.Sprintf("register:%s:%s", o.ListenAddr, o.PublicKey)); err == nil {
			msg["signature"] = sig
		}
	}
	return c.Send(msg)
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

// RotateKey requests a key rotation for a node.
// Requires a signature proving ownership of the current key and the new public key.
func (c *Client) RotateKey(nodeID uint32, signatureB64, newPubKeyB64 string) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":    "rotate_key",
		"node_id": nodeID,
	}
	if signatureB64 != "" {
		msg["signature"] = signatureB64
	}
	if newPubKeyB64 != "" {
		msg["new_public_key"] = newPubKeyB64
	}
	return c.Send(msg)
}

// SubmitBadge attaches a verified-address badge to a node. signatureB64 is a
// signature by the node's CURRENT key over "submit_badge:<node_id>:<badge>",
// proving ownership; the registry also verifies the badge offline against the
// pinned issuer key.
func (c *Client) SubmitBadge(nodeID uint32, badge, badgeSig, signatureB64 string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":      "submit_badge",
		"node_id":   nodeID,
		"badge":     badge,
		"badge_sig": badgeSig,
		"signature": signatureB64,
	})
}

// EnrollRecovery records a node's opaque recovery commitment. signatureB64 is
// a signature by the node's CURRENT key over
// "enroll_recovery:<node_id>:<commitment>".
func (c *Client) EnrollRecovery(nodeID uint32, enrollment, enrollmentSig, signatureB64 string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":           "enroll_recovery",
		"node_id":        nodeID,
		"enrollment":     enrollment,
		"enrollment_sig": enrollmentSig,
		"signature":      signatureB64,
	})
}

// RecoverIdentity force-rotates a node's key to newPubKeyB64 using a
// cold-key-signed recovery authorization — no current key required.
func (c *Client) RecoverIdentity(nodeID uint32, recovery, recoverySig, newPubKeyB64 string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":           "recover_identity",
		"node_id":        nodeID,
		"recovery":       recovery,
		"recovery_sig":   recoverySig,
		"new_public_key": newPubKeyB64,
	})
}

func (c *Client) Lookup(nodeID uint32) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":    "lookup",
		"node_id": nodeID,
	})
}

func (c *Client) Resolve(nodeID, requesterID uint32) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":         "resolve",
		"node_id":      nodeID,
		"requester_id": requesterID,
	}
	sig, err := c.sign(fmt.Sprintf("resolve:%d:%d", requesterID, nodeID))
	if err != nil {
		return nil, err
	}
	msg["signature"] = sig
	return c.Send(msg)
}

func (c *Client) ReportTrust(nodeID, peerID uint32) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":    "report_trust",
		"node_id": nodeID,
		"peer_id": peerID,
	}
	sig, err := c.sign(fmt.Sprintf("report_trust:%d:%d", nodeID, peerID))
	if err != nil {
		return nil, err
	}
	msg["signature"] = sig
	return c.Send(msg)
}

func (c *Client) RevokeTrust(nodeID, peerID uint32) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":    "revoke_trust",
		"node_id": nodeID,
		"peer_id": peerID,
	}
	sig, err := c.sign(fmt.Sprintf("revoke_trust:%d:%d", nodeID, peerID))
	if err != nil {
		return nil, err
	}
	msg["signature"] = sig
	return c.Send(msg)
}

func (c *Client) SetVisibility(nodeID uint32, public bool) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":    "set_visibility",
		"node_id": nodeID,
		"public":  public,
	}
	sig, err := c.sign(fmt.Sprintf("set_visibility:%d", nodeID))
	if err != nil {
		return nil, err
	}
	msg["signature"] = sig
	return c.Send(msg)
}

func (c *Client) CreateNetwork(nodeID uint32, name, joinRule, token, adminToken string, enterprise bool, networkAdminToken ...string) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":      "create_network",
		"node_id":   nodeID,
		"name":      name,
		"join_rule": joinRule,
		"token":     token,
	}
	if adminToken != "" {
		msg["admin_token"] = adminToken
	}
	if enterprise {
		msg["enterprise"] = true
	}
	if len(networkAdminToken) > 0 && networkAdminToken[0] != "" {
		msg["network_admin_token"] = networkAdminToken[0]
	}
	return c.Send(msg)
}

// CreateManagedNetwork creates a network with managed rules.
func (c *Client) CreateManagedNetwork(nodeID uint32, name, joinRule, token, adminToken string, enterprise bool, rules string, networkAdminToken ...string) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":      "create_network",
		"node_id":   nodeID,
		"name":      name,
		"join_rule": joinRule,
		"token":     token,
		"rules":     rules,
	}
	if adminToken != "" {
		msg["admin_token"] = adminToken
	}
	if enterprise {
		msg["enterprise"] = true
	}
	if len(networkAdminToken) > 0 && networkAdminToken[0] != "" {
		msg["network_admin_token"] = networkAdminToken[0]
	}
	return c.Send(msg)
}

func (c *Client) JoinNetwork(nodeID uint32, networkID uint16, token string, inviterID uint32, adminToken string) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":       "join_network",
		"node_id":    nodeID,
		"network_id": networkID,
		"token":      token,
		"inviter_id": inviterID,
	}
	sig, err := c.sign(fmt.Sprintf("join_network:%d:%d", nodeID, networkID))
	if err == nil {
		msg["signature"] = sig
	} else if adminToken != "" {
		msg["admin_token"] = adminToken
	}
	return c.Send(msg)
}

func (c *Client) LeaveNetwork(nodeID uint32, networkID uint16, adminToken string) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":       "leave_network",
		"node_id":    nodeID,
		"network_id": networkID,
	}
	sig, err := c.sign(fmt.Sprintf("leave_network:%d:%d", nodeID, networkID))
	if err == nil {
		msg["signature"] = sig
	} else if adminToken != "" {
		msg["admin_token"] = adminToken
	}
	return c.Send(msg)
}

func (c *Client) DeleteNetwork(networkID uint16, adminToken string, nodeID ...uint32) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":       "delete_network",
		"network_id": networkID,
	}
	if adminToken != "" {
		msg["admin_token"] = adminToken
	}
	if len(nodeID) > 0 && nodeID[0] != 0 {
		msg["node_id"] = nodeID[0]
	}
	return c.Send(msg)
}

func (c *Client) RenameNetwork(networkID uint16, name, adminToken string, nodeID ...uint32) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":       "rename_network",
		"network_id": networkID,
		"name":       name,
	}
	if adminToken != "" {
		msg["admin_token"] = adminToken
	}
	if len(nodeID) > 0 && nodeID[0] != 0 {
		msg["node_id"] = nodeID[0]
	}
	return c.Send(msg)
}

func (c *Client) SetNetworkEnterprise(networkID uint16, enterprise bool, adminToken string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "set_network_enterprise",
		"network_id":  networkID,
		"enterprise":  enterprise,
		"admin_token": adminToken,
	})
}

// ListNetworks returns the registry's network catalog. Member counts
// (the `members` field on each entry) are admin-only — pass a non-empty
// adminToken to receive them; otherwise the field is omitted.
func (c *Client) ListNetworks(adminToken ...string) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type": "list_networks",
	}
	if len(adminToken) > 0 && adminToken[0] != "" {
		msg["admin_token"] = adminToken[0]
	}
	return c.Send(msg)
}

func (c *Client) ListNodes(networkID uint16, adminToken ...string) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":       "list_nodes",
		"network_id": networkID,
	}
	if len(adminToken) > 0 && adminToken[0] != "" {
		msg["admin_token"] = adminToken[0]
	}
	return c.Send(msg)
}

func (c *Client) Deregister(nodeID uint32) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":    "deregister",
		"node_id": nodeID,
	}
	sig, err := c.sign(fmt.Sprintf("deregister:%d", nodeID))
	if err != nil {
		return nil, err
	}
	msg["signature"] = sig
	return c.Send(msg)
}

func (c *Client) Heartbeat(nodeID uint32) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":    "heartbeat",
		"node_id": nodeID,
	}
	sig, err := c.sign(fmt.Sprintf("heartbeat:%d", nodeID))
	if err != nil {
		return nil, err
	}
	msg["signature"] = sig
	return c.Send(msg)
}

func (c *Client) Punch(requesterID, nodeA, nodeB uint32) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":         "punch",
		"requester_id": requesterID,
		"node_a":       nodeA,
		"node_b":       nodeB,
	}
	sig, err := c.sign(fmt.Sprintf("punch:%d:%d", nodeA, nodeB))
	if err != nil {
		return nil, err
	}
	msg["signature"] = sig
	return c.Send(msg)
}

// RequestHandshake relays a handshake request through the registry to a target node.
// This works even for private nodes — no IP exposure needed.
// M12 fix: includes a signature to prove sender identity.
func (c *Client) RequestHandshake(fromNodeID, toNodeID uint32, justification, signatureB64 string) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":          "request_handshake",
		"from_node_id":  fromNodeID,
		"to_node_id":    toNodeID,
		"justification": justification,
	}
	if signatureB64 != "" {
		msg["signature"] = signatureB64
	}
	return c.Send(msg)
}

// PollHandshakes retrieves and clears pending handshake requests for a node.
// H3 fix: includes a signature to prove node identity.
func (c *Client) PollHandshakes(nodeID uint32) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":    "poll_handshakes",
		"node_id": nodeID,
	}
	sig, err := c.sign(fmt.Sprintf("poll_handshakes:%d", nodeID))
	if err != nil {
		return nil, err
	}
	msg["signature"] = sig
	return c.Send(msg)
}

// RespondHandshake approves or rejects a relayed handshake request.
// If accepted, the registry creates a mutual trust pair.
// M12 fix: includes a signature to prove responder identity.
func (c *Client) RespondHandshake(nodeID, peerID uint32, accept bool, signatureB64 string) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":    "respond_handshake",
		"node_id": nodeID,
		"peer_id": peerID,
		"accept":  accept,
	}
	if signatureB64 != "" {
		msg["signature"] = signatureB64
	}
	return c.Send(msg)
}

// SetHostname sets or clears the hostname for a node.
// An empty hostname clears the current hostname.
func (c *Client) SetHostname(nodeID uint32, hostname string) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":     "set_hostname",
		"node_id":  nodeID,
		"hostname": hostname,
	}
	sig, err := c.sign(fmt.Sprintf("set_hostname:%d", nodeID))
	if err != nil {
		return nil, err
	}
	msg["signature"] = sig
	return c.Send(msg)
}

// SetTags sets the capability tags for a node.
func (c *Client) SetTags(nodeID uint32, tags []string) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":    "set_tags",
		"node_id": nodeID,
		"tags":    tags,
	}
	sig, err := c.sign(fmt.Sprintf("set_tags:%d", nodeID))
	if err != nil {
		return nil, err
	}
	msg["signature"] = sig
	return c.Send(msg)
}

// ResolveHostname resolves a hostname to node info (node_id, address, public flag).
func (c *Client) ResolveHostname(hostname string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":     "resolve_hostname",
		"hostname": hostname,
	})
}

// ResolveHostnameAs resolves a hostname with a requester_id for privacy checks.
// Private nodes require the requester to have a trust pair or shared network.
func (c *Client) ResolveHostnameAs(requesterID uint32, hostname string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":         "resolve_hostname",
		"hostname":     hostname,
		"requester_id": requesterID,
	})
}

// CheckTrust checks if a trust pair or shared network exists between two nodes.
func (c *Client) CheckTrust(nodeA, nodeB uint32) (bool, error) {
	if c == nil {
		return false, ErrNoRegistry
	}
	resp, err := c.Send(map[string]interface{}{
		"type":    "check_trust",
		"node_id": nodeA,
		"peer_id": nodeB,
	})
	if err != nil {
		return false, err
	}
	trusted, _ := resp["trusted"].(bool)
	return trusted, nil
}

// InviteToNetwork stores a pending invite for a target node to join an invite-only network.
func (c *Client) InviteToNetwork(networkID uint16, inviterID, targetNodeID uint32, adminToken string) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":           "invite_to_network",
		"network_id":     networkID,
		"inviter_id":     inviterID,
		"target_node_id": targetNodeID,
	}
	sig, err := c.sign(fmt.Sprintf("invite:%d:%d:%d", inviterID, networkID, targetNodeID))
	if err != nil {
		return nil, err
	}
	msg["signature"] = sig
	if adminToken != "" {
		msg["admin_token"] = adminToken
	}
	return c.Send(msg)
}

// PollInvites returns and clears pending network invites for a node. Signed.
func (c *Client) PollInvites(nodeID uint32) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":    "poll_invites",
		"node_id": nodeID,
	}
	sig, err := c.sign(fmt.Sprintf("poll_invites:%d", nodeID))
	if err != nil {
		return nil, err
	}
	msg["signature"] = sig
	return c.Send(msg)
}

// RespondInvite accepts or rejects a pending network invite. Signed.
func (c *Client) RespondInvite(nodeID uint32, networkID uint16, accept bool) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":       "respond_invite",
		"node_id":    nodeID,
		"network_id": networkID,
		"accept":     accept,
	}
	sig, err := c.sign(fmt.Sprintf("respond_invite:%d:%d", nodeID, networkID))
	if err != nil {
		return nil, err
	}
	msg["signature"] = sig
	return c.Send(msg)
}

// PromoteMember promotes a network member to admin. Only the owner can promote.
func (c *Client) PromoteMember(networkID uint16, nodeID, targetNodeID uint32, adminToken string) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":           "promote_member",
		"network_id":     networkID,
		"node_id":        nodeID,
		"target_node_id": targetNodeID,
	}
	if adminToken != "" {
		msg["admin_token"] = adminToken
	}
	return c.Send(msg)
}

// DemoteMember demotes an admin to member. Only the owner can demote.
func (c *Client) DemoteMember(networkID uint16, nodeID, targetNodeID uint32, adminToken string) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":           "demote_member",
		"network_id":     networkID,
		"node_id":        nodeID,
		"target_node_id": targetNodeID,
	}
	if adminToken != "" {
		msg["admin_token"] = adminToken
	}
	return c.Send(msg)
}

// KickMember removes a member from a network. Requires owner or admin role.
func (c *Client) KickMember(networkID uint16, nodeID, targetNodeID uint32, adminToken string) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":           "kick_member",
		"network_id":     networkID,
		"node_id":        nodeID,
		"target_node_id": targetNodeID,
	}
	if adminToken != "" {
		msg["admin_token"] = adminToken
	}
	return c.Send(msg)
}

// TransferOwnership transfers network ownership to another member. Only the current owner can transfer.
func (c *Client) TransferOwnership(networkID uint16, ownerNodeID, newOwnerID uint32, adminToken string) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":         "transfer_ownership",
		"network_id":   networkID,
		"node_id":      ownerNodeID,
		"new_owner_id": newOwnerID,
	}
	if adminToken != "" {
		msg["admin_token"] = adminToken
	}
	return c.Send(msg)
}

// GetMemberRole returns the RBAC role of a node in a network.
func (c *Client) GetMemberRole(networkID uint16, targetNodeID uint32) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":           "get_member_role",
		"network_id":     networkID,
		"target_node_id": targetNodeID,
	})
}

// SetNetworkPolicy sets or updates a network's policy. Requires owner/admin role or admin token.
func (c *Client) SetNetworkPolicy(networkID uint16, policy map[string]interface{}, adminToken string) (map[string]interface{}, error) {
	msg := map[string]interface{}{}
	for k, v := range policy {
		msg[k] = v
	}
	msg["type"] = "set_network_policy"
	msg["network_id"] = networkID
	if adminToken != "" {
		msg["admin_token"] = adminToken
	}
	return c.Send(msg)
}

// GetNetworkPolicy returns the policy for a given network.
func (c *Client) GetNetworkPolicy(networkID uint16) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":       "get_network_policy",
		"network_id": networkID,
	})
}

// SetExprPolicy sets the programmable policy for a network.
// Requires owner/admin role or admin token.
func (c *Client) SetExprPolicy(networkID uint16, policyJSON json.RawMessage, adminToken string) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":        "set_expr_policy",
		"network_id":  networkID,
		"expr_policy": string(policyJSON),
	}
	if adminToken != "" {
		msg["admin_token"] = adminToken
	}
	return c.Send(msg)
}

// GetExprPolicy returns the programmable policy for a network.
func (c *Client) GetExprPolicy(networkID uint16) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":       "get_expr_policy",
		"network_id": networkID,
	})
}

// SetKeyExpiry sets the key expiry time for a node. Requires signature.
func (c *Client) SetKeyExpiry(nodeID uint32, expiresAt time.Time) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":       "set_key_expiry",
		"node_id":    nodeID,
		"expires_at": expiresAt.Format(time.RFC3339),
	}
	sig, err := c.sign(fmt.Sprintf("set_key_expiry:%d", nodeID))
	if err != nil {
		return nil, err
	}
	msg["signature"] = sig
	return c.Send(msg)
}

// GetKeyInfo returns key lifecycle metadata for a node.
func (c *Client) GetKeyInfo(nodeID uint32) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":    "get_key_info",
		"node_id": nodeID,
	})
}

// --- Admin methods (bypass node signature, use admin_token instead) ---

// SetHostnameAdmin sets a node's hostname using admin token auth.
func (c *Client) SetHostnameAdmin(nodeID uint32, hostname, adminToken string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "set_hostname",
		"node_id":     nodeID,
		"hostname":    hostname,
		"admin_token": adminToken,
	})
}

// SetVisibilityAdmin sets a node's visibility using admin token auth.
func (c *Client) SetVisibilityAdmin(nodeID uint32, public bool, adminToken string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "set_visibility",
		"node_id":     nodeID,
		"public":      public,
		"admin_token": adminToken,
	})
}

// SetTagsAdmin sets a node's tags using admin token auth.
func (c *Client) SetTagsAdmin(nodeID uint32, tags []string, adminToken string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "set_tags",
		"node_id":     nodeID,
		"tags":        tags,
		"admin_token": adminToken,
	})
}

// SetMemberTags sets admin-assigned tags for a member within a network.
func (c *Client) SetMemberTags(netID uint16, targetNodeID uint32, tags []string, adminToken string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":           "set_member_tags",
		"network_id":     netID,
		"target_node_id": targetNodeID,
		"tags":           tags,
		"admin_token":    adminToken,
	})
}

// GetMemberTags returns admin-assigned member tags for a node (or all members if targetNodeID=0).
func (c *Client) GetMemberTags(netID uint16, targetNodeID uint32) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":           "get_member_tags",
		"network_id":     netID,
		"target_node_id": targetNodeID,
	})
}

// SetKeyExpiryAdmin sets a node's key expiry using admin token auth.
func (c *Client) SetKeyExpiryAdmin(nodeID uint32, expiresAt time.Time, adminToken string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "set_key_expiry",
		"node_id":     nodeID,
		"expires_at":  expiresAt.Format(time.RFC3339),
		"admin_token": adminToken,
	})
}

// ClearKeyExpiryAdmin removes the key expiry from a node using admin token auth.
func (c *Client) ClearKeyExpiryAdmin(nodeID uint32, adminToken string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "set_key_expiry",
		"node_id":     nodeID,
		"expires_at":  "never",
		"admin_token": adminToken,
	})
}

// DeregisterAdmin removes a node using admin token auth.
func (c *Client) DeregisterAdmin(nodeID uint32, adminToken string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "deregister",
		"node_id":     nodeID,
		"admin_token": adminToken,
	})
}

// GetAuditLog returns recent audit entries from the registry.
func (c *Client) GetAuditLog(networkID uint16, adminToken string) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":        "get_audit_log",
		"admin_token": adminToken,
	}
	if networkID != 0 {
		msg["network_id"] = networkID
	}
	return c.Send(msg)
}

// SetWebhook configures the registry webhook URL. Pass empty string to disable.
func (c *Client) SetWebhook(url, adminToken string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "set_webhook",
		"url":         url,
		"admin_token": adminToken,
	})
}

// GetWebhook returns the current webhook configuration.
func (c *Client) GetWebhook(adminToken string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "get_webhook",
		"admin_token": adminToken,
	})
}

// GetWebhookDLQ returns the dead letter queue (failed webhook events).
func (c *Client) GetWebhookDLQ(adminToken string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "get_webhook_dlq",
		"admin_token": adminToken,
	})
}

// SetIdentityWebhook configures the identity verification webhook URL.
func (c *Client) SetIdentityWebhook(url, adminToken string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "set_identity_webhook",
		"url":         url,
		"admin_token": adminToken,
	})
}

// SetExternalID sets the external identity on a node. Requires admin token.
func (c *Client) SetExternalID(nodeID uint32, externalID, adminToken string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "set_external_id",
		"node_id":     nodeID,
		"external_id": externalID,
		"admin_token": adminToken,
	})
}

// GetIdentity returns the external identity of a node. Requires admin token.
func (c *Client) GetIdentity(nodeID uint32, adminToken string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "get_identity",
		"node_id":     nodeID,
		"admin_token": adminToken,
	})
}

// ProvisionNetwork applies a network blueprint. Requires admin token.
func (c *Client) ProvisionNetwork(blueprint map[string]interface{}, adminToken string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "provision_network",
		"blueprint":   blueprint,
		"admin_token": adminToken,
	})
}

// SetAuditExport configures the audit export adapter. Requires admin token.
func (c *Client) SetAuditExport(format, endpoint, token, index, source, adminToken string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "set_audit_export",
		"format":      format,
		"endpoint":    endpoint,
		"token":       token,
		"index":       index,
		"source":      source,
		"admin_token": adminToken,
	})
}

// GetAuditExport returns the current audit export configuration. Requires admin token.
func (c *Client) GetAuditExport(adminToken string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "get_audit_export",
		"admin_token": adminToken,
	})
}

// SetIDPConfig configures the identity provider. Requires admin token.
func (c *Client) SetIDPConfig(idpType, url, issuer, clientID, tenantID, domain, adminToken string) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"type":        "set_idp_config",
		"idp_type":    idpType,
		"url":         url,
		"admin_token": adminToken,
	}
	if issuer != "" {
		msg["issuer"] = issuer
	}
	if clientID != "" {
		msg["client_id"] = clientID
	}
	if tenantID != "" {
		msg["tenant_id"] = tenantID
	}
	if domain != "" {
		msg["domain"] = domain
	}
	return c.Send(msg)
}

// GetIDPConfig returns the current identity provider configuration. Requires admin token.
func (c *Client) GetIDPConfig(adminToken string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "get_idp_config",
		"admin_token": adminToken,
	})
}

// GetProvisionStatus returns per-network provisioning status. Requires admin token.
func (c *Client) GetProvisionStatus(adminToken string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "get_provision_status",
		"admin_token": adminToken,
	})
}

// DirectorySync pushes a directory listing to update RBAC roles and membership.
func (c *Client) DirectorySync(networkID uint16, entries []map[string]interface{}, removeUnlisted bool, adminToken string) (map[string]interface{}, error) {
	entryList := make([]interface{}, len(entries))
	for i, e := range entries {
		entryList[i] = e
	}
	return c.Send(map[string]interface{}{
		"type":            "directory_sync",
		"network_id":      networkID,
		"entries":         entryList,
		"remove_unlisted": removeUnlisted,
		"admin_token":     adminToken,
	})
}

// DirectoryStatus returns directory sync status for a network.
func (c *Client) DirectoryStatus(networkID uint16, adminToken string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "directory_status",
		"network_id":  networkID,
		"admin_token": adminToken,
	})
}

// ValidateToken validates a JWT token against the configured IDP. Requires admin token.
func (c *Client) ValidateToken(token, adminToken string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{
		"type":        "validate_token",
		"token":       token,
		"admin_token": adminToken,
	})
}
