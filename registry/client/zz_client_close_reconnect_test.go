// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/pilot-protocol/common/registry/wire"
)

// Regression and behaviour tests for:
//
//   - Close idempotency (nightly "close of closed channel" panic when the
//     daemon's forceReconnectRegistry `go old.Close()` raced Stop's Close);
//   - pool reconnect behaviour: the triggering error is kept, per-reconnect
//     success logging is Debug with a periodic INFO summary, jittered
//     exponential backoff on rapid server closes (the registry rate
//     limiter's EOF-without-error-frame signature) and on repeated reconnect
//     failures, and a retry on another healthy pool conn before redialing.

// --- helpers ----------------------------------------------------------------

// scriptedRegistry is a JSON-wire registry stand-in whose drop hook decides,
// per request, whether to close the connection without answering (what the
// real registry does when its rate limiter denies a request).
type scriptedRegistry struct {
	ln       net.Listener
	conns    atomic.Int32 // connections accepted
	received atomic.Int32 // requests read (answered, dropped or hung)
	served   atomic.Int32 // requests answered
	dropped  atomic.Int32 // requests answered by closing the conn
	hung     atomic.Int32 // requests never answered, conn left open

	mu   sync.Mutex
	drop func(connSeq, reqSeq int, age time.Duration) bool
	// hang, when set, picks requests that are read but never answered
	// while the conn stays open: a silently hung registry connection.
	hang func(connSeq, reqSeq int) bool
	live []net.Conn
	wg   sync.WaitGroup
}

func newScriptedRegistry(t *testing.T, drop func(connSeq, reqSeq int, age time.Duration) bool) *scriptedRegistry {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &scriptedRegistry{ln: ln, drop: drop}
	s.wg.Add(1)
	go s.accept()
	t.Cleanup(s.stop)
	return s
}

// closeAfter answers n requests per connection, then closes the connection
// on the next request without replying.
func closeAfter(n int) func(int, int, time.Duration) bool {
	return func(_, reqSeq int, _ time.Duration) bool { return reqSeq > n }
}

// afterGrace mimics the production registry: the first request that
// arrives on a connection older than grace is closed without a reply.
func afterGrace(grace time.Duration) func(int, int, time.Duration) bool {
	return func(_, _ int, age time.Duration) bool { return age >= grace }
}

func neverDrop(int, int, time.Duration) bool { return false }

func (s *scriptedRegistry) addr() string { return s.ln.Addr().String() }

// waitConns waits until the server has accepted n connections. Closing the
// listener before that would reset connections still in the accept queue.
func (s *scriptedRegistry) waitConns(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for int(s.conns.Load()) < n {
		if time.Now().After(deadline) {
			t.Fatalf("server accepted %d conns, want %d", s.conns.Load(), n)
		}
		time.Sleep(time.Millisecond)
	}
}

func (s *scriptedRegistry) setDrop(fn func(int, int, time.Duration) bool) {
	s.mu.Lock()
	s.drop = fn
	s.mu.Unlock()
}

func (s *scriptedRegistry) setHang(fn func(connSeq, reqSeq int) bool) {
	s.mu.Lock()
	s.hang = fn
	s.mu.Unlock()
}

// shutdown stops accepting and closes every live connection, so redials fail.
func (s *scriptedRegistry) shutdown() {
	s.ln.Close()
	s.mu.Lock()
	for _, c := range s.live {
		c.Close()
	}
	s.mu.Unlock()
}

func (s *scriptedRegistry) stop() {
	s.shutdown()
	s.wg.Wait()
}

func (s *scriptedRegistry) accept() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		seq := int(s.conns.Add(1))
		s.mu.Lock()
		s.live = append(s.live, conn)
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serve(conn, seq)
		}()
	}
}

func (s *scriptedRegistry) serve(conn net.Conn, connSeq int) {
	defer conn.Close()
	start := time.Now()
	for reqSeq := 1; ; reqSeq++ {
		var lenBuf [4]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(lenBuf[:])
		if n > 1<<20 {
			return
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(conn, body); err != nil {
			return
		}
		var req map[string]interface{}
		if err := json.Unmarshal(body, &req); err != nil {
			return
		}
		s.received.Add(1)
		s.mu.Lock()
		drop, hang := s.drop, s.hang
		s.mu.Unlock()
		if hang != nil && hang(connSeq, reqSeq) {
			s.hung.Add(1)
			_, _ = io.Copy(io.Discard, conn) // until the client gives up
			return
		}
		if drop(connSeq, reqSeq, time.Since(start)) {
			s.dropped.Add(1)
			return // close without an error frame
		}
		out, _ := json.Marshal(map[string]interface{}{"type": "ok", "echo": req})
		var outLen [4]byte
		binary.BigEndian.PutUint32(outLen[:], uint32(len(out)))
		if _, err := conn.Write(append(outLen[:], out...)); err != nil {
			return
		}
		s.served.Add(1)
	}
}

// holdIdleEntries takes n entries off the pool's free list so requests
// cannot use them, and returns an idempotent function that gives them back.
func holdIdleEntries(t *testing.T, c *Client, n int) func() {
	t.Helper()
	held := make([]*pooledConn, 0, n)
	for i := 0; i < n; i++ {
		select {
		case e := <-c.pool.free:
			held = append(held, e)
		case <-time.After(2 * time.Second):
			t.Fatalf("could not take pool entry %d", i)
		}
	}
	var once sync.Once
	release := func() {
		once.Do(func() {
			for _, e := range held {
				c.releaseEntry(e)
			}
		})
	}
	t.Cleanup(release)
	return release
}

// holdAllBut takes every pool entry except keep off the free list (all
// entries must be idle), so the next request is forced onto keep. It
// returns an idempotent function that gives them back.
func holdAllBut(t *testing.T, c *Client, keep *pooledConn) func() {
	t.Helper()
	var held []*pooledConn
	for range len(c.pool.entries) {
		select {
		case e := <-c.pool.free:
			if e != keep {
				held = append(held, e)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("pool entry not idle")
		}
	}
	c.releaseEntry(keep)
	var once sync.Once
	release := func() {
		once.Do(func() {
			for _, e := range held {
				c.releaseEntry(e)
			}
		})
	}
	t.Cleanup(release)
	return release
}

// countingConn counts Close calls on one dialed connection.
type countingConn struct {
	net.Conn
	closes atomic.Int32
}

func (c *countingConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

// connRecorder is a WithDialer dialer that records every connection it
// opens. When gate is non-nil it is called with the 1-based dial number
// and may return a channel the dial then waits on.
type connRecorder struct {
	mu    sync.Mutex
	conns []*countingConn
	gate  func(n int) <-chan struct{}
}

func (r *connRecorder) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	r.mu.Lock()
	n := len(r.conns) + 1
	gate := r.gate
	r.mu.Unlock()
	if gate != nil {
		if ch := gate(n); ch != nil {
			<-ch
		}
	}
	var d net.Dialer
	raw, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	cc := &countingConn{Conn: raw}
	r.mu.Lock()
	r.conns = append(r.conns, cc)
	r.mu.Unlock()
	return cc, nil
}

func (r *connRecorder) all() []*countingConn {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*countingConn(nil), r.conns...)
}

// logCapture is a slog.Handler that records every record at every level.
type logCapture struct {
	mu   sync.Mutex
	recs []capturedLog
}

type capturedLog struct {
	level slog.Level
	msg   string
	attrs map[string]any
}

func (h *logCapture) Enabled(context.Context, slog.Level) bool { return true }
func (h *logCapture) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *logCapture) WithGroup(string) slog.Handler            { return h }
func (h *logCapture) Handle(_ context.Context, r slog.Record) error {
	rec := capturedLog{level: r.Level, msg: r.Message, attrs: map[string]any{}}
	r.Attrs(func(a slog.Attr) bool {
		rec.attrs[a.Key] = a.Value.Resolve().Any()
		return true
	})
	h.mu.Lock()
	h.recs = append(h.recs, rec)
	h.mu.Unlock()
	return nil
}

func (h *logCapture) find(level slog.Level, msg string) []capturedLog {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []capturedLog
	for _, r := range h.recs {
		if r.level == level && r.msg == msg {
			out = append(out, r)
		}
	}
	return out
}

func (h *logCapture) count(level slog.Level) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, r := range h.recs {
		if r.level == level {
			n++
		}
	}
	return n
}

// testPolicy is a reconnect policy with test-sized timings.
func testPolicy() *reconnectPolicy {
	return &reconnectPolicy{
		dialBase:     5 * time.Millisecond,
		dialMax:      20 * time.Millisecond,
		cooldownBase: 10 * time.Millisecond,
		cooldownMax:  80 * time.Millisecond,
		rapidWindow:  30 * time.Second,
		quietReset:   time.Hour,
		summaryEvery: time.Hour,
		// Generous: tests that need a hung other conn shrink it.
		otherConnTimeout: 5 * time.Second,
	}
}

// instrument points c at a log capture and a test policy. It must run
// before c is used concurrently.
func instrument(c *Client, p *reconnectPolicy) *logCapture {
	h := &logCapture{}
	c.logger = slog.New(h)
	c.reconn.policy = p
	return h
}

func send(c *Client, typ string) (map[string]interface{}, error) {
	return c.Send(map[string]interface{}{"type": typ})
}

func mustOK(t *testing.T, c *Client, typ string) {
	t.Helper()
	resp, err := send(c, typ)
	if err != nil {
		t.Fatalf("send %q: %v", typ, err)
	}
	if resp["type"] != "ok" {
		t.Fatalf("send %q: resp %v", typ, resp)
	}
}

func assertClosedErr(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error after Close, got nil")
	}
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("err = %v, want errors.Is(err, ErrClosed)", err)
	}
	if !errors.Is(err, ErrNoRegistry) {
		t.Fatalf("err = %v, want errors.Is(err, ErrNoRegistry)", err)
	}
	if !strings.Contains(err.Error(), "closed") {
		t.Fatalf("err = %q, want it to mention closed", err)
	}
}

// --- Close: idempotent, race-free ---------------------------------------------

func TestErrClosedMatchesErrNoRegistry(t *testing.T) {
	t.Parallel()
	if !errors.Is(ErrClosed, ErrNoRegistry) {
		t.Fatal("errors.Is(ErrClosed, ErrNoRegistry) = false")
	}
	if errors.Is(ErrNoRegistry, ErrClosed) {
		t.Fatal("ErrNoRegistry must not match ErrClosed")
	}
	wrapped := closedDuring(io.EOF)
	if !errors.Is(wrapped, ErrClosed) || !errors.Is(wrapped, io.EOF) {
		t.Fatalf("closedDuring(EOF) = %v, want both ErrClosed and io.EOF in the chain", wrapped)
	}
	if closedDuring(nil) != ErrClosed || closedDuring(ErrClosed) != ErrClosed {
		t.Fatal("closedDuring(nil / ErrClosed) must return ErrClosed itself")
	}
}

// TestCloseTwiceDoesNotPanic is the direct regression for the nightly
// "panic: close of closed channel" at Client.Close: a pooled client closed
// once by forceReconnectRegistry's `go old.Close()` and once by Stop.
func TestCloseTwiceDoesNotPanic(t *testing.T) {
	t.Parallel()
	for _, size := range []int{1, 4} {
		srv := newScriptedRegistry(t, neverDrop)
		c, err := DialPool(srv.addr(), size)
		if err != nil {
			t.Fatalf("DialPool(%d): %v", size, err)
		}
		mustOK(t, c, "warm")
		if err := c.Close(); err != nil {
			t.Fatalf("size %d: first Close: %v", size, err)
		}
		if err := c.Close(); err != nil {
			t.Fatalf("size %d: second Close = %v, want nil", size, err)
		}
		_, err = send(c, "after-close")
		assertClosedErr(t, err)
	}
}

// TestCloseRacesCloseAndSend reproduces the daemon shape under -race: many
// goroutines hammer Send while two goroutines Close the same client (Stop
// and a forced reconnect retiring it). Nothing may panic, every failed Send
// must report the client closed, and Send after Close must keep doing so.
func TestCloseRacesCloseAndSend(t *testing.T) {
	t.Parallel()
	ctors := map[string]func(addr string) (*Client, error){
		"Dial":     func(a string) (*Client, error) { return Dial(a) },
		"DialPool": func(a string) (*Client, error) { return DialPool(a, 4) },
	}
	for name, dial := range ctors {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			srv := newScriptedRegistry(t, neverDrop)
			for iter := 0; iter < 20; iter++ {
				c, err := dial(srv.addr())
				if err != nil {
					t.Fatalf("dial: %v", err)
				}
				instrument(c, testPolicy())

				var wg sync.WaitGroup
				start := make(chan struct{})
				errs := make(chan error, 64)
				for g := 0; g < 8; g++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						<-start
						for {
							if _, err := send(c, "x"); err != nil {
								errs <- err
								return
							}
						}
					}()
				}
				closeErrs := make(chan error, 3)
				for g := 0; g < 3; g++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						<-start
						time.Sleep(time.Millisecond)
						closeErrs <- c.Close()
					}()
				}
				close(start)
				wg.Wait()
				close(errs)
				close(closeErrs)
				for err := range errs {
					assertClosedErr(t, err)
				}
				for err := range closeErrs {
					if err != nil {
						t.Fatalf("Close: %v", err)
					}
				}
				_, err = send(c, "after")
				assertClosedErr(t, err)
			}
		})
	}
}

// TestCloseClosesEveryPoolConnExactlyOnce checks that Close (called several
// times, concurrently) closes each pooled connection exactly once, including
// a connection that replaced a dropped one, and that the dropped connection
// itself was closed exactly once.
func TestCloseClosesEveryPoolConnExactlyOnce(t *testing.T) {
	t.Parallel()
	srv := newScriptedRegistry(t, func(connSeq, reqSeq int, _ time.Duration) bool {
		return connSeq == 1 && reqSeq == 1 // drop the primary's first request
	})
	rec := &connRecorder{}
	c, err := DialPool(srv.addr(), 3, WithDialer(rec.dial))
	if err != nil {
		t.Fatalf("DialPool: %v", err)
	}
	instrument(c, testPolicy())
	release := holdAllBut(t, c, c.pool.entries[0]) // only the primary is free
	mustOK(t, c, "drop-then-redial")
	release()
	if got := len(rec.all()); got != 4 {
		t.Fatalf("dials = %d, want 4 (3 pool conns + 1 redial)", got)
	}

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = c.Close() }()
	}
	wg.Wait()
	_ = c.Close()

	for i, cc := range rec.all() {
		if n := cc.closes.Load(); n != 1 {
			t.Errorf("conn %d closed %d times, want exactly 1", i, n)
		}
	}
}

// TestCloseDuringRedialClosesLateConn: Close runs while a pool entry is being
// redialed. The redial completes after Close; its connection must be closed
// (not leaked into a closed client) and the request must report ErrClosed.
func TestCloseDuringRedialClosesLateConn(t *testing.T) {
	t.Parallel()
	srv := newScriptedRegistry(t, func(connSeq, reqSeq int, _ time.Duration) bool {
		return connSeq == 1 && reqSeq == 1
	})
	gate := make(chan struct{})
	entered := make(chan struct{})
	rec := &connRecorder{gate: func(n int) <-chan struct{} {
		if n == 3 { // the redial after the two initial pool conns
			close(entered)
			return gate
		}
		return nil
	}}
	c, err := DialPool(srv.addr(), 2, WithDialer(rec.dial))
	if err != nil {
		t.Fatalf("DialPool: %v", err)
	}
	instrument(c, testPolicy())
	holdAllBut(t, c, c.pool.entries[0]) // the primary is the conn the server drops

	done := make(chan error, 1)
	go func() {
		_, err := send(c, "x")
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("redial never started")
	}

	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close blocked on an in-flight redial")
	}
	close(gate)

	select {
	case err := <-done:
		assertClosedErr(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Send did not return after Close")
	}
	conns := rec.all()
	if len(conns) != 3 {
		t.Fatalf("dials = %d, want 3", len(conns))
	}
	for i, cc := range conns {
		if n := cc.closes.Load(); n != 1 {
			t.Errorf("conn %d closed %d times, want exactly 1", i, n)
		}
	}
}

// TestCloseWakesReconnectBackoff: a request stuck in reconnect backoff
// against a dead registry returns promptly with ErrClosed when the client is
// closed, on both the pooled and the single-conn path (where the backoff
// runs with c.mu held and would otherwise block Close).
func TestCloseWakesReconnectBackoff(t *testing.T) {
	t.Parallel()
	for _, size := range []int{1, 2} {
		t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
			t.Parallel()
			srv := newScriptedRegistry(t, closeAfter(0))
			c, err := DialPool(srv.addr(), size)
			if err != nil {
				t.Fatalf("DialPool: %v", err)
			}
			p := testPolicy()
			p.dialBase, p.dialMax = time.Minute, time.Minute
			instrument(c, p)
			srv.waitConns(t, size)
			srv.shutdown() // every request now fails and every redial is refused

			done := make(chan error, 1)
			go func() {
				_, err := send(c, "x")
				done <- err
			}()
			// Let the request fail, dial once and park in the backoff.
			time.Sleep(100 * time.Millisecond)
			start := time.Now()
			closed := make(chan error, 1)
			go func() { closed <- c.Close() }()
			select {
			case err := <-done:
				assertClosedErr(t, err)
			case <-time.After(5 * time.Second):
				t.Fatal("Send stayed in reconnect backoff after Close")
			}
			select {
			case <-closed:
			case <-time.After(5 * time.Second):
				t.Fatal("Close blocked behind the reconnect backoff")
			}
			if d := time.Since(start); d > 5*time.Second {
				t.Fatalf("Close/Send took %v", d)
			}
		})
	}
}

// TestSendWaitingForFreeEntryHonoursContext: a pooled Send blocked because
// every entry is busy returns when its context is done.
func TestSendWaitingForFreeEntryHonoursContext(t *testing.T) {
	t.Parallel()
	srv := newScriptedRegistry(t, neverDrop)
	c, err := DialPool(srv.addr(), 2)
	if err != nil {
		t.Fatalf("DialPool: %v", err)
	}
	defer c.Close()
	holdIdleEntries(t, c, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.SendContext(ctx, map[string]interface{}{"type": "x"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
}

func TestBinaryClientCloseIdempotentAndErrClosed(t *testing.T) {
	t.Parallel()
	srv := newFakeBinaryServer(t, func(byte, []byte) (byte, []byte) {
		return wire.MsgHeartbeatOK, wire.EncodeHeartbeatResp(1, false)
	})
	c, err := DialBinary(srv.addr())
	if err != nil {
		t.Fatalf("DialBinary: %v", err)
	}
	if _, _, err := c.Heartbeat(1, nil); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = c.Close() }()
	}
	wg.Wait()
	if err := c.Close(); err != nil {
		t.Fatalf("second Close = %v, want nil", err)
	}
	_, _, err = c.Heartbeat(1, nil)
	assertClosedErr(t, err)
	_, err = c.Lookup(1)
	assertClosedErr(t, err)
	_, err = c.Resolve(1, 2, nil)
	assertClosedErr(t, err)
	_, err = c.SendJSON(map[string]interface{}{"type": "x"})
	assertClosedErr(t, err)
	var nilClient *BinaryClient
	if err := nilClient.Close(); err != nil {
		t.Fatalf("nil BinaryClient Close = %v", err)
	}
}

// TestBinaryClientCloseWakesReconnectBackoff: BinaryClient.reconnect sleeps
// with c.mu held; Close must wake it instead of waiting out the backoff.
func TestBinaryClientCloseWakesReconnectBackoff(t *testing.T) {
	t.Parallel()
	srv := newFakeBinaryServer(t, func(byte, []byte) (byte, []byte) {
		return wire.MsgHeartbeatOK, wire.EncodeHeartbeatResp(1, false)
	})
	c, err := DialBinary(srv.addr())
	if err != nil {
		t.Fatalf("DialBinary: %v", err)
	}
	srv.Close()
	c.mu.Lock()
	_ = c.conn.Close()
	c.mu.Unlock()

	done := make(chan error, 1)
	go func() {
		_, _, err := c.Heartbeat(1, nil)
		done <- err
	}()
	time.Sleep(100 * time.Millisecond) // first redial refused; now in backoff
	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()
	select {
	case err := <-done:
		assertClosedErr(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("Heartbeat stayed in reconnect backoff after Close")
	}
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("Close blocked behind the reconnect backoff")
	}
}

// --- Reconnect: triggering error, logging, retry on another entry -------------

// TestPoolReconnectLogsCauseAtDebugWithInfoSummary: a server that closes
// every connection after one request makes each request redial. Each
// reconnect is logged at Debug with the error that triggered it; nothing is
// logged per reconnect at INFO; one INFO summary (flushed by Close) carries
// the counts and the last cause.
func TestPoolReconnectLogsCauseAtDebugWithInfoSummary(t *testing.T) {
	t.Parallel()
	srv := newScriptedRegistry(t, closeAfter(1))
	c, err := DialPool(srv.addr(), 2)
	if err != nil {
		t.Fatalf("DialPool: %v", err)
	}
	logs := instrument(c, testPolicy())
	release := holdIdleEntries(t, c, 1)

	const sends = 6
	for i := 0; i < sends; i++ {
		mustOK(t, c, "x")
	}
	release()

	if got := logs.count(slog.LevelInfo); got != 0 {
		t.Fatalf("%d INFO records before the summary interval, want 0: %+v", got, logs.find(slog.LevelInfo, "registry reconnect summary"))
	}
	reconnected := logs.find(slog.LevelDebug, "registry pool conn reconnected")
	if len(reconnected) != sends-1 {
		t.Fatalf("Debug reconnect records = %d, want %d", len(reconnected), sends-1)
	}
	for _, r := range reconnected {
		if cause, _ := r.attrs["cause"].(string); !strings.Contains(cause, "EOF") {
			t.Fatalf("reconnect record cause = %q, want the triggering EOF", cause)
		}
	}
	dropped := logs.find(slog.LevelDebug, "registry conn dropped")
	if len(dropped) != sends-1 {
		t.Fatalf("Debug drop records = %d, want %d", len(dropped), sends-1)
	}

	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	summaries := logs.find(slog.LevelInfo, "registry reconnect summary")
	if len(summaries) != 1 {
		t.Fatalf("INFO summaries = %d, want 1 (flushed by Close)", len(summaries))
	}
	s := summaries[0].attrs
	if s["reconnects"] != int64(sends-1) || s["rapid_closes"] != int64(sends-1) {
		t.Fatalf("summary counts = %v", s)
	}
	if s["rate_limit_suspected"] != true {
		t.Fatalf("summary rate_limit_suspected = %v, want true", s["rate_limit_suspected"])
	}
	if cause, _ := s["last_cause"].(string); !strings.Contains(cause, "EOF") {
		t.Fatalf("summary last_cause = %q", cause)
	}
}

// TestReconnectSummaryIsPeriodic: with a short summary interval, INFO
// summaries appear at most once per interval, however many reconnects
// happen.
func TestReconnectSummaryIsPeriodic(t *testing.T) {
	t.Parallel()
	srv := newScriptedRegistry(t, closeAfter(1))
	c, err := DialPool(srv.addr(), 2)
	if err != nil {
		t.Fatalf("DialPool: %v", err)
	}
	defer c.Close()
	p := testPolicy()
	p.summaryEvery = 150 * time.Millisecond
	p.cooldownBase = 0 // keep the loop fast; backoff is tested separately
	logs := instrument(c, p)
	holdIdleEntries(t, c, 1)

	start := time.Now()
	sends := 0
	for time.Since(start) < 500*time.Millisecond {
		mustOK(t, c, "x")
		sends++
	}
	elapsed := time.Since(start)
	summaries := logs.find(slog.LevelInfo, "registry reconnect summary")
	maxWant := int(elapsed/p.summaryEvery) + 1
	if len(summaries) == 0 || len(summaries) > maxWant {
		t.Fatalf("%d summaries for %d reconnects in %v, want 1..%d", len(summaries), sends-1, elapsed, maxWant)
	}
	if got := len(logs.find(slog.LevelInfo, "registry pool conn reconnected")); got != 0 {
		t.Fatalf("%d per-reconnect INFO lines, want 0", got)
	}
	total := 0
	for _, s := range summaries {
		total += int(s.attrs["reconnects"].(int64))
	}
	if total > sends-1 || total == 0 {
		t.Fatalf("summaries report %d reconnects, %d happened", total, sends-1)
	}
}

// TestSinglePathReconnectLogsCauseAtDebug covers the non-pooled client.
func TestSinglePathReconnectLogsCauseAtDebug(t *testing.T) {
	t.Parallel()
	srv := newScriptedRegistry(t, closeAfter(1))
	c, err := Dial(srv.addr())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()
	logs := instrument(c, testPolicy())
	mustOK(t, c, "a")
	mustOK(t, c, "b")
	recs := logs.find(slog.LevelDebug, "registry reconnected")
	if len(recs) != 1 {
		t.Fatalf("Debug reconnect records = %d, want 1", len(recs))
	}
	if cause, _ := recs[0].attrs["cause"].(string); !strings.Contains(cause, "EOF") {
		t.Fatalf("cause = %q, want EOF", cause)
	}
	if got := logs.count(slog.LevelInfo); got != 0 {
		t.Fatalf("%d INFO records, want 0", got)
	}
}

// TestReconnectFailureKeepsTriggeringAndReconnectErrors: when the redial
// fails too, the returned error carries both the error that triggered the
// reconnect and the reconnect's own error.
func TestReconnectFailureKeepsTriggeringAndReconnectErrors(t *testing.T) {
	t.Parallel()
	for _, size := range []int{1, 2} {
		t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
			t.Parallel()
			srv := newScriptedRegistry(t, closeAfter(0))
			c, err := DialPool(srv.addr(), size)
			if err != nil {
				t.Fatalf("DialPool: %v", err)
			}
			defer c.Close()
			logs := instrument(c, testPolicy())
			if size > 1 {
				holdIdleEntries(t, c, size-1)
			}
			srv.waitConns(t, size)
			srv.ln.Close() // the drop still happens; the redial is refused

			_, err = send(c, "x")
			if err == nil {
				t.Fatal("expected an error")
			}
			if !errors.Is(err, io.EOF) {
				t.Fatalf("err = %v, want the triggering io.EOF in the chain", err)
			}
			if !errors.Is(err, syscall.ECONNREFUSED) {
				t.Fatalf("err = %v, want the reconnect's ECONNREFUSED in the chain", err)
			}
			for _, want := range []string{"send failed and reconnect failed", "recv: EOF", "reconnect failed after 5 attempts"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("err = %q, want it to contain %q", err, want)
				}
			}
			warns := 0
			for _, lvl := range []slog.Level{slog.LevelWarn} {
				for _, msg := range []string{"registry reconnect failed", "registry pool conn reconnect failed"} {
					for _, r := range logs.find(lvl, msg) {
						warns++
						if cause, _ := r.attrs["cause"].(string); !strings.Contains(cause, "EOF") {
							t.Fatalf("reconnect-failed WARN cause = %q, want EOF", cause)
						}
					}
				}
			}
			if warns != maxReconnectAttempts {
				t.Fatalf("reconnect-failed WARN records = %d, want %d", warns, maxReconnectAttempts)
			}
		})
	}
}

// TestRetryAfterReconnectFailureKeepsTriggeringError: the redial succeeds
// but the retry is dropped too; the error names both failures.
func TestRetryAfterReconnectFailureKeepsTriggeringError(t *testing.T) {
	t.Parallel()
	srv := newScriptedRegistry(t, closeAfter(0))
	c, err := DialPool(srv.addr(), 2)
	if err != nil {
		t.Fatalf("DialPool: %v", err)
	}
	defer c.Close()
	instrument(c, testPolicy())
	holdIdleEntries(t, c, 1)
	_, err = send(c, "x")
	if err == nil || !strings.Contains(err.Error(), "retried after reconnect; first failure: recv: EOF") {
		t.Fatalf("err = %v, want the retry error annotated with the first failure", err)
	}
	if !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v, want io.EOF in the chain", err)
	}
}

// TestPoolRetriesOnOtherHealthyEntryBeforeRedial: after a closed-connection
// error on one entry, the request is retried on another idle healthy entry
// with no redial. The dropped entry is skipped while healthy entries are
// free and redialed lazily when it is next needed.
func TestPoolRetriesOnOtherHealthyEntryBeforeRedial(t *testing.T) {
	t.Parallel()
	srv := newScriptedRegistry(t, func(connSeq, reqSeq int, _ time.Duration) bool {
		return connSeq == 1 && reqSeq == 1
	})
	rec := &connRecorder{}
	c, err := DialPool(srv.addr(), 2, WithDialer(rec.dial))
	if err != nil {
		t.Fatalf("DialPool: %v", err)
	}
	defer c.Close()
	logs := instrument(c, testPolicy())

	// Make sure the first request lands on the primary (the conn the
	// server drops): drain the free list and put the primary back first.
	<-c.pool.free
	<-c.pool.free
	c.releaseEntry(c.pool.entries[0])
	c.releaseEntry(c.pool.entries[1])

	mustOK(t, c, "dropped-then-served-by-other")
	if got := len(rec.all()); got != 2 {
		t.Fatalf("dials = %d, want 2 (served by the other entry, no redial)", got)
	}
	if got := srv.dropped.Load(); got != 1 {
		t.Fatalf("server drops = %d, want 1", got)
	}
	if n := rec.all()[0].closes.Load(); n != 1 {
		t.Fatalf("dropped conn closed %d times, want 1 (retired right away)", n)
	}

	// The healthy entry is preferred: still no redial.
	mustOK(t, c, "healthy-preferred")
	if got := len(rec.all()); got != 2 {
		t.Fatalf("dials = %d after a second request, want 2", got)
	}

	// With the healthy entry busy, the broken one is redialed lazily.
	release := holdAllBut(t, c, c.pool.entries[0])
	mustOK(t, c, "lazy-redial")
	release()
	if got := len(rec.all()); got != 3 {
		t.Fatalf("dials = %d, want 3 after the broken entry was needed", got)
	}
	if !c.pool.entries[0].healthy() || !c.pool.entries[1].healthy() {
		t.Fatal("both entries should be healthy again")
	}
	c.mu.Lock()
	primarySynced := c.conn == c.pool.entries[0].conn
	c.mu.Unlock()
	if !primarySynced {
		t.Fatal("c.conn out of sync with the redialed primary entry")
	}

	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	s := logs.find(slog.LevelInfo, "registry reconnect summary")
	if len(s) != 1 || s[0].attrs["served_by_other_conn"] != int64(1) {
		t.Fatalf("summary = %+v, want served_by_other_conn=1", s)
	}
}

// TestPoolFallsBackToRedialWhenOtherEntryAlsoDropped: the other entry is
// dead too, so after one retry on it the client redials and succeeds.
func TestPoolFallsBackToRedialWhenOtherEntryAlsoDropped(t *testing.T) {
	t.Parallel()
	srv := newScriptedRegistry(t, func(connSeq, reqSeq int, _ time.Duration) bool {
		return connSeq <= 2 && reqSeq == 1 // both initial conns die on first use
	})
	c, err := DialPool(srv.addr(), 2)
	if err != nil {
		t.Fatalf("DialPool: %v", err)
	}
	defer c.Close()
	instrument(c, testPolicy())
	mustOK(t, c, "x")
	if got := srv.dropped.Load(); got != 2 {
		t.Fatalf("server drops = %d, want 2 (first entry, then the other)", got)
	}
	if got := srv.conns.Load(); got != 3 {
		t.Fatalf("server conns = %d, want 3 (one redial)", got)
	}
}

// TestPoolDoesNotRetryTimeoutOnOtherEntry: a timeout is not a
// closed-connection error, so it goes straight to the redial.
func TestPoolDoesNotRetryTimeoutOnOtherEntry(t *testing.T) {
	t.Parallel()
	if isConnDropped(fmt.Errorf("recv: %w", os.ErrDeadlineExceeded)) {
		t.Fatal("a read timeout must not count as a dropped connection")
	}
}

// primaryFirst reorders a two-entry pool's free list so the next request
// lands on the primary entry (connSeq 1 on the server).
func primaryFirst(t *testing.T, c *Client) {
	t.Helper()
	if len(c.pool.entries) != 2 {
		t.Fatalf("pool size %d, want 2", len(c.pool.entries))
	}
	<-c.pool.free
	<-c.pool.free
	c.releaseEntry(c.pool.entries[0])
	c.releaseEntry(c.pool.entries[1])
}

// hangsOn returns a hang hook for every request on connection connSeq.
func hangsOn(connSeq int) func(int, int) bool {
	return func(cs, _ int) bool { return cs == connSeq }
}

// TestPoolOtherEntryRetryIsBoundedWhenOtherConnHangs: the request's conn
// is dropped (a limiter denial) and the other idle conn is silently hung.
// The retry on the other conn gives up after otherConnTimeout instead of
// the 30 s read deadline, retires that conn (a late reply could still
// arrive on it), and the request is served on the redialed conn.
func TestPoolOtherEntryRetryIsBoundedWhenOtherConnHangs(t *testing.T) {
	t.Parallel()
	srv := newScriptedRegistry(t, func(connSeq, reqSeq int, _ time.Duration) bool {
		return connSeq == 1 && reqSeq == 1
	})
	srv.setHang(hangsOn(2))
	rec := &connRecorder{}
	c, err := DialPool(srv.addr(), 2, WithDialer(rec.dial))
	if err != nil {
		t.Fatalf("DialPool: %v", err)
	}
	defer c.Close()
	p := testPolicy()
	p.otherConnTimeout = 150 * time.Millisecond
	logs := instrument(c, p)
	primaryFirst(t, c)

	start := time.Now()
	mustOK(t, c, "x")
	elapsed := time.Since(start)
	if elapsed < p.otherConnTimeout {
		t.Fatalf("Send took %v, want >= otherConnTimeout %v (the other conn was not tried)", elapsed, p.otherConnTimeout)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("Send took %v: the retry on the hung conn was not bounded by otherConnTimeout", elapsed)
	}
	if got := srv.received.Load(); got != 3 {
		t.Fatalf("server received the request %d times, want 3 (dropped, hung, redialed)", got)
	}
	if got := srv.hung.Load(); got != 1 {
		t.Fatalf("hung requests = %d, want 1", got)
	}
	if c.pool.entries[1].healthy() {
		t.Fatal("the hung entry is still marked healthy; a late reply could reach the next request")
	}
	conns := rec.all()
	if len(conns) != 3 {
		t.Fatalf("dials = %d, want 3 (one redial)", len(conns))
	}
	if n := conns[1].closes.Load(); n != 1 {
		t.Fatalf("hung conn closed %d times, want 1 (retired)", n)
	}
	timedOut := false
	for _, r := range logs.find(slog.LevelDebug, "registry conn dropped") {
		if e, ok := r.attrs["err"].(error); ok && errors.Is(e, os.ErrDeadlineExceeded) {
			timedOut = true
		}
	}
	if !timedOut {
		t.Fatal("no Debug record for the other conn's timeout")
	}

	// The redialed primary is healthy and preferred: no further dial.
	mustOK(t, c, "after")
	if got := len(rec.all()); got != 3 {
		t.Fatalf("dials = %d after a second request, want 3", got)
	}
}

// TestPoolOtherEntryRetryHonoursContext: with a long otherConnTimeout, the
// caller's ctx (its deadline or its cancellation) ends the retry on a hung
// other conn, and no redial is attempted once ctx is done. The error keeps
// the triggering drop and matches the ctx error.
func TestPoolOtherEntryRetryHonoursContext(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		ctx  func() (context.Context, context.CancelFunc)
		want error
	}{
		{"deadline", func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), 150*time.Millisecond)
		}, context.DeadlineExceeded},
		{"cancel", func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			time.AfterFunc(150*time.Millisecond, cancel)
			return ctx, cancel
		}, context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := newScriptedRegistry(t, func(connSeq, reqSeq int, _ time.Duration) bool {
				return connSeq == 1 && reqSeq == 1
			})
			srv.setHang(hangsOn(2))
			rec := &connRecorder{}
			c, err := DialPool(srv.addr(), 2, WithDialer(rec.dial))
			if err != nil {
				t.Fatalf("DialPool: %v", err)
			}
			defer c.Close()
			p := testPolicy()
			p.otherConnTimeout = time.Minute // only ctx can end the retry
			logs := instrument(c, p)
			primaryFirst(t, c)

			ctx, cancel := tc.ctx()
			defer cancel()
			start := time.Now()
			_, err = c.SendContext(ctx, map[string]interface{}{"type": "x"})
			elapsed := time.Since(start)
			if err == nil {
				t.Fatal("expected an error once ctx ended")
			}
			if elapsed > 5*time.Second {
				t.Fatalf("SendContext took %v: ctx did not end the retry on the hung conn", elapsed)
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want errors.Is(err, %v)", err, tc.want)
			}
			if !errors.Is(err, io.EOF) {
				t.Fatalf("err = %v, want the triggering io.EOF in the chain", err)
			}
			if got := len(rec.all()); got != 2 {
				t.Fatalf("dials = %d, want 2 (no redial after ctx ended)", got)
			}
			if c.pool.entries[1].healthy() {
				t.Fatal("the abandoned entry is still marked healthy")
			}
			if w := logs.find(slog.LevelWarn, "registry pool conn reconnect failed"); len(w) != 0 {
				t.Fatalf("%d reconnect-failed WARNs for a caller that gave up, want 0", len(w))
			}
			c.reconn.mu.Lock()
			fs := c.reconn.failStreak
			c.reconn.mu.Unlock()
			if fs != 0 {
				t.Fatalf("failStreak = %d, want 0: ctx ending is not a registry failure", fs)
			}
		})
	}
}

// TestPoolRequestSentAtMostThreeTimesAndExtendsStreakOnce: every conn a
// request is tried on drops it. The request reaches the registry at most
// three times (its conn, another idle conn, its redialed conn), and the
// rapid-close streak grows by one for the whole request, so one shed
// request does not double the next cooldown. Every close still shows in
// the summary.
func TestPoolRequestSentAtMostThreeTimesAndExtendsStreakOnce(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		dropping int // conns (by accept order) that drop their first request
		wantOK   bool
	}{
		{"served-after-redial", 2, true},
		{"every-attempt-dropped", 3, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := newScriptedRegistry(t, func(connSeq, reqSeq int, _ time.Duration) bool {
				return connSeq <= tc.dropping && reqSeq == 1
			})
			c, err := DialPool(srv.addr(), 2)
			if err != nil {
				t.Fatalf("DialPool: %v", err)
			}
			logs := instrument(c, testPolicy())
			_, err = send(c, "register")
			if tc.wantOK && err != nil {
				t.Fatalf("send: %v", err)
			}
			if !tc.wantOK && (err == nil || !strings.Contains(err.Error(), "retried after reconnect")) {
				t.Fatalf("err = %v, want the redialed retry's failure", err)
			}
			if got := srv.received.Load(); got != 3 {
				t.Fatalf("server received the request %d times, want 3", got)
			}
			c.reconn.mu.Lock()
			streak := c.reconn.rapidStreak
			c.reconn.mu.Unlock()
			if streak != 1 {
				t.Fatalf("rapid-close streak = %d after one request, want 1", streak)
			}
			if err := c.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			s := logs.find(slog.LevelInfo, "registry reconnect summary")
			if len(s) != 1 || s[0].attrs["rapid_closes"] != int64(tc.dropping) {
				t.Fatalf("summary = %+v, want rapid_closes=%d", s, tc.dropping)
			}
		})
	}
}

// TestSinglePathRequestSentAtMostTwice: the single-conn client redials
// and retries once, so a request reaches the registry at most twice.
func TestSinglePathRequestSentAtMostTwice(t *testing.T) {
	t.Parallel()
	srv := newScriptedRegistry(t, closeAfter(0))
	c, err := Dial(srv.addr())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()
	instrument(c, testPolicy())
	if _, err := send(c, "register"); err == nil {
		t.Fatal("expected an error: every conn drops")
	}
	if got := srv.received.Load(); got != 2 {
		t.Fatalf("server received the request %d times, want 2", got)
	}
}

// TestBoundedRoundTripLeavesNoDeadline: a ctx cancelled at varying points
// around a bounded exchange either fails it with the cancellation or
// leaves no deadline on the conn that answered, so its next plain round
// trip works. (Both outcomes occur across the iterations.)
func TestBoundedRoundTripLeavesNoDeadline(t *testing.T) {
	t.Parallel()
	srv := newScriptedRegistry(t, neverDrop)
	dial := func() net.Conn {
		conn, err := net.Dial("tcp", srv.addr())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() { conn.Close() })
		return conn
	}
	conn := dial()
	msg := map[string]interface{}{"type": "x"}
	answered := 0
	for i := 0; i < 200; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		go func(d time.Duration) {
			time.Sleep(d)
			cancel()
		}(time.Duration(i%50) * 10 * time.Microsecond)
		_, err := boundedRoundTrip(ctx, conn, msg, time.Second)
		cancel()
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("iteration %d: err = %v, want a cancellation", i, err)
			}
			conn = dial() // interrupted mid-exchange: retire it
			continue
		}
		answered++
		time.Sleep(50 * time.Microsecond) // let a late cancellation run
		if _, err := roundTrip(conn, msg); err != nil {
			t.Fatalf("iteration %d: plain round trip after a bounded one: %v", i, err)
		}
	}
	if answered == 0 {
		t.Fatal("no bounded exchange completed; the test did not exercise the race")
	}
}

// TestDefaultOtherConnTimeoutFitsDaemonDeadline: the other-conn retry
// plus the longest cooldown leaves most of the daemon's 8 s registry call
// deadline for the redial and the final attempt.
func TestDefaultOtherConnTimeoutFitsDaemonDeadline(t *testing.T) {
	t.Parallel()
	p := defaultReconnectPolicy
	if p.otherConnTimeout <= 0 {
		t.Fatalf("otherConnTimeout = %v, want > 0", p.otherConnTimeout)
	}
	if budget := p.otherConnTimeout + p.cooldownMax; budget > 4*time.Second {
		t.Fatalf("otherConnTimeout + cooldownMax = %v, want <= 4s (half the daemon's 8s deadline)", budget)
	}
}

// --- Backoff -------------------------------------------------------------------

// TestRapidClosesBackOffExponentiallyWithJitter: a server that closes every
// connection after one request (the rate-limit signature: EOF, no error
// frame, on a young connection) makes the client wait a growing, jittered
// cooldown before each redial. Timing is checked against lower bounds only,
// which a slow machine cannot break.
func TestRapidClosesBackOffExponentiallyWithJitter(t *testing.T) {
	t.Parallel()
	srv := newScriptedRegistry(t, closeAfter(1))
	c, err := DialPool(srv.addr(), 2)
	if err != nil {
		t.Fatalf("DialPool: %v", err)
	}
	defer c.Close()
	p := testPolicy()
	p.cooldownBase, p.cooldownMax = 20*time.Millisecond, 160*time.Millisecond
	instrument(c, p)
	holdIdleEntries(t, c, 1)

	mustOK(t, c, "first") // uses up the primary's one request
	start := time.Now()
	const redials = 5
	for i := 0; i < redials; i++ {
		mustOK(t, c, "x")
	}
	elapsed := time.Since(start)

	// Streak n waits jitter(min(base<<(n-1), max)) >= half of that.
	var minWait time.Duration
	for n := 1; n <= redials; n++ {
		d := p.cooldownBase << (n - 1)
		if d > p.cooldownMax {
			d = p.cooldownMax
		}
		minWait += d / 2
	}
	if elapsed < minWait {
		t.Fatalf("%d rapid-close redials took %v, want >= %v of backoff", redials, elapsed, minWait)
	}
	c.reconn.mu.Lock()
	streak := c.reconn.rapidStreak
	c.reconn.mu.Unlock()
	if streak != redials {
		t.Fatalf("rapid-close streak = %d, want %d", streak, redials)
	}
}

// TestGracePeriodClosesAreDetectedAndStreakResets mirrors production: the
// registry closes the first request on a connection older than its grace
// period. Requests keep succeeding (retry), the closes are classified as
// rapid, and once the server stops shedding and a connection outlives the
// rapid-close window, the streak resets.
func TestGracePeriodClosesAreDetectedAndStreakResets(t *testing.T) {
	t.Parallel()
	srv := newScriptedRegistry(t, afterGrace(60*time.Millisecond))
	c, err := DialPool(srv.addr(), 2)
	if err != nil {
		t.Fatalf("DialPool: %v", err)
	}
	defer c.Close()
	p := testPolicy()
	p.rapidWindow = 250 * time.Millisecond
	logs := instrument(c, p)

	deadline := time.Now().Add(400 * time.Millisecond)
	for time.Now().Before(deadline) {
		mustOK(t, c, "x")
		time.Sleep(20 * time.Millisecond)
	}
	if srv.dropped.Load() == 0 {
		t.Fatal("server never shed a request; test did not exercise the grace path")
	}
	rapid := 0
	for _, r := range logs.find(slog.LevelDebug, "registry conn dropped") {
		if r.attrs["rapid_close"] == true {
			rapid++
		}
	}
	if rapid == 0 {
		t.Fatal("no drop was classified as a rapid close")
	}

	// Stop shedding; a request on a connection older than the rapid-close
	// window proves the registry is healthy again.
	srv.setDrop(neverDrop)
	time.Sleep(p.rapidWindow + 50*time.Millisecond)
	mustOK(t, c, "healthy")
	mustOK(t, c, "healthy")
	c.reconn.mu.Lock()
	streak := c.reconn.rapidStreak
	c.reconn.mu.Unlock()
	if streak != 0 {
		t.Fatalf("rapid-close streak = %d after a healthy old connection, want 0", streak)
	}
	if d := c.reconn.cooldown(); d != 0 {
		t.Fatalf("cooldown = %v after reset, want 0", d)
	}
}

// TestIdleCloseDoesNotBackOff: a connection closed by the peer after it
// outlived the rapid-close window (an idle timeout, a NAT drop) is redialed
// with no cooldown.
func TestIdleCloseDoesNotBackOff(t *testing.T) {
	t.Parallel()
	var tr reconnectTracker
	p := testPolicy()
	tr.policy = p
	if tr.connError(fmt.Errorf("recv: %w", io.EOF), time.Minute, true, nil) {
		t.Fatal("EOF on a minute-old conn classified as rapid")
	}
	if d := tr.cooldown(); d != 0 {
		t.Fatalf("cooldown after an idle close = %v, want 0", d)
	}
	if tr.connError(fmt.Errorf("recv: %w", os.ErrDeadlineExceeded), time.Second, true, nil) {
		t.Fatal("a timeout classified as a rapid close")
	}
	if tr.connError(fmt.Errorf("send: %w", net.ErrClosed), time.Second, true, nil) {
		t.Fatal("a locally closed conn classified as a rapid close")
	}
}

// TestRepeatedReconnectFailuresBackOff: each reconnect that exhausts its
// dial attempts grows the cooldown before the next one; a successful redial
// ends that streak.
func TestRepeatedReconnectFailuresBackOff(t *testing.T) {
	t.Parallel()
	srv := newScriptedRegistry(t, closeAfter(0))
	rec := &connRecorder{}
	c, err := DialPool(srv.addr(), 2, WithDialer(rec.dial))
	if err != nil {
		t.Fatalf("DialPool: %v", err)
	}
	defer c.Close()
	p := testPolicy()
	p.rapidWindow = time.Nanosecond // isolate the failure streak
	instrument(c, p)
	holdIdleEntries(t, c, 1)
	realAddr := srv.addr()
	srv.waitConns(t, 2)
	srv.ln.Close()

	for i := 1; i <= 3; i++ {
		if _, err := send(c, "x"); err == nil {
			t.Fatal("expected a failure while the registry is down")
		}
		c.reconn.mu.Lock()
		fs := c.reconn.failStreak
		c.reconn.mu.Unlock()
		if fs != i {
			t.Fatalf("after %d failed reconnects failStreak = %d", i, fs)
		}
	}
	for i := 0; i < 20; i++ {
		if d := c.reconn.cooldown(); d < p.cooldownBase<<2/2 || d > p.cooldownBase<<2 {
			t.Fatalf("cooldown at failStreak 3 = %v, want in [%v, %v]", d, p.cooldownBase<<2/2, p.cooldownBase<<2)
		}
	}

	// Bring a registry back on the same address and redial successfully.
	ln, err := net.Listen("tcp", realAddr)
	if err != nil {
		t.Skipf("could not rebind %s: %v", realAddr, err)
	}
	srv2 := &scriptedRegistry{ln: ln, drop: neverDrop}
	srv2.wg.Add(1)
	go srv2.accept()
	t.Cleanup(srv2.stop)
	mustOK(t, c, "back")
	c.reconn.mu.Lock()
	fs := c.reconn.failStreak
	c.reconn.mu.Unlock()
	if fs != 0 {
		t.Fatalf("failStreak = %d after a successful redial, want 0", fs)
	}
}

// --- Unit: tracker and classification -----------------------------------------

func TestCooldownGrowsExponentiallyWithJitterAndCaps(t *testing.T) {
	t.Parallel()
	var tr reconnectTracker
	p := testPolicy()
	p.cooldownBase, p.cooldownMax = 100*time.Millisecond, 800*time.Millisecond
	tr.policy = p
	if d := tr.cooldown(); d != 0 {
		t.Fatalf("initial cooldown = %v, want 0", d)
	}
	for n := 1; n <= 8; n++ {
		tr.connError(io.EOF, time.Second, true, nil) // rapid close
		want := p.cooldownBase << (n - 1)
		if want > p.cooldownMax {
			want = p.cooldownMax
		}
		seen := map[time.Duration]bool{}
		for i := 0; i < 50; i++ {
			d := tr.cooldown()
			if d < want/2 || d > want {
				t.Fatalf("streak %d: cooldown %v outside [%v, %v]", n, d, want/2, want)
			}
			seen[d] = true
		}
		if len(seen) < 2 {
			t.Fatalf("streak %d: cooldown not jittered (always %v)", n, want)
		}
	}
	tr.healthy(p.rapidWindow) // an answer on an old conn ends the streak
	if d := tr.cooldown(); d != 0 {
		t.Fatalf("cooldown after healthy = %v, want 0", d)
	}
}

func TestStreaksResetAfterQuietPeriod(t *testing.T) {
	t.Parallel()
	var tr reconnectTracker
	p := testPolicy()
	p.quietReset = 30 * time.Millisecond
	tr.policy = p
	tr.connError(io.EOF, time.Second, true, nil)
	tr.exhausted()
	if tr.cooldown() == 0 {
		t.Fatal("expected a cooldown right after the events")
	}
	time.Sleep(50 * time.Millisecond)
	if d := tr.cooldown(); d != 0 {
		t.Fatalf("cooldown after the quiet period = %v, want 0", d)
	}
}

// TestSummaryTimer: the first event of a window arms a timer that emits
// one summary summaryEvery later, even if nothing else happens; events
// inside a pending window do not emit; stop flushes and disarms.
func TestSummaryTimer(t *testing.T) {
	t.Parallel()
	var tr reconnectTracker
	p := testPolicy()
	p.summaryEvery = 60 * time.Millisecond
	tr.policy = p
	got := make(chan []any, 8)
	emit := func(s []any) { got <- s }
	asMap := func(s []any) map[string]any {
		m := map[string]any{}
		for i := 0; i+1 < len(s); i += 2 {
			m[s[i].(string)] = s[i+1]
		}
		return m
	}

	if s := tr.stop(); s != nil {
		t.Fatalf("stop with no events = %v, want nil", s)
	}
	tr = reconnectTracker{policy: p}

	start := time.Now()
	tr.reconnected(io.EOF, emit)
	tr.reconnected(io.EOF, emit)
	tr.servedByOther(emit)
	var first []any
	select {
	case first = <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("no summary after the interval")
	}
	if waited := time.Since(start); waited < p.summaryEvery {
		t.Fatalf("summary after %v, want >= %v", waited, p.summaryEvery)
	}
	m := asMap(first)
	if m["reconnects"] != 2 || m["served_by_other_conn"] != 1 || m["last_cause"] != "EOF" {
		t.Fatalf("summary attrs = %v", m)
	}
	select {
	case s := <-got:
		t.Fatalf("second summary with no new events: %v", s)
	case <-time.After(3 * p.summaryEvery):
	}

	// A new event opens a new window; stop flushes it before the timer.
	tr.dialFailed(emit)
	s := tr.stop()
	if m := asMap(s); m["failed_dials"] != 1 {
		t.Fatalf("stop summary = %v", s)
	}
	tr.reconnected(io.EOF, emit) // after stop: counted, never emitted
	select {
	case s := <-got:
		t.Fatalf("summary emitted after stop: %v", s)
	case <-time.After(3 * p.summaryEvery):
	}
}

func TestConnErrorClassification(t *testing.T) {
	t.Parallel()
	opErr := func(errno syscall.Errno) error {
		return fmt.Errorf("recv: %w", &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", errno)})
	}
	cases := []struct {
		name          string
		err           error
		peer, dropped bool
	}{
		{"eof", fmt.Errorf("recv: %w", io.EOF), true, true},
		{"unexpected eof", fmt.Errorf("recv: %w", io.ErrUnexpectedEOF), true, true},
		{"reset", opErr(syscall.ECONNRESET), true, true},
		{"broken pipe", opErr(syscall.EPIPE), true, true},
		{"local close", fmt.Errorf("send: %w", net.ErrClosed), false, true},
		{"not connected", errNotConnected, false, true},
		{"timeout", fmt.Errorf("recv: %w", os.ErrDeadlineExceeded), false, false},
		{"decode", errors.New("recv: json decode: bad"), false, false},
	}
	for _, tc := range cases {
		if got := isPeerClose(tc.err); got != tc.peer {
			t.Errorf("%s: isPeerClose = %v, want %v", tc.name, got, tc.peer)
		}
		if got := isConnDropped(tc.err); got != tc.dropped {
			t.Errorf("%s: isConnDropped = %v, want %v", tc.name, got, tc.dropped)
		}
	}
}

func TestJitterBounds(t *testing.T) {
	t.Parallel()
	for _, d := range []time.Duration{0, 1, 2, 3, time.Millisecond, time.Second} {
		for i := 0; i < 100; i++ {
			j := jitter(d)
			if j < d/2 || j > d {
				t.Fatalf("jitter(%v) = %v outside [%v, %v]", d, j, d/2, d)
			}
		}
	}
}
