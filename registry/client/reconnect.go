// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"sync"
	"syscall"
	"time"
)

// ErrClosed is returned by every request method of a closed *Client or
// *BinaryClient, including requests that were still in flight when Close
// ran. errors.Is(ErrClosed, ErrNoRegistry) is true, so callers that already
// treat "no registry" as recoverable handle a closed client (for example one
// retired by a forced reconnect) the same way.
var ErrClosed error = closedError{}

type closedError struct{}

func (closedError) Error() string { return "registry client closed" }

// Is makes errors.Is(ErrClosed, ErrNoRegistry) true.
func (closedError) Is(target error) bool { return target == ErrNoRegistry }

// errNotConnected is the connection-level error for a slot whose connection
// was retired (dropped, or a redial failed) and has not been replaced yet.
var errNotConnected = errors.New("registry connection not established")

// closedDuring reports a request that was aborted because Close ran while it
// was in flight. The result matches ErrClosed (and so ErrNoRegistry) and
// keeps the I/O error that Close caused.
func closedDuring(err error) error {
	if err == nil || errors.Is(err, ErrClosed) {
		return ErrClosed
	}
	return fmt.Errorf("%w: request aborted: %w", ErrClosed, err)
}

// isPeerClose reports whether err means the registry (or something on the
// path) closed or reset the connection: EOF with no response frame, a
// connection reset, or a broken pipe.
func isPeerClose(err error) bool {
	return errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.ECONNABORTED) ||
		errors.Is(err, syscall.EPIPE)
}

// isConnDropped reports whether err means the connection itself is gone
// (closed by the peer or locally), as opposed to a timeout on a half-open
// connection, a malformed frame, or an error response from the registry.
func isConnDropped(err error) bool {
	return isPeerClose(err) || errors.Is(err, net.ErrClosed) || errors.Is(err, errNotConnected)
}

// maxReconnectAttempts bounds the dials one reconnect makes.
const maxReconnectAttempts = 5

// reconnectPolicy holds the reconnect timing knobs. Tests shrink them through
// reconnectTracker.policy; production always uses defaultReconnectPolicy.
type reconnectPolicy struct {
	// dialBase and dialMax shape the jittered exponential backoff between
	// the dial attempts of one reconnect.
	dialBase, dialMax time.Duration
	// cooldownBase and cooldownMax shape the client-wide wait before a
	// reconnect's first dial. It is zero until the registry starts closing
	// fresh connections (see rapidWindow) or whole reconnects fail, then
	// doubles with each such event.
	cooldownBase, cooldownMax time.Duration
	// rapidWindow: a connection the peer closes or resets while younger
	// than this counts as a rapid close, the registry rate limiter's
	// signature (it closes, with no error frame, the first request it
	// denies after a connection's grace period). A success on a connection
	// at least this old ends the rapid-close streak.
	rapidWindow time.Duration
	// quietReset ends both streaks when no rapid close or failed reconnect
	// happened for this long.
	quietReset time.Duration
	// summaryEvery is the minimum interval between INFO summaries.
	summaryEvery time.Duration
}

var defaultReconnectPolicy = reconnectPolicy{
	dialBase:     500 * time.Millisecond,
	dialMax:      8 * time.Second,
	cooldownBase: 250 * time.Millisecond,
	// Kept well below the 8 s deadline the daemon puts on registry calls,
	// so the cooldown alone never turns a shed request into a timeout.
	cooldownMax:  2 * time.Second,
	rapidWindow:  30 * time.Second,
	quietReset:   time.Minute,
	summaryEvery: time.Minute,
}

// jitter returns a random duration in [d/2, d] ("equal jitter"), so clients
// shed by the same limiter do not redial in lockstep.
func jitter(d time.Duration) time.Duration {
	if d <= 1 {
		return d
	}
	half := d / 2
	return half + rand.N(d-half+1) //nolint:gosec // backoff jitter, not a security value
}

// reconnectTracker is the reconnect state shared by every connection of one
// Client: the backoff streaks and the counters behind the periodic INFO
// summary. The registry's limiter works per source IP and globally, so one
// connection being shed is evidence about all of them. The zero value is
// ready to use.
type reconnectTracker struct {
	mu sync.Mutex
	// policy overrides defaultReconnectPolicy when non-nil (tests only).
	policy *reconnectPolicy

	rapidStreak int       // consecutive rapid closes (rate-limit signature)
	failStreak  int       // consecutive reconnects that exhausted every dial attempt
	lastEvent   time.Time // last rapid close or failed reconnect

	// The INFO summary: the first event of a window arms timer, which
	// emits the window's counters summaryEvery later. So at most one
	// summary per summaryEvery, and a burst is reported even if nothing
	// follows it. stopped (set by Close) disarms it for good.
	windowStart time.Time
	stats       reconnectStats
	timer       *time.Timer
	stopped     bool
}

// reconnectStats are the counters reported by one INFO summary.
type reconnectStats struct {
	reconnects  int    // successful redials
	failedDials int    // failed dial attempts
	rapidCloses int    // connections closed by the peer shortly after they were used
	otherConn   int    // requests served by another pooled connection after a drop
	lastCause   string // the connection error behind the latest drop or reconnect
}

func (t *reconnectTracker) pol() reconnectPolicy {
	if t.policy != nil {
		return *t.policy
	}
	return defaultReconnectPolicy
}

// quietResetLocked ends both streaks after a quiet period.
func (t *reconnectTracker) quietResetLocked(now time.Time, p reconnectPolicy) {
	if !t.lastEvent.IsZero() && now.Sub(t.lastEvent) >= p.quietReset {
		t.rapidStreak = 0
		t.failStreak = 0
	}
}

// countedLocked is called after a summary counter changed: it opens the
// summary window and arms the timer that will emit it through emit.
func (t *reconnectTracker) countedLocked(now time.Time, emit func([]any)) {
	if t.windowStart.IsZero() {
		t.windowStart = now
	}
	if t.timer != nil || t.stopped || emit == nil {
		return
	}
	t.timer = time.AfterFunc(t.pol().summaryEvery-now.Sub(t.windowStart), func() {
		t.mu.Lock()
		t.timer = nil
		summary := t.summaryLocked(time.Now())
		t.mu.Unlock()
		emit(summary)
	})
}

// connError records a connection-level request failure on a connection of
// the given age and reports whether it is a rapid close.
func (t *reconnectTracker) connError(err error, age time.Duration, emit func([]any)) (rapid bool) {
	p := t.pol()
	rapid = isPeerClose(err) && age > 0 && age < p.rapidWindow
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stats.lastCause = err.Error()
	if rapid {
		t.quietResetLocked(now, p)
		t.rapidStreak++
		t.stats.rapidCloses++
		t.lastEvent = now
		t.countedLocked(now, emit)
	}
	return rapid
}

// healthy records a request answered on a connection of the given age. An
// answer on a connection older than the rapid-close window shows the
// registry is no longer shedding it, which ends the rapid-close streak.
func (t *reconnectTracker) healthy(age time.Duration) {
	if age < t.pol().rapidWindow {
		return
	}
	t.mu.Lock()
	t.rapidStreak = 0
	t.mu.Unlock()
}

// cooldown returns the wait before a reconnect's first dial: zero while
// nothing suspicious happened, otherwise a jittered exponential of the
// combined streak, capped at cooldownMax.
func (t *reconnectTracker) cooldown() time.Duration {
	p := t.pol()
	t.mu.Lock()
	t.quietResetLocked(time.Now(), p)
	n := t.rapidStreak + t.failStreak
	t.mu.Unlock()
	if n <= 0 || p.cooldownBase <= 0 {
		return 0
	}
	d := p.cooldownMax
	if n <= 16 {
		if v := p.cooldownBase << (n - 1); v < d {
			d = v
		}
	}
	return jitter(d)
}

func (t *reconnectTracker) dialFailed(emit func([]any)) {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stats.failedDials++
	t.countedLocked(now, emit)
}

// exhausted records a reconnect that failed every dial attempt.
func (t *reconnectTracker) exhausted() {
	now := time.Now()
	t.mu.Lock()
	t.quietResetLocked(now, t.pol())
	t.failStreak++
	t.lastEvent = now
	t.mu.Unlock()
}

func (t *reconnectTracker) reconnected(cause error, emit func([]any)) {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.failStreak = 0
	t.stats.reconnects++
	if cause != nil {
		t.stats.lastCause = cause.Error()
	}
	t.countedLocked(now, emit)
}

func (t *reconnectTracker) servedByOther(emit func([]any)) {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stats.otherConn++
	t.countedLocked(now, emit)
}

// stop disarms the summary timer for good and returns the summary of the
// current window, or nil if nothing happened in it (used by Close so the
// last window is not lost).
func (t *reconnectTracker) stop() []any {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stopped = true
	if t.timer != nil {
		t.timer.Stop()
		t.timer = nil
	}
	return t.summaryLocked(time.Now())
}

// summaryLocked returns the slog attributes summarising the current window
// and starts a new one, or nil when nothing happened in it.
func (t *reconnectTracker) summaryLocked(now time.Time) []any {
	s := t.stats
	window := time.Duration(0)
	if !t.windowStart.IsZero() {
		window = now.Sub(t.windowStart)
	}
	t.stats = reconnectStats{}
	t.windowStart = time.Time{}
	if s.reconnects == 0 && s.failedDials == 0 && s.rapidCloses == 0 && s.otherConn == 0 {
		return nil
	}
	return []any{
		"window", window.Round(time.Second).String(),
		"reconnects", s.reconnects,
		"failed_dials", s.failedDials,
		"rapid_closes", s.rapidCloses,
		"served_by_other_conn", s.otherConn,
		"rate_limit_suspected", s.rapidCloses > 0,
		"backoff_streak", t.rapidStreak + t.failStreak,
		"last_cause", s.lastCause,
	}
}

// sleepCtx waits for d, returning early with ctx's error when ctx is done or
// with ErrClosed when done is closed.
func sleepCtx(ctx context.Context, done <-chan struct{}, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return ErrClosed
	}
}
