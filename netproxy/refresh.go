// SPDX-License-Identifier: AGPL-3.0-or-later

package netproxy

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os/exec"
	"strings"
	"time"
)

// EnvRefreshCommand is the environment variable that, by convention, holds
// the refresh command for WithRefreshCommand, e.g.
//
//	PILOT_PROXY_CMD='bash -c '\''printf %s "$https_proxy"'\'''
//
// netproxy never reads it on its own: a program opts in by passing
// WithRefreshCommand(os.Getenv(EnvRefreshCommand)).
const EnvRefreshCommand = "PILOT_PROXY_CMD"

// DefaultRefreshInterval is how long a refreshing Resolver uses the settings
// it last read before a lookup reads them again.
const DefaultRefreshInterval = 60 * time.Second

// refreshTimeout bounds one refresh (one run of the refresh command). A
// variable so tests can shorten it.
var refreshTimeout = 10 * time.Second

// maxRefreshOutput caps what a refresh command may print.
const maxRefreshOutput = 64 << 10

// Option configures a Resolver built by NewResolver.
type Option func(*options)

type options struct {
	source   func(context.Context) (string, error)
	command  bool
	interval time.Duration
	onError  func(error)
}

func newOptions(opts []Option) options {
	var o options
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	return o
}

// WithRefreshCommand makes the Resolver take its proxy URL from the output
// of command, run with "sh -c" in the process's environment, stdin and
// stderr discarded, for at most 10 seconds. The output, surrounding
// whitespace trimmed, must be one http:// or https:// proxy URL with its
// current credentials. It is never logged or included in errors.
//
// The command runs when NewResolver builds the Resolver, again at most
// every refresh interval, and whenever a proxy rejects the credentials. Its
// URL replaces the explicit URL, or in ModeAuto the environment's proxy
// URLs, while NO_PROXY and the loopback exemption keep applying. If a run
// fails, or prints nothing or something that is not a proxy URL, the last
// good URL stays in use.
//
// A child process inherits this process's environment, so the command must
// read the current value from somewhere that tracks the rotation — in Meta
// Muse a new bash does: bash -c 'printf %s "$https_proxy"'. The command is
// trusted configuration, like the proxy URL itself. An empty command
// leaves the Resolver unchanged, so wiring an unset EnvRefreshCommand is
// harmless.
func WithRefreshCommand(command string) Option {
	return func(o *options) {
		if strings.TrimSpace(command) == "" {
			return
		}
		o.source = commandSource(command)
		o.command = true
	}
}

// WithRefreshFunc is WithRefreshCommand for a Go function: fn returns the
// current proxy URL, under the same rules as a refresh command's output. It
// must honour ctx, which carries the 10 second refresh deadline. Its errors
// are passed on (prefixed "netproxy: proxy refresh: "), so they must not
// contain credentials. A nil fn leaves the Resolver unchanged.
func WithRefreshFunc(fn func(ctx context.Context) (string, error)) Option {
	return func(o *options) {
		if fn == nil {
			return
		}
		o.source = fn
		o.command = false
	}
}

// WithRefreshInterval sets how long the Resolver uses the settings it last
// read before a lookup reads them again. Zero means DefaultRefreshInterval;
// a negative interval turns timed refreshes off, leaving only the refreshes
// a rejected credential triggers (and explicit Refresh calls).
func WithRefreshInterval(d time.Duration) Option {
	return func(o *options) { o.interval = d }
}

// WithRefreshErrorHandler has fn called with the error when a refresh
// fails, once per run of consecutive failures: after a failure it is not
// called again until a refresh has succeeded. The error never contains
// credentials or the refresh command's output (a WithRefreshFunc
// function's own errors aside). fn is called from the refreshing goroutine
// and must not block.
func WithRefreshErrorHandler(fn func(error)) Option {
	return func(o *options) { o.onError = fn }
}

// configure applies o to a new Resolver and, with a refresh source, runs
// the first refresh.
func (r *Resolver) configure(o options) {
	r.source, r.command, r.onError = o.source, o.command, o.onError
	r.interval = o.interval
	if r.interval == 0 {
		r.interval = DefaultRefreshInterval
	}
	r.lastRun = time.Now()
	if r.source != nil {
		// Failures are reported through onError and leave the initial
		// settings in place.
		_ = r.Refresh(context.Background())
	}
}

// refreshable reports whether the Resolver has settings to re-read.
func (r *Resolver) refreshable() bool {
	if r == nil {
		return false
	}
	switch r.mode {
	case ModeAuto:
		return true
	case ModeExplicit:
		return r.source != nil
	}
	return false
}

// snapshot returns the current settings without refreshing.
func (r *Resolver) snapshot() *proxyState {
	if r != nil {
		if st := r.state.Load(); st != nil {
			return st
		}
	}
	return &emptyState
}

// current returns the settings for a lookup, refreshing them first when the
// refresh interval has passed. If ctx ends before that refresh does, the
// previous settings are returned.
func (r *Resolver) current(ctx context.Context) *proxyState {
	if !r.refreshable() || r.interval < 0 {
		return r.snapshot()
	}
	r.mu.Lock()
	var call *refreshCall
	if time.Since(r.lastRun) >= r.interval {
		call = r.inflight
		if call == nil {
			call = r.startLocked()
		}
	}
	r.mu.Unlock()
	if call != nil {
		call.wait(ctx)
	}
	return r.snapshot()
}

// Refresh re-reads the Resolver's settings now: the environment in
// ModeAuto, and the refresh source if there is one. A refresh already in
// progress is joined rather than repeated. On error the previous settings
// stay in use. Refresh is a no-op for Resolvers with nothing to re-read
// (nil, Off, and Explicit without a refresh source). The error never
// contains credentials; ctx only bounds the wait.
func (r *Resolver) Refresh(ctx context.Context) error {
	if !r.refreshable() {
		return nil
	}
	r.mu.Lock()
	call := r.inflight
	if call == nil {
		call = r.startLocked()
	}
	r.mu.Unlock()
	if !call.wait(ctx) {
		return ctx.Err()
	}
	return call.err
}

// attemptCount returns the number of refreshes started so far.
func (r *Resolver) attemptCount() uint64 {
	if !r.refreshable() {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.attempts
}

// reauth handles a proxy rejecting the credentials in used. start is
// attemptCount from before used was picked; pick applies a reading of the
// settings to the same target. It reports the proxy to retry through (nil
// for a direct connection) and whether a retry is worthwhile, which it is
// only when the current settings differ from used:
//
//   - they already differ (another caller refreshed): no new refresh;
//   - a refresh is in progress: wait for it;
//   - a refresh started after used was picked and has finished: it could
//     not do better, so no new refresh and no retry;
//   - otherwise: refresh now.
//
// err is the error of the refresh this call waited for, if it failed.
func (r *Resolver) reauth(ctx context.Context, start uint64, used *url.URL, pick func(*proxyState) *url.URL) (next *url.URL, retry bool, err error) {
	if !r.refreshable() {
		return nil, false, nil
	}
	r.mu.Lock()
	if cur := pick(r.snapshot()); !sameURL(cur, used) {
		r.mu.Unlock()
		return cur, true, nil
	}
	call := r.inflight
	if call == nil {
		if r.attempts != start {
			r.mu.Unlock()
			return nil, false, nil
		}
		call = r.startLocked()
	}
	r.mu.Unlock()
	if !call.wait(ctx) {
		return nil, false, nil
	}
	if cur := pick(r.snapshot()); !sameURL(cur, used) {
		return cur, true, nil
	}
	return nil, false, call.err
}

// refreshCall is one refresh, shared by everyone waiting for it.
type refreshCall struct {
	done chan struct{}
	err  error // set before done is closed
}

// wait blocks until the refresh finishes (true) or ctx ends (false). It
// gives up after the refresh deadline plus a margin even if ctx never ends,
// in case a WithRefreshFunc function ignores its context.
func (c *refreshCall) wait(ctx context.Context) bool {
	t := time.NewTimer(refreshTimeout + 5*time.Second)
	defer t.Stop()
	select {
	case <-c.done:
		return true
	case <-ctx.Done():
	case <-t.C:
	}
	return false
}

// startLocked starts a refresh. r.mu must be held.
func (r *Resolver) startLocked() *refreshCall {
	c := &refreshCall{done: make(chan struct{})}
	r.inflight = c
	r.attempts++
	go r.run(c)
	return c
}

// run performs refresh c. It runs on its own goroutine, detached from the
// callers' contexts, so one caller giving up does not fail the refresh for
// the others.
func (r *Resolver) run(c *refreshCall) {
	ctx, cancel := context.WithTimeout(context.Background(), refreshTimeout)
	st, err := r.load(ctx)
	cancel()

	r.mu.Lock()
	report := false
	if err == nil {
		r.state.Store(st)
		r.failing = false
	} else {
		report = !r.failing
		r.failing = true
	}
	r.lastRun = time.Now()
	r.inflight = nil
	c.err = err
	r.mu.Unlock()

	if report && r.onError != nil {
		r.onError(err)
	}
	close(c.done)
}

// load reads a fresh copy of the settings.
func (r *Resolver) load(ctx context.Context) (*proxyState, error) {
	var st *proxyState
	if r.mode == ModeAuto {
		var err error
		if st, err = readEnv(r.getenv); err != nil {
			return nil, err
		}
	} else {
		cp := *r.snapshot()
		st = &cp
	}
	if r.source != nil {
		raw, err := r.source(ctx)
		if err != nil {
			if r.command {
				return nil, err
			}
			return nil, fmt.Errorf("netproxy: proxy refresh: %w", err)
		}
		u, err := parseRefreshed(raw)
		if err != nil {
			return nil, err
		}
		st.fixed = u
	}
	return st, nil
}

// errRefreshOutput never echoes the output: it would carry credentials.
var errRefreshOutput = errors.New("netproxy: refreshed proxy URL is unusable (value withheld; want http://[user:pass@]host[:port] or https://...)")

// parseRefreshed validates a refresh source's output. Unlike an environment
// variable, it must spell out its scheme, so a stray token is never taken
// for a proxy host name (which errors and logs would then show).
func parseRefreshed(raw string) (*url.URL, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, errors.New("netproxy: refreshed proxy URL is empty")
	}
	scheme, _, ok := strings.Cut(s, "://")
	if !ok {
		return nil, errRefreshOutput
	}
	switch strings.ToLower(scheme) {
	case "http", "https":
	default:
		return nil, errRefreshOutput
	}
	u, err := parseProxyURL(s)
	if err != nil {
		return nil, errRefreshOutput
	}
	return u, nil
}

// commandSource runs command with "sh -c" and returns what it prints.
// Errors say how the command failed (exit status, timeout, not startable)
// and never include its output or stderr.
func commandSource(command string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		cmd := exec.CommandContext(ctx, "sh", "-c", command)
		var out cappedBuffer
		cmd.Stdout = &out
		// Stdin and Stderr stay nil (the null device): stderr could echo
		// credentials, e.g. under "set -x".
		cmd.WaitDelay = time.Second // a child left holding stdout cannot hang Wait
		err := cmd.Run()
		switch {
		case ctx.Err() != nil:
			return "", fmt.Errorf("netproxy: refresh command timed out after %v", refreshTimeout)
		case err != nil:
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				return "", fmt.Errorf("netproxy: refresh command failed: %s", ee.ProcessState)
			}
			if errors.Is(err, exec.ErrWaitDelay) {
				return "", errors.New("netproxy: refresh command left a process holding its output open")
			}
			return "", fmt.Errorf("netproxy: refresh command failed to run: %v", err)
		case out.overflow:
			return "", fmt.Errorf("netproxy: refresh command printed more than %d bytes", maxRefreshOutput)
		}
		return string(out.buf), nil
	}
}

// cappedBuffer keeps the first maxRefreshOutput bytes written to it and
// notes whether there were more.
type cappedBuffer struct {
	buf      []byte
	overflow bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if room := maxRefreshOutput - len(b.buf); len(p) > room {
		b.buf = append(b.buf, p[:room]...)
		b.overflow = true
		return len(p), nil
	}
	b.buf = append(b.buf, p...)
	return len(p), nil
}

// sameURL reports whether a and b are the same proxy with the same
// credentials (nil meaning a direct connection).
func sameURL(a, b *url.URL) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.String() == b.String()
}

// refreshFailedError adds the reason a credential refresh failed to the
// error that triggered the refresh. Both stay reachable via errors.As/Is.
type refreshFailedError struct {
	err     error
	refresh error
}

func (e *refreshFailedError) Error() string {
	return e.err.Error() + " (proxy credential refresh failed: " + e.refresh.Error() + ")"
}

func (e *refreshFailedError) Unwrap() []error { return []error{e.err, e.refresh} }

// withRefreshError returns err, annotated with refreshErr when there is one.
func withRefreshError(err, refreshErr error) error {
	if refreshErr == nil {
		return err
	}
	return &refreshFailedError{err: err, refresh: refreshErr}
}
