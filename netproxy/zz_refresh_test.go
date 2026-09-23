// SPDX-License-Identifier: AGPL-3.0-or-later

package netproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// credSource simulates a sandbox that rotates its proxy credentials: the
// test proxy only accepts the newest ones, and the refresh command prints
// them, the way a fresh shell sees the current HTTPS_PROXY in Meta Muse.
// The command also logs each run, so tests can count refreshes.
type credSource struct {
	t     *testing.T
	proxy *testProxy
	dir   string
	gen   int
	// delay is a shell snippet run before printing (e.g. "sleep 0.3;").
	delay string
}

func newCredSource(t *testing.T, proxy *testProxy) *credSource {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("refresh commands run with sh -c")
	}
	c := &credSource{t: t, proxy: proxy, dir: t.TempDir()}
	c.rotate()
	return c
}

// rotate issues new credentials. From now on the proxy rejects the old ones
// (tunnels it already opened stay up) and the command prints the new ones.
// The password holds characters that need escaping in a URL.
func (c *credSource) rotate() (user, pass string) {
	c.gen++
	user, pass = "muse-agent", fmt.Sprintf("tok/%d?r#s@t", c.gen)
	c.proxy.setAuth(user, pass)
	c.write(c.urlFor(user, pass))
	return user, pass
}

func (c *credSource) urlFor(user, pass string) string {
	return "http://" + url.UserPassword(user, pass).String() + "@" + c.proxy.addr()
}

// current is the URL the command prints now.
func (c *credSource) current() string {
	b, err := os.ReadFile(filepath.Join(c.dir, "url"))
	if err != nil {
		c.t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

// write replaces what the command prints, atomically.
func (c *credSource) write(proxyURL string) {
	c.t.Helper()
	tmp := filepath.Join(c.dir, "url.tmp")
	if err := os.WriteFile(tmp, []byte(proxyURL+"\n"), 0o600); err != nil {
		c.t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(c.dir, "url")); err != nil {
		c.t.Fatal(err)
	}
}

// fail makes the command exit 3 (true) or work again (false).
func (c *credSource) fail(on bool) {
	c.t.Helper()
	path := filepath.Join(c.dir, "fail")
	if on {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			c.t.Fatal(err)
		}
		return
	}
	if err := os.Remove(path); err != nil {
		c.t.Fatal(err)
	}
}

func (c *credSource) command() string {
	return fmt.Sprintf("echo run >> %s; [ -e %s ] && exit 3; %s cat %s",
		shellQuote(filepath.Join(c.dir, "runs")), shellQuote(filepath.Join(c.dir, "fail")),
		c.delay, shellQuote(filepath.Join(c.dir, "url")))
}

// runs counts the command's runs so far.
func (c *credSource) runs() int {
	b, err := os.ReadFile(filepath.Join(c.dir, "runs"))
	if errors.Is(err, os.ErrNotExist) {
		return 0
	}
	if err != nil {
		c.t.Fatal(err)
	}
	return strings.Count(string(b), "run\n")
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// errorLog collects WithRefreshErrorHandler calls.
type errorLog struct {
	mu   sync.Mutex
	errs []error
}

func (l *errorLog) handler() Option {
	return WithRefreshErrorHandler(func(err error) {
		l.mu.Lock()
		l.errs = append(l.errs, err)
		l.mu.Unlock()
	})
}

func (l *errorLog) all() []error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]error(nil), l.errs...)
}

// syncEnv is a getenv whose values tests change while a Resolver reads it.
type syncEnv struct {
	mu sync.Mutex
	m  map[string]string
}

func (e *syncEnv) get(k string) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.m[k]
}

func (e *syncEnv) set(k, v string) {
	e.mu.Lock()
	e.m[k] = v
	e.mu.Unlock()
}

func dialEcho(t *testing.T, d *Dialer, target, msg string) net.Conn {
	t.Helper()
	c, err := d.DialContext(context.Background(), "tcp", target)
	if err != nil {
		t.Fatalf("dial %s: %v", target, err)
	}
	roundTrip(t, c, msg)
	return c
}

// The Muse scenario end to end: a daemon started with HTTPS_PROXY holding
// the launch-time credentials, and PILOT_PROXY_CMD printing the current
// ones. The proxy rotates several times; every new dial still succeeds
// (one 407, one command run, one retry per rotation) and every tunnel
// opened before a rotation keeps working.
func TestRefreshKeepsLongRunningDialerWorkingAcrossRotations(t *testing.T) {
	t.Parallel()
	echoIP, echoPort := newEchoServer(t)
	proxy := newTestProxy(t, map[string]string{echoHost: echoIP})
	creds := newCredSource(t, proxy)
	var errs errorLog
	env := envMap(map[string]string{"HTTPS_PROXY": creds.current(), "NO_PROXY": "localhost"})
	r, err := newAuto(env, newOptions([]Option{WithRefreshCommand(creds.command()), WithRefreshInterval(time.Hour), errs.handler()}))
	if err != nil {
		t.Fatalf("newAuto: %v", err)
	}
	if got := creds.runs(); got != 1 {
		t.Fatalf("command ran %d times while building the Resolver, want 1", got)
	}
	d := NewDialer(r)
	target := net.JoinHostPort(echoHost, echoPort)

	var open []net.Conn
	defer func() {
		for _, c := range open {
			c.Close()
		}
	}()
	open = append(open, dialEcho(t, d, target, "before any rotation"))

	const rotations = 4
	for i := 1; i <= rotations; i++ {
		user, pass := creds.rotate()
		open = append(open, dialEcho(t, d, target, fmt.Sprintf("after rotation %d", i)))
		for j, c := range open {
			roundTrip(t, c, fmt.Sprintf("tunnel %d still up after rotation %d", j, i))
		}
		_, _, auths := proxy.seen()
		if last := auths[len(auths)-1]; last != basicAuth(user, pass) {
			t.Fatalf("rotation %d: retry sent %q, want the new credentials", i, last)
		}
	}
	if got := proxy.rejected.Load(); got != rotations {
		t.Fatalf("proxy rejected %d CONNECTs, want one per rotation (%d)", got, rotations)
	}
	if got := creds.runs(); got != 1+rotations {
		t.Fatalf("command ran %d times, want %d (build + one per rotation)", got, 1+rotations)
	}
	if e := errs.all(); len(e) != 0 {
		t.Fatalf("unexpected refresh errors: %v", e)
	}
}

// When the refreshed credentials are the ones the proxy just rejected, the
// dial fails with the 407 straight away: no retry, no loop.
func TestRefreshUnchangedCredentialsDoNotRetry(t *testing.T) {
	t.Parallel()
	proxy := newTestProxy(t, nil)
	creds := newCredSource(t, proxy)
	stale := creds.urlFor("muse-agent", "expired")
	creds.write(stale) // the command keeps printing credentials the proxy refuses
	r, err := NewResolver(stale, WithRefreshCommand(creds.command()), WithRefreshInterval(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	d := NewDialer(r)
	target := "registry.pilot.invalid:443"
	for i := 1; i <= 3; i++ {
		_, err := d.DialContext(context.Background(), "tcp", target)
		want := "proxy CONNECT " + target + ": 407 Proxy Authentication Required"
		if err == nil || err.Error() != want {
			t.Fatalf("dial %d: error = %v, want %q", i, err, want)
		}
		var ce *ConnectError
		if !errors.As(err, &ce) || ce.StatusCode != http.StatusProxyAuthRequired {
			t.Fatalf("dial %d: %v is not a 407 ConnectError", i, err)
		}
		if got := proxy.rejected.Load(); got != int32(i) {
			t.Fatalf("dial %d: proxy saw %d CONNECTs, want %d (no retries)", i, got, i)
		}
		// One refresh per failed dial at most: build + i.
		if got := creds.runs(); got != 1+i {
			t.Fatalf("dial %d: command ran %d times, want %d", i, got, 1+i)
		}
	}

	// The same holds for ModeAuto without a command: the environment is
	// re-read, found unchanged, and the dial fails once.
	proxy2 := newTestProxy(t, nil, withAuth("u", "current"))
	auto, err := fromEnv(envMap(map[string]string{"HTTPS_PROXY": proxy2.url("u:old")}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewDialer(auto).Dial("tcp", target); err == nil {
		t.Fatal("dial with stale environment credentials succeeded")
	}
	if got := proxy2.rejected.Load(); got != 1 {
		t.Fatalf("auto: proxy saw %d CONNECTs, want 1", got)
	}
}

// A refresh command that starts failing never costs the working
// credentials: lookups keep the last good URL, the failure is reported
// once per run of failures, and a dial the proxy rejects says why the
// refresh did not help.
func TestRefreshCommandFailureKeepsLastGoodCredentials(t *testing.T) {
	t.Parallel()
	echoIP, echoPort := newEchoServer(t)
	proxy := newTestProxy(t, map[string]string{echoHost: echoIP})
	creds := newCredSource(t, proxy)
	_, pass1 := creds.user1()
	var errs errorLog
	r, err := NewResolver(proxy.url("launch:time"), WithRefreshCommand(creds.command()), WithRefreshInterval(time.Hour), errs.handler())
	if err != nil {
		t.Fatal(err)
	}
	d := NewDialer(r)
	target := net.JoinHostPort(echoHost, echoPort)
	dialEcho(t, d, target, "working").Close()

	creds.fail(true)
	for i := 0; i < 3; i++ {
		err := r.Refresh(context.Background())
		if err == nil || err.Error() != "netproxy: refresh command failed: exit status 3" {
			t.Fatalf("Refresh = %v, want the exit status", err)
		}
	}
	if e := errs.all(); len(e) != 1 {
		t.Fatalf("error handler called %d times for one run of failures, want 1: %v", len(e), e)
	}
	dialEcho(t, d, target, "last good credentials still used").Close()
	if got := proxy.rejected.Load(); got != 0 {
		t.Fatalf("proxy rejected %d CONNECTs, want 0", got)
	}

	// The proxy rotates while the command is broken: the dial fails, and
	// its error carries both the 407 and the refresh failure.
	_, pass2 := creds.rotate()
	_, err = d.DialContext(context.Background(), "tcp", target)
	if err == nil {
		t.Fatal("dial succeeded with a broken refresh command after a rotation")
	}
	var ce *ConnectError
	if !errors.As(err, &ce) || ce.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("%v is not a 407 ConnectError", err)
	}
	if !strings.Contains(err.Error(), "407 Proxy Authentication Required (proxy credential refresh failed: netproxy: refresh command failed: exit status 3)") {
		t.Fatalf("error = %q, want the 407 and the refresh failure", err)
	}
	if got := proxy.rejected.Load(); got != 1 {
		t.Fatalf("proxy saw %d rejected CONNECTs, want 1 (no retry with unchanged credentials)", got)
	}
	if e := errs.all(); len(e) != 1 {
		t.Fatalf("error handler called %d times, want still 1", len(e))
	}

	// The command recovers: the next rejected dial refreshes and succeeds.
	creds.fail(false)
	dialEcho(t, d, target, "recovered").Close()
	if got := proxy.rejected.Load(); got != 2 {
		t.Fatalf("proxy saw %d rejected CONNECTs, want 2", got)
	}

	// A new run of failures is reported again.
	creds.fail(true)
	if err := r.Refresh(context.Background()); err == nil {
		t.Fatal("Refresh succeeded with a failing command")
	}
	all := errs.all()
	if len(all) != 2 {
		t.Fatalf("error handler called %d times, want 2 (one per run of failures)", len(all))
	}
	for _, e := range append(all, err) {
		for _, secret := range []string{pass1, pass2, "tok/", "tok%2F"} {
			if strings.Contains(e.Error(), secret) {
				t.Fatalf("error %q leaks %q", e, secret)
			}
		}
	}
	if s := r.String(); s != "http://***@"+proxy.addr()+" (credentials refreshed by command)" {
		t.Fatalf("String = %q", s)
	}
}

// user1 returns the first generation's credentials.
func (c *credSource) user1() (user, pass string) { return "muse-agent", "tok/1?r#s@t" }

// Lookups refresh on the timer too. With a failing command every lookup
// keeps the last good URL, and the failure is still reported only once.
func TestRefreshIntervalKeepsLastGoodOnFailure(t *testing.T) {
	t.Parallel()
	echoIP, echoPort := newEchoServer(t)
	proxy := newTestProxy(t, map[string]string{echoHost: echoIP})
	creds := newCredSource(t, proxy)
	var errs errorLog
	r, err := NewResolver(proxy.url("launch:time"), WithRefreshCommand(creds.command()), WithRefreshInterval(time.Nanosecond), errs.handler())
	if err != nil {
		t.Fatal(err)
	}
	d := NewDialer(r)
	target := net.JoinHostPort(echoHost, echoPort)
	creds.fail(true)
	for i := 0; i < 3; i++ {
		dialEcho(t, d, target, "on the last good credentials").Close()
	}
	if got := creds.runs(); got != 4 {
		t.Fatalf("command ran %d times, want 4 (build + one per lookup)", got)
	}
	if e := errs.all(); len(e) != 1 {
		t.Fatalf("error handler called %d times, want 1: %v", len(e), e)
	}

	// Once the command works, a lookup picks up rotated credentials without
	// waiting for a 407.
	creds.fail(false)
	creds.rotate()
	dialEcho(t, d, target, "rotated").Close()
	if got := proxy.rejected.Load(); got != 0 {
		t.Fatalf("proxy rejected %d CONNECTs, want 0: the timed refresh ran first", got)
	}
}

// Fifty dials hit a rotation at once. They share one refresh: the command
// runs exactly once, and every dial succeeds.
func TestRefreshConcurrentRejectionsRunOneCommand(t *testing.T) {
	t.Parallel()
	echoIP, echoPort := newEchoServer(t)
	proxy := newTestProxy(t, map[string]string{echoHost: echoIP})
	creds := newCredSource(t, proxy)
	creds.delay = "sleep 0.3;" // keep the refresh in flight while the others arrive
	r, err := NewResolver(proxy.url("launch:time"), WithRefreshCommand(creds.command()), WithRefreshInterval(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	d := NewDialer(r)
	target := net.JoinHostPort(echoHost, echoPort)
	creds.rotate()

	const n = 50
	var wg sync.WaitGroup
	var failed atomic.Int32
	gate := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-gate
			c, err := d.DialContext(context.Background(), "tcp", target)
			if err != nil {
				failed.Add(1)
				t.Errorf("dial: %v", err)
				return
			}
			defer c.Close()
			msg := "concurrent"
			c.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := c.Write([]byte(msg)); err != nil {
				t.Errorf("write: %v", err)
				return
			}
			buf := make([]byte, len(msg))
			if _, err := io.ReadFull(c, buf); err != nil || string(buf) != msg {
				t.Errorf("read %q: %v", buf, err)
			}
		}()
	}
	close(gate)
	wg.Wait()
	if failed.Load() != 0 {
		t.Fatalf("%d of %d dials failed", failed.Load(), n)
	}
	if got := creds.runs(); got != 2 {
		t.Fatalf("command ran %d times, want 2 (build + exactly one refresh for the rotation)", got)
	}
	rejected := proxy.rejected.Load()
	if rejected < 2 {
		t.Fatalf("only %d dials hit the rotation; the test did not exercise concurrent rejections", rejected)
	}
	t.Logf("%d of %d dials were rejected and shared one refresh", rejected, n)
}

// Without a command, ModeAuto re-reads the environment, which is enough for
// a process whose environment is updated in place.
func TestRefreshAutoModeRereadsEnvironment(t *testing.T) {
	t.Parallel()
	echoIP, echoPort := newEchoServer(t)
	proxy := newTestProxy(t, map[string]string{echoHost: echoIP}, withAuth("u", "one"))
	env := &syncEnv{m: map[string]string{"HTTPS_PROXY": proxy.url("u:one")}}
	r, err := newAuto(env.get, options{})
	if err != nil {
		t.Fatal(err)
	}
	d := NewDialer(r)
	target := net.JoinHostPort(echoHost, echoPort)
	first := dialEcho(t, d, target, "one")
	defer first.Close()

	proxy.setAuth("u", "two")
	env.set("HTTPS_PROXY", proxy.url("u:two"))
	dialEcho(t, d, target, "two").Close()
	roundTrip(t, first, "first tunnel untouched")
	if got := proxy.rejected.Load(); got != 1 {
		t.Fatalf("proxy rejected %d CONNECTs, want 1", got)
	}

	// On the timer, a lookup follows the environment without any 407.
	env2 := &syncEnv{m: map[string]string{"HTTPS_PROXY": "http://a.invalid:1"}}
	r2, err := newAuto(env2.get, newOptions([]Option{WithRefreshInterval(time.Nanosecond)}))
	if err != nil {
		t.Fatal(err)
	}
	env2.set("HTTPS_PROXY", "http://b.invalid:2")
	env2.set("NO_PROXY", "skip.invalid")
	if got := proxyFor(t, r2, "x.invalid:443"); got != "http://b.invalid:2" {
		t.Fatalf("after the environment changed: proxy %q", got)
	}
	if got := proxyFor(t, r2, "skip.invalid:443"); got != "" {
		t.Fatalf("new NO_PROXY ignored: proxy %q", got)
	}
	// An environment without a proxy at first starts proxying once one is
	// set.
	env3 := &syncEnv{m: map[string]string{}}
	r3, err := newAuto(env3.get, newOptions([]Option{WithRefreshInterval(time.Nanosecond)}))
	if err != nil {
		t.Fatal(err)
	}
	if r3.Enabled() || proxyFor(t, r3, "x.invalid:443") != "" || proxyForURL(t, r3, "https://x.invalid/") != "" {
		t.Fatal("empty environment proxies")
	}
	env3.set("https_proxy", "http://late.invalid:3128")
	if got := proxyFor(t, r3, "x.invalid:443"); got != "http://late.invalid:3128" {
		t.Fatalf("after https_proxy was set: proxy %q", got)
	}
	if got := proxyForURL(t, r3, "https://x.invalid/"); got != "http://late.invalid:3128" {
		t.Fatalf("after https_proxy was set: request proxy %q", got)
	}
	if !r3.Enabled() {
		t.Fatal("Enabled still false after the environment gained a proxy")
	}

	// An unusable HTTPS_PROXY is a failed refresh: the last reading stays.
	env2.set("HTTPS_PROXY", "socks5://c.invalid:3")
	if got := proxyFor(t, r2, "x.invalid:443"); got != "http://b.invalid:2" {
		t.Fatalf("after an unusable HTTPS_PROXY: proxy %q", got)
	}
	var ee *EnvError
	if err := r2.Refresh(context.Background()); !errors.As(err, &ee) || ee.Var != "HTTPS_PROXY" {
		t.Fatalf("Refresh = %v, want an EnvError for HTTPS_PROXY", err)
	}
}

// FromEnvironment follows the real process environment.
func TestFromEnvironmentFollowsInProcessUpdates(t *testing.T) {
	echoIP, echoPort := newEchoServer(t)
	proxy := newTestProxy(t, map[string]string{echoHost: echoIP}, withAuth("u", "one"))
	t.Setenv("HTTPS_PROXY", proxy.url("u:one"))
	r, err := FromEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	d := NewDialer(r)
	target := net.JoinHostPort(echoHost, echoPort)
	dialEcho(t, d, target, "one").Close()
	proxy.setAuth("u", "two")
	t.Setenv("HTTPS_PROXY", proxy.url("u:two"))
	dialEcho(t, d, target, "two").Close()
}

// When refreshed settings stop proxying the target, the retry dials it
// directly.
func TestRefreshRetryFollowsNewRouting(t *testing.T) {
	t.Parallel()
	echoIP, echoPort := newEchoServer(t)
	proxy := newTestProxy(t, map[string]string{echoHost: echoIP}, withAuth("u", "one"))
	env := &syncEnv{m: map[string]string{"HTTPS_PROXY": proxy.url("u:one")}}
	r, err := newAuto(env.get, options{})
	if err != nil {
		t.Fatal(err)
	}
	fwd := &recordingForward{hosts: map[string]string{echoHost: echoIP}}
	d := &Dialer{Resolver: r, Forward: fwd.dial}
	proxy.setAuth("u", "two")
	env.set("NO_PROXY", echoHost)
	target := net.JoinHostPort(echoHost, echoPort)
	dialEcho(t, d, target, "direct after refresh").Close()
	if got := fwd.seen(); len(got) != 2 || got[0] != proxy.addr() || got[1] != target {
		t.Fatalf("dials = %q, want the proxy and then the target directly", got)
	}
}

// Some proxies' rejections arrive as a status line net/http cannot parse
// ("malformed HTTP status code"). That also triggers a refresh.
func TestDialerRefreshesOnMalformedRejection(t *testing.T) {
	t.Parallel()
	echoIP, echoPort := newEchoServer(t)
	proxy := newTestProxy(t, map[string]string{echoHost: echoIP}, withRejectLine("HTTP/1.1 407Proxy Authentication Required"))
	creds := newCredSource(t, proxy)
	r, err := NewResolver(proxy.url("launch:time"), WithRefreshCommand(creds.command()), WithRefreshInterval(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	d := NewDialer(r)
	target := net.JoinHostPort(echoHost, echoPort)
	creds.rotate()
	dialEcho(t, d, target, "after a garbled 407").Close()
	if got, runs := proxy.rejected.Load(), creds.runs(); got != 1 || runs != 2 {
		t.Fatalf("rejected %d, command runs %d; want 1 and 2", got, runs)
	}

	// Without anything to refresh, the error is returned as before.
	_, err = NewDialer(mustExplicit(t, proxy.url("u:wrong"))).Dial("tcp", target)
	if err == nil || !strings.Contains(err.Error(), `read CONNECT response: malformed HTTP status code "407Proxy"`) {
		t.Fatalf("error = %v", err)
	}
}

// A refresh source's output carries credentials: nothing it prints, and
// nothing a failing command writes to stderr, reaches an error or String.
func TestRefreshOutputNeverLeaks(t *testing.T) {
	t.Parallel()
	for _, out := range []string{
		"socks5://user:SECRET@proxy.invalid:1080",
		"SECRET",
		"user:SECRET@proxy.invalid:3128", // no scheme: rejected for refresh output
		"http://user:SECRET@",
		"http://user:SECRET@proxy.invalid:3128\nSECRET-line-two",
		"   \n",
	} {
		var errs errorLog
		r, err := NewResolver("http://initial.invalid:3128", WithRefreshFunc(func(context.Context) (string, error) { return out, nil }), errs.handler())
		if err != nil {
			t.Fatal(err)
		}
		rerr := r.Refresh(context.Background())
		if rerr == nil {
			t.Fatalf("output %q accepted", out)
		}
		all := errs.all()
		if len(all) != 1 {
			t.Fatalf("output %q: handler called %d times", out, len(all))
		}
		for _, s := range []string{rerr.Error(), all[0].Error(), r.String()} {
			if strings.Contains(s, "SECRET") {
				t.Fatalf("output %q leaked into %q", out, s)
			}
		}
		if got := proxyFor(t, r, "x.invalid:443"); got != "http://initial.invalid:3128" {
			t.Fatalf("output %q: proxy %q, want the initial URL kept", out, got)
		}
	}

	if runtime.GOOS == "windows" {
		return
	}
	for _, cmd := range []string{
		`printf %s 'socks5://user:SECRET@proxy.invalid:1'`,
		`echo 'http://user:SECRET@proxy.invalid:1' >&2; exit 1`,
		`echo 'http://user:SECRET@proxy.invalid:1'; kill -9 $$`,
	} {
		var errs errorLog
		r, err := NewResolver("http://initial.invalid:3128", WithRefreshCommand(cmd), errs.handler())
		if err != nil {
			t.Fatal(err)
		}
		all := errs.all()
		if len(all) != 1 {
			t.Fatalf("command %q: handler called %d times", cmd, len(all))
		}
		if strings.Contains(all[0].Error(), "SECRET") || strings.Contains(r.String(), "SECRET") {
			t.Fatalf("command %q leaked: %q / %q", cmd, all[0], r)
		}
		t.Logf("command %q: %v", cmd, all[0])
	}
}

func TestRefreshCommandTimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("refresh commands run with sh -c")
	}
	defer func(d time.Duration) { refreshTimeout = d }(refreshTimeout)
	refreshTimeout = 300 * time.Millisecond

	var errs errorLog
	start := time.Now()
	r, err := NewResolver("http://initial.invalid:3128", WithRefreshCommand("sleep 5; echo http://late.invalid:1"), errs.handler())
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("a hung command held NewResolver for %v", elapsed)
	}
	all := errs.all()
	if len(all) != 1 || all[0].Error() != "netproxy: refresh command timed out after 300ms" {
		t.Fatalf("errors = %v", all)
	}
	if got := proxyFor(t, r, "x.invalid:443"); got != "http://initial.invalid:3128" {
		t.Fatalf("proxy %q, want the initial URL", got)
	}
}

func TestNewResolverOptions(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	source := func(u string) Option {
		return WithRefreshFunc(func(context.Context) (string, error) {
			calls.Add(1)
			return u, nil
		})
	}

	// "off" ignores options; the source never runs.
	off, err := NewResolver("off", source("http://x.invalid:1"))
	if err != nil || off.Mode() != ModeOff || off.Enabled() || calls.Load() != 0 {
		t.Fatalf("off: %v %v, source ran %d times", off, err, calls.Load())
	}

	// An empty command is no refresh source at all.
	plain, err := NewResolver("http://u:p@proxy.invalid:1", WithRefreshCommand("  "), WithRefreshFunc(nil))
	if err != nil {
		t.Fatal(err)
	}
	if plain.refreshable() || plain.String() != "http://***@proxy.invalid:1" {
		t.Fatalf("empty command: refreshable=%v String=%q", plain.refreshable(), plain.String())
	}
	for _, r := range []*Resolver{nil, Off(), plain, mustExplicit(t, "http://p.invalid:1")} {
		if err := r.Refresh(context.Background()); err != nil {
			t.Fatalf("Refresh on %v = %v", r, err)
		}
	}

	// Explicit with a source: the source's URL replaces the given one.
	ex, err := NewResolver("http://old:pw@proxy.invalid:1", source("https://new:pw@proxy2.invalid:8443"))
	if err != nil {
		t.Fatal(err)
	}
	if ex.Mode() != ModeExplicit || proxyFor(t, ex, "localhost:1") != "https://new:pw@proxy2.invalid:8443" {
		t.Fatalf("explicit+source: mode %q proxy %q", ex.Mode(), proxyFor(t, ex, "localhost:1"))
	}
	if s := ex.String(); s != "https://***@proxy2.invalid:8443 (credentials refreshed by callback)" {
		t.Fatalf("String = %q", s)
	}

	// Auto with a source: its URL replaces the environment's, NO_PROXY and
	// the loopback exemption still apply.
	auto, err := newAuto(envMap(map[string]string{"HTTPS_PROXY": "http://env.invalid:1", "HTTP_PROXY": "http://envplain.invalid:1", "NO_PROXY": "skip.invalid"}),
		newOptions([]Option{source("http://u:pw@cmd.invalid:3128")}))
	if err != nil {
		t.Fatal(err)
	}
	for addr, want := range map[string]string{
		"x.invalid:443":    "http://u:pw@cmd.invalid:3128",
		"skip.invalid:443": "",
		"127.0.0.1:443":    "",
	} {
		if got := proxyFor(t, auto, addr); got != want {
			t.Fatalf("auto+source %s: proxy %q, want %q", addr, got, want)
		}
	}
	if got := proxyForURL(t, auto, "http://x.invalid/"); got != "http://u:pw@cmd.invalid:3128" {
		t.Fatalf("auto+source plain request: proxy %q", got)
	}
	if s := auto.String(); s != "auto: http://***@cmd.invalid:3128 (NO_PROXY=skip.invalid) (credentials refreshed by callback)" {
		t.Fatalf("String = %q", s)
	}

	// Auto with no proxy in the environment and a failing source: enabled
	// (the source may supply one later), dialing directly for now.
	var errs errorLog
	empty, err := newAuto(envMap(nil), newOptions([]Option{
		WithRefreshFunc(func(context.Context) (string, error) { return "", errors.New("not yet") }),
		errs.handler(),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !empty.Enabled() || proxyFor(t, empty, "x.invalid:443") != "" {
		t.Fatalf("auto without a proxy yet: enabled=%v", empty.Enabled())
	}
	if s := empty.String(); s != "auto: no proxy in environment (credentials refreshed by callback)" {
		t.Fatalf("String = %q", s)
	}
	if e := errs.all(); len(e) != 1 || e[0].Error() != "netproxy: proxy refresh: not yet" {
		t.Fatalf("errors = %v", e)
	}

	// Timed refreshes: within the interval lookups reuse the last reading;
	// after it, one lookup refreshes. A negative interval never does.
	var n atomic.Int32
	counting := WithRefreshFunc(func(context.Context) (string, error) {
		return fmt.Sprintf("http://p%d.invalid:1", n.Add(1)), nil
	})
	timed, err := NewResolver("http://p0.invalid:1", counting, WithRefreshInterval(200*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if got := proxyFor(t, timed, "x.invalid:443"); got != "http://p1.invalid:1" {
			t.Fatalf("within the interval: proxy %q", got)
		}
	}
	time.Sleep(250 * time.Millisecond)
	if got := proxyFor(t, timed, "x.invalid:443"); got != "http://p2.invalid:1" {
		t.Fatalf("after the interval: proxy %q", got)
	}
	n.Store(0)
	never, err := NewResolver("http://p0.invalid:1", counting, WithRefreshInterval(-1))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	for i := 0; i < 5; i++ {
		proxyFor(t, never, "x.invalid:443")
	}
	if n.Load() != 1 {
		t.Fatalf("negative interval: source ran %d times, want 1 (at build)", n.Load())
	}
}

// A caller that stops waiting does not cancel the refresh: it completes
// and its result is used.
func TestRefreshWaitHonoursContext(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	var n atomic.Int32
	r, err := NewResolver("http://p0.invalid:1", WithRefreshFunc(func(ctx context.Context) (string, error) {
		i := n.Add(1)
		if i > 1 {
			<-release
		}
		return fmt.Sprintf("http://p%d.invalid:1", i), nil
	}), WithRefreshInterval(-1))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := r.Refresh(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Refresh = %v, want the context's deadline", err)
	}
	if got := proxyFor(t, r, "x.invalid:443"); got != "http://p1.invalid:1" {
		t.Fatalf("while the refresh is in flight: proxy %q", got)
	}
	close(release)
	waitFor(t, "the abandoned refresh to land", func() bool {
		u, _ := r.ProxyForAddr("x.invalid:443")
		return u != nil && u.String() == "http://p2.invalid:1"
	})
	if n.Load() != 2 {
		t.Fatalf("source ran %d times, want 2", n.Load())
	}
}
