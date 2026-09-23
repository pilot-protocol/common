// SPDX-License-Identifier: AGPL-3.0-or-later

// Package netproxy routes outbound connections through an HTTP CONNECT proxy.
//
// It exists for hosts where the only way out is an egress proxy that allows
// "CONNECT host:443" (hosted agent sandboxes, locked-down corporate VMs):
// outbound UDP is blocked, direct TCP is killed, and local DNS for the target
// hostnames may be poisoned. Everything here therefore keeps the target as a
// HOSTNAME all the way to the proxy — nothing in this package resolves a
// target address locally — and TLS stays end-to-end between the caller and
// the real server (the proxy only ever sees an opaque tunnel).
//
// Two pieces:
//
//   - Resolver decides, per target, which proxy (if any) to use: an explicit
//     URL, the conventional environment variables (HTTPS_PROXY, ALL_PROXY,
//     NO_PROXY, ...), or none. The same decision is exposed as a per-address
//     lookup for raw TCP dials (ProxyForAddr) and as an http.Transport.Proxy
//     function (ProxyForRequest), so HTTP clients and raw TCP dials follow
//     identical rules.
//   - Dialer is a DialContext-compatible dialer that tunnels through the
//     proxy the Resolver picks, or dials directly when there is none.
//
// # Rotating credentials
//
// Some egress proxies (Meta Muse's, for one) rotate the credentials embedded
// in HTTPS_PROXY every few minutes. A fresh shell sees the current value; a
// long-running process keeps its launch-time copy and gets 407 Proxy
// Authentication Required on every new CONNECT, while tunnels it already
// opened stay up. A Resolver therefore re-reads its proxy settings:
//
//   - on a timer (DefaultRefreshInterval, see WithRefreshInterval): the
//     first lookup after the interval has passed starts a refresh in the
//     background and, like every lookup, answers from the settings in hand,
//     so a slow refresh never holds up a connection;
//   - immediately when a proxy rejects its credentials: Dialer and
//     RefreshingTransport then refresh once and retry once on a new
//     connection, and only when the refresh produced different credentials.
//
// A ModeAuto Resolver re-reads the process environment. WithRefreshCommand
// adds a command whose output is the current proxy URL, for processes whose
// own environment never changes; by convention programs take that command
// from EnvRefreshCommand (PILOT_PROXY_CMD). Concurrent rejections share one
// refresh, and a failed refresh keeps the last good settings.
//
// Proxy credentials (URL userinfo) are only ever written to the proxy in a
// Proxy-Authorization header. They never appear in errors or in the output
// of Redact / Resolver.String, which is what callers must use for logging.
// A refresh command's output is treated the same way and is never logged.
package netproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Mode names. Parse accepts ModeAuto and ModeOff (case-insensitive) in
// addition to an explicit proxy URL; Resolver.Mode reports one of the three.
const (
	// ModeAuto takes the proxy from the environment (see FromEnvironment).
	ModeAuto = "auto"
	// ModeOff never uses a proxy.
	ModeOff = "off"
	// ModeExplicit uses one explicitly configured proxy URL for every target.
	ModeExplicit = "explicit"
)

// Resolver decides which proxy, if any, an outbound connection to a given
// target should go through. A nil *Resolver is valid and never proxies.
// Resolvers are safe for concurrent use.
//
// Off and Explicit Resolvers without a refresh source never change. A
// ModeAuto Resolver, and any Resolver with a refresh source
// (WithRefreshCommand, WithRefreshFunc), re-reads its settings over time;
// see the package documentation under "Rotating credentials".
type Resolver struct {
	mode string

	// getenv is the environment a ModeAuto Resolver reads (os.Getenv
	// outside tests).
	getenv func(string) string
	// source, when set, supplies the current proxy URL; command reports
	// that it runs a shell command (for String).
	source  func(context.Context) (string, error)
	command bool
	// interval is the refresh TTL; negative disables timed refreshes.
	interval time.Duration
	// onError receives the first error of each run of failed refreshes.
	onError func(error)

	// state holds the current settings. Refreshes replace it whole, so a
	// lookup always sees one consistent set.
	state atomic.Pointer[proxyState]

	mu sync.Mutex // guards the fields below
	// inflight is the refresh in progress, which every caller joins.
	inflight *refreshCall
	// attempts counts refreshes started. A caller notes it before picking
	// a proxy; if it has moved when the proxy then rejects the
	// credentials, a refresh already ran after the pick and running
	// another one right away cannot learn anything newer.
	attempts uint64
	// lastRun is when the last refresh finished (or the Resolver was built).
	lastRun time.Time
	// failing is set while refreshes keep failing, so onError hears about
	// a run of failures once.
	failing bool
}

// proxyState is one reading of a Resolver's settings.
type proxyState struct {
	// fixed is the proxy for every target in ModeExplicit, and in ModeAuto
	// the proxy URL from the refresh source, which then replaces the
	// environment's proxy URLs (NO_PROXY still applies).
	fixed *url.URL

	// ModeAuto: proxy for TLS / opaque TCP targets (HTTPS_PROXY, https_proxy,
	// ALL_PROXY, all_proxy) and the optional override for plain-HTTP request
	// URLs (HTTP_PROXY, http_proxy). noProxy lists the bypassed targets.
	secure  *url.URL
	plain   *url.URL
	noProxy noProxy
	// noProxyRaw is kept only for String().
	noProxyRaw string
	// warnings lists the proxy variables that were set but skipped because
	// their values are unusable (*EnvError each).
	warnings []error
}

var emptyState proxyState

// EnvError reports a proxy environment variable whose value cannot be used.
// Its message names the variable and never includes the value's
// credentials.
type EnvError struct {
	// Var is the environment variable, e.g. "HTTP_PROXY".
	Var string
	// Err says why the value is unusable.
	Err error
}

func (e *EnvError) Error() string { return e.Var + ": " + e.Err.Error() }

func (e *EnvError) Unwrap() error { return e.Err }

// Off returns a Resolver that never uses a proxy.
func Off() *Resolver { return &Resolver{mode: ModeOff} }

// Explicit returns a Resolver that sends every target — including loopback
// and anything NO_PROXY would exempt — through proxyURL. The URL must use
// the http or https scheme ("http://[user:pass@]host[:port]"); a URL with no
// scheme is taken as http. The port defaults to 80 for http and 443 for
// https. Everything up to the last "@" is the userinfo, so credentials may
// hold unescaped '/', '?', '#' or '@'; percent-escapes in them are decoded.
//
// The Resolver never changes; NewResolver with WithRefreshCommand builds
// one whose credentials follow a refresh source.
func Explicit(proxyURL string) (*Resolver, error) {
	return newExplicit(proxyURL, options{})
}

func newExplicit(proxyURL string, o options) (*Resolver, error) {
	if strings.TrimSpace(proxyURL) == "" {
		return nil, errors.New("netproxy: empty proxy URL")
	}
	u, err := parseProxyURL(proxyURL)
	if err != nil {
		return nil, err
	}
	r := &Resolver{mode: ModeExplicit}
	r.state.Store(&proxyState{fixed: u})
	r.configure(o)
	return r, nil
}

// FromEnvironment returns a Resolver built from the conventional proxy
// environment variables:
//
//   - TLS and raw TCP targets (ProxyForAddr, and https:// / wss:// requests)
//     use the first usable one of HTTPS_PROXY, https_proxy, ALL_PROXY,
//     all_proxy.
//   - Plain http:// / ws:// requests use the first usable one of HTTP_PROXY,
//     http_proxy, and otherwise the same proxy as TLS targets. HTTP_PROXY
//     (upper case) is ignored when REQUEST_METHOD is set, as net/http does,
//     so a CGI request header cannot inject a proxy.
//   - NO_PROXY / no_proxy exempts targets: a comma- or space-separated list
//     of host names (matching the name and its subdomains; a leading "." or
//     "*." matches subdomains only), IP addresses, CIDR ranges, each
//     optionally with ":port", or "*" for everything. localhost and loopback
//     addresses are always exempt.
//
// Each variable is parsed on its own, so one bad value never disables
// another. A value is unusable when it is malformed or names a scheme other
// than http or https (socks5://, for example). An unusable HTTP_PROXY,
// http_proxy, ALL_PROXY or all_proxy is skipped (the next variable in its
// list applies) and reported by Warnings. Only an unusable HTTPS_PROXY or
// https_proxy, which explicitly names the TLS proxy, makes FromEnvironment
// fail, with an *EnvError naming it.
//
// The variables are read now, and read again at most every
// DefaultRefreshInterval and whenever a proxy rejects the credentials (see
// Refresh), so a process whose environment is updated in place follows it.
// A later reading that fails keeps the previous one.
//
// An environment with no usable proxy variables yields a Resolver that
// does not proxy (Enabled reports false). Neither errors nor warnings ever
// echo a value's credentials.
func FromEnvironment() (*Resolver, error) {
	return newAuto(os.Getenv, options{})
}

func fromEnv(getenv func(string) string) (*Resolver, error) {
	return newAuto(getenv, options{})
}

func newAuto(getenv func(string) string, o options) (*Resolver, error) {
	st, err := readEnv(getenv)
	if err != nil {
		return nil, err
	}
	r := &Resolver{mode: ModeAuto, getenv: getenv}
	r.state.Store(st)
	r.configure(o)
	return r, nil
}

// readEnv reads the ModeAuto settings from the environment.
func readEnv(getenv func(string) string) (*proxyState, error) {
	st := &proxyState{}
	for _, name := range []string{"HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"} {
		u, err := envProxy(getenv, name)
		if err != nil {
			if name == "HTTPS_PROXY" || name == "https_proxy" {
				return nil, err
			}
			st.warnings = append(st.warnings, err)
			continue
		}
		if u != nil {
			st.secure = u
			break
		}
	}
	plainVars := []string{"HTTP_PROXY", "http_proxy"}
	if getenv("REQUEST_METHOD") != "" {
		plainVars = plainVars[1:]
	}
	for _, name := range plainVars {
		u, err := envProxy(getenv, name)
		if err != nil {
			st.warnings = append(st.warnings, err)
			continue
		}
		if u != nil {
			st.plain = u
			break
		}
	}
	st.noProxyRaw, _ = firstEnv(getenv, "NO_PROXY", "no_proxy")
	st.noProxy = parseNoProxy(st.noProxyRaw)
	return st, nil
}

// envProxy parses one proxy variable: nil, nil when it is unset or blank,
// and an *EnvError when its value is unusable.
func envProxy(getenv func(string) string, name string) (*url.URL, error) {
	raw := strings.TrimSpace(getenv(name))
	if raw == "" {
		return nil, nil
	}
	u, err := parseProxyURL(raw)
	if err != nil {
		return nil, &EnvError{Var: name, Err: err}
	}
	return u, nil
}

// Warnings reports the proxy environment variables the current reading of
// the environment skipped because their values are unusable, one *EnvError
// per variable, in precedence order. It is empty for Resolvers that do not
// read the environment. The messages are safe to log.
func (r *Resolver) Warnings() []error {
	st := r.snapshot()
	if len(st.warnings) == 0 {
		return nil
	}
	return append([]error(nil), st.warnings...)
}

// Parse builds a Resolver from a -proxy style setting: "auto" (or "") reads
// the environment via FromEnvironment, "off" disables proxying, and anything
// else is an explicit proxy URL (see Explicit). Deciding whether "auto"
// applies at all (for example only in a TCP-only transport mode) is the
// caller's policy; compare the setting against ModeAuto for that.
//
// Parse(spec) is NewResolver(spec) without options.
func Parse(spec string) (*Resolver, error) {
	return NewResolver(spec)
}

// NewResolver is Parse with options, for example a refresh command for
// proxies that rotate their credentials:
//
//	r, err := netproxy.NewResolver(spec,
//		netproxy.WithRefreshCommand(os.Getenv(netproxy.EnvRefreshCommand)),
//		netproxy.WithRefreshErrorHandler(func(err error) {
//			slog.Warn("proxy credential refresh failed", "err", err)
//		}))
//
// Options do not apply to "off". With a refresh source, NewResolver runs it
// once before returning; if that run fails, the Resolver starts from the
// environment ("auto") or the given URL, and the error goes to the
// WithRefreshErrorHandler function.
func NewResolver(spec string, opts ...Option) (*Resolver, error) {
	o := newOptions(opts)
	s := strings.TrimSpace(spec)
	switch strings.ToLower(s) {
	case "", ModeAuto:
		return newAuto(os.Getenv, o)
	case ModeOff:
		return Off(), nil
	}
	return newExplicit(s, o)
}

// Mode reports ModeAuto, ModeOff or ModeExplicit. A nil Resolver is ModeOff.
func (r *Resolver) Mode() string {
	if r == nil || r.mode == "" {
		return ModeOff
	}
	return r.mode
}

// Enabled reports whether the Resolver can route any target through a proxy.
// It is false for Off, for a nil Resolver and for an environment without
// proxy variables. A Resolver with a refresh source reports true: the
// source can supply a proxy at any time.
func (r *Resolver) Enabled() bool {
	if r == nil {
		return false
	}
	switch r.mode {
	case ModeExplicit, ModeAuto:
		return r.source != nil || r.snapshot().proxies()
	}
	return false
}

// proxies reports whether st routes anything through a proxy.
func (st *proxyState) proxies() bool {
	return st.fixed != nil || st.secure != nil || st.plain != nil
}

// String describes the Resolver for logs, with credentials redacted, e.g.
// "off", "http://***@proxy.internal:3128" or
// "auto: http://***@proxy.internal:3128 (NO_PROXY=localhost,.corp)".
// Resolvers with a refresh source add " (credentials refreshed by
// command)" or " (credentials refreshed by callback)".
func (r *Resolver) String() string {
	st := r.snapshot()
	switch r.Mode() {
	case ModeExplicit:
		return Redact(st.fixed) + r.refreshSuffix()
	case ModeAuto:
		if !st.proxies() {
			return "auto: no proxy in environment" + st.ignoredSuffix() + r.refreshSuffix()
		}
		var s string
		switch {
		case st.fixed != nil:
			s = "auto: " + Redact(st.fixed)
		case st.secure == nil:
			s = "auto: http-only " + Redact(st.plain)
		default:
			s = "auto: " + Redact(st.secure)
			if st.plain != nil && Redact(st.plain) != Redact(st.secure) {
				s += ", http " + Redact(st.plain)
			}
		}
		if st.noProxyRaw != "" {
			s += " (NO_PROXY=" + st.noProxyRaw + ")"
		}
		return s + st.ignoredSuffix() + r.refreshSuffix()
	}
	return ModeOff
}

func (r *Resolver) refreshSuffix() string {
	switch {
	case r.source == nil:
		return ""
	case r.command:
		return " (credentials refreshed by command)"
	}
	return " (credentials refreshed by callback)"
}

// ignoredSuffix names the skipped variables for String, e.g.
// " (ignored unusable HTTP_PROXY, ALL_PROXY)".
func (st *proxyState) ignoredSuffix() string {
	if len(st.warnings) == 0 {
		return ""
	}
	names := make([]string, 0, len(st.warnings))
	for _, w := range st.warnings {
		var ee *EnvError
		if errors.As(w, &ee) {
			names = append(names, ee.Var)
		}
	}
	return " (ignored unusable " + strings.Join(names, ", ") + ")"
}

// ProxyForAddr returns the proxy to tunnel a raw TCP (or TLS) connection to
// addr ("host:port") through, or nil to dial directly. addr is inspected as
// text only; host names are never resolved. When the refresh interval has
// passed, the lookup starts a refresh in the background (see
// WithRefreshInterval) and answers from the current settings; it never
// waits for a refresh.
func (r *Resolver) ProxyForAddr(addr string) (*url.URL, error) {
	// current first: a refresh can turn proxying on (a variable set in
	// place, a refresh source's first URL).
	st := r.current()
	if !st.proxies() {
		return nil, nil
	}
	return r.pickAddr(st, addr)
}

// pickAddr applies st to a raw TCP target.
func (r *Resolver) pickAddr(st *proxyState, addr string) (*url.URL, error) {
	if r.mode == ModeExplicit {
		return cloneURL(st.fixed), nil
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("netproxy: invalid target address %q: %w", addr, err)
	}
	return cloneURL(st.pick(host, port, true)), nil
}

// ProxyForRequest returns the proxy for req, or nil for a direct connection.
// Its signature matches http.Transport.Proxy:
//
//	tr.Proxy = resolver.ProxyForRequest
//
// https:// and wss:// requests follow exactly the same rules as ProxyForAddr
// (net/http then tunnels them with CONNECT, sending the host name); http://
// and ws:// requests prefer HTTP_PROXY in ModeAuto. The result is always
// the current proxy URL, and like ProxyForAddr the lookup never waits for a
// refresh; RefreshingTransport also retries a request once when the proxy
// rejects the credentials.
func (r *Resolver) ProxyForRequest(req *http.Request) (*url.URL, error) {
	if req == nil || req.URL == nil {
		return nil, nil
	}
	st := r.current()
	if !st.proxies() {
		return nil, nil
	}
	return r.pickRequest(st, req), nil
}

// pickRequest applies st to an HTTP request.
func (r *Resolver) pickRequest(st *proxyState, req *http.Request) *url.URL {
	if r.mode == ModeExplicit {
		return cloneURL(st.fixed)
	}
	secure := true
	defaultPort := "443"
	switch strings.ToLower(req.URL.Scheme) {
	case "http", "ws":
		secure = false
		defaultPort = "80"
	}
	port := req.URL.Port()
	if port == "" {
		port = defaultPort
	}
	return cloneURL(st.pick(req.URL.Hostname(), port, secure))
}

// pick applies the ModeAuto rules to one target.
func (st *proxyState) pick(host, port string, secure bool) *url.URL {
	proxy := st.secure
	switch {
	case st.fixed != nil:
		proxy = st.fixed
	case !secure && st.plain != nil:
		proxy = st.plain
	}
	if proxy == nil || !st.noProxy.useProxy(host, port) {
		return nil
	}
	return proxy
}

// Redact renders a proxy URL for logging as scheme://host:port, replacing
// any userinfo (user name and password alike) with "***" and dropping the
// path, query and fragment. Redact(nil) is "".
//
// A URL with "@" in its path, query, fragment or opaque part is taken to be
// a proxy URL whose credentials held an unescaped '/', '?' or '#', which
// url.Parse splits so that part of the credentials lands in Host. Redact
// then withholds everything before the last "@" and shows only what follows
// it as the host.
func Redact(u *url.URL) string {
	if u == nil {
		return ""
	}
	var b strings.Builder
	if u.Scheme != "" {
		b.WriteString(u.Scheme)
		b.WriteString("://")
	}
	if tail := u.Opaque + u.Path + "?" + u.RawQuery + "#" + u.Fragment; strings.Contains(tail, "@") {
		host := tail[strings.LastIndex(tail, "@")+1:]
		if i := strings.IndexAny(host, "/?#"); i >= 0 {
			host = host[:i]
		}
		b.WriteString("***@")
		b.WriteString(host)
		return b.String()
	}
	if u.User != nil {
		b.WriteString("***@")
	}
	b.WriteString(u.Host)
	return b.String()
}

// errWithheld is the parse error for a proxy URL with credentials: the
// value is never echoed.
var errWithheld = errors.New("netproxy: invalid proxy URL (value withheld: it contains credentials)")

// parseProxyURL validates a proxy URL. Errors never include credentials.
//
// The userinfo is split off by hand at the LAST "@" rather than by
// url.Parse, which ends the authority at the first '/', '?' or '#'. Proxy
// credentials are often tokens that contain those characters unescaped
// (base64 uses '/'); url.Parse would take part of such a token as the proxy
// host, which then shows up in logs and errors and is looked up in DNS.
// Here everything before the last "@" is credentials, and is only ever
// percent-decoded and sent in Proxy-Authorization.
func parseProxyURL(raw string) (*url.URL, error) {
	s := strings.TrimSpace(raw)
	scheme, rest, ok := strings.Cut(s, "://")
	if !ok || !validScheme(scheme) {
		// "proxy.internal:3128" / "user:pass@proxy:3128": the scheme is
		// conventionally optional and means http.
		scheme, rest = "http", s
	}
	scheme = strings.ToLower(scheme)
	switch scheme {
	case "http", "https":
	default:
		if strings.Contains(rest, "@") && !knownScheme[scheme] {
			// The "scheme" could be a user name ("user://pass@host").
			return nil, errors.New("netproxy: unsupported proxy scheme (want http or https)")
		}
		return nil, fmt.Errorf("netproxy: unsupported proxy scheme %q (want http or https)", scheme)
	}

	var user *url.Userinfo
	hostPart := rest
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		var err error
		if user, err = parseUserinfo(rest[:at]); err != nil {
			return nil, err
		}
		hostPart = rest[at+1:]
	}
	// hostPart holds no credentials: everything up to the last "@" is gone.
	u, err := url.Parse(scheme + "://" + hostPart)
	if err != nil {
		if user != nil {
			return nil, errWithheld
		}
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, fmt.Errorf("netproxy: invalid proxy URL: %v", err)
	}
	u.User = user
	if u.Hostname() == "" {
		return nil, fmt.Errorf("netproxy: proxy URL %s has no host", Redact(u))
	}
	return u, nil
}

// parseUserinfo decodes "user[:password]" (percent-escapes allowed, other
// characters taken literally). The error never includes the value. An
// empty userinfo ("http://@proxy") means no credentials.
func parseUserinfo(s string) (*url.Userinfo, error) {
	if s == "" {
		return nil, nil
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < ' ' || c == 0x7f {
			return nil, errWithheld
		}
	}
	name, password, hasPassword := strings.Cut(s, ":")
	name, err := url.PathUnescape(name)
	if err != nil {
		return nil, errWithheld
	}
	if !hasPassword {
		return url.User(name), nil
	}
	if password, err = url.PathUnescape(password); err != nil {
		return nil, errWithheld
	}
	return url.UserPassword(name, password), nil
}

// validScheme reports whether s is a syntactically valid URL scheme
// (RFC 3986: ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )).
func validScheme(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z':
		case i > 0 && ('0' <= c && c <= '9' || c == '+' || c == '-' || c == '.'):
		default:
			return false
		}
	}
	return true
}

// knownScheme lists schemes that are safe to echo in an error even when
// the value carries credentials.
var knownScheme = map[string]bool{
	"socks": true, "socks4": true, "socks4a": true, "socks5": true, "socks5h": true,
	"ftp": true, "ws": true, "wss": true, "quic": true, "h2": true, "file": true,
}

// proxyHostPort is the address to dial for the proxy itself, with the
// scheme's default port filled in.
func proxyHostPort(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	return net.JoinHostPort(u.Hostname(), port)
}

func firstEnv(getenv func(string) string, names ...string) (value, name string) {
	for _, n := range names {
		if v := strings.TrimSpace(getenv(n)); v != "" {
			return v, n
		}
	}
	return "", ""
}

// cloneURL returns a copy so callers cannot mutate the Resolver's URLs.
// url.Userinfo is immutable, so a shallow copy is enough.
func cloneURL(u *url.URL) *url.URL {
	if u == nil {
		return nil
	}
	c := *u
	return &c
}
