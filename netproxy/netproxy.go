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
// Proxy credentials (URL userinfo) are only ever written to the proxy in a
// Proxy-Authorization header. They never appear in errors or in the output
// of Redact / Resolver.String, which is what callers must use for logging.
package netproxy

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
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
// Resolvers are immutable and safe for concurrent use.
type Resolver struct {
	mode string

	// fixed is the proxy for every target in ModeExplicit.
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
func Explicit(proxyURL string) (*Resolver, error) {
	if strings.TrimSpace(proxyURL) == "" {
		return nil, errors.New("netproxy: empty proxy URL")
	}
	u, err := parseProxyURL(proxyURL)
	if err != nil {
		return nil, err
	}
	return &Resolver{mode: ModeExplicit, fixed: u}, nil
}

// FromEnvironment returns a Resolver built from a snapshot of the
// conventional proxy environment variables, taken now:
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
// An environment with no usable proxy variables yields a Resolver that
// never proxies (Enabled reports false). Neither errors nor warnings ever
// echo a value's credentials.
func FromEnvironment() (*Resolver, error) {
	return fromEnv(os.Getenv)
}

func fromEnv(getenv func(string) string) (*Resolver, error) {
	r := &Resolver{mode: ModeAuto}
	for _, name := range []string{"HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"} {
		u, err := envProxy(getenv, name)
		if err != nil {
			if name == "HTTPS_PROXY" || name == "https_proxy" {
				return nil, err
			}
			r.warnings = append(r.warnings, err)
			continue
		}
		if u != nil {
			r.secure = u
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
			r.warnings = append(r.warnings, err)
			continue
		}
		if u != nil {
			r.plain = u
			break
		}
	}
	r.noProxyRaw, _ = firstEnv(getenv, "NO_PROXY", "no_proxy")
	r.noProxy = parseNoProxy(r.noProxyRaw)
	return r, nil
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

// Warnings reports the proxy environment variables FromEnvironment skipped
// because their values are unusable, one *EnvError per variable, in
// precedence order. It is empty for other Resolvers. The messages are safe
// to log.
func (r *Resolver) Warnings() []error {
	if r == nil || len(r.warnings) == 0 {
		return nil
	}
	return append([]error(nil), r.warnings...)
}

// Parse builds a Resolver from a -proxy style setting: "auto" (or "") reads
// the environment via FromEnvironment, "off" disables proxying, and anything
// else is an explicit proxy URL (see Explicit). Deciding whether "auto"
// applies at all (for example only in a TCP-only transport mode) is the
// caller's policy; compare the setting against ModeAuto for that.
func Parse(spec string) (*Resolver, error) {
	s := strings.TrimSpace(spec)
	switch strings.ToLower(s) {
	case "", ModeAuto:
		return FromEnvironment()
	case ModeOff:
		return Off(), nil
	}
	return Explicit(s)
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
// proxy variables.
func (r *Resolver) Enabled() bool {
	if r == nil {
		return false
	}
	switch r.mode {
	case ModeExplicit:
		return r.fixed != nil
	case ModeAuto:
		return r.secure != nil || r.plain != nil
	}
	return false
}

// String describes the Resolver for logs, with credentials redacted, e.g.
// "off", "http://***@proxy.internal:3128" or
// "auto: http://***@proxy.internal:3128 (NO_PROXY=localhost,.corp)".
func (r *Resolver) String() string {
	switch r.Mode() {
	case ModeExplicit:
		return Redact(r.fixed)
	case ModeAuto:
		if !r.Enabled() {
			return "auto: no proxy in environment" + r.ignoredSuffix()
		}
		s := "auto: " + Redact(r.secure)
		if r.secure == nil {
			s = "auto: http-only " + Redact(r.plain)
		} else if r.plain != nil && Redact(r.plain) != Redact(r.secure) {
			s += ", http " + Redact(r.plain)
		}
		if r.noProxyRaw != "" {
			s += " (NO_PROXY=" + r.noProxyRaw + ")"
		}
		return s + r.ignoredSuffix()
	}
	return ModeOff
}

// ignoredSuffix names the skipped variables for String, e.g.
// " (ignored unusable HTTP_PROXY, ALL_PROXY)".
func (r *Resolver) ignoredSuffix() string {
	if len(r.warnings) == 0 {
		return ""
	}
	names := make([]string, 0, len(r.warnings))
	for _, w := range r.warnings {
		var ee *EnvError
		if errors.As(w, &ee) {
			names = append(names, ee.Var)
		}
	}
	return " (ignored unusable " + strings.Join(names, ", ") + ")"
}

// ProxyForAddr returns the proxy to tunnel a raw TCP (or TLS) connection to
// addr ("host:port") through, or nil to dial directly. addr is inspected as
// text only; host names are never resolved.
func (r *Resolver) ProxyForAddr(addr string) (*url.URL, error) {
	if !r.Enabled() {
		return nil, nil
	}
	if r.mode == ModeExplicit {
		return cloneURL(r.fixed), nil
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("netproxy: invalid target address %q: %w", addr, err)
	}
	return cloneURL(r.pick(host, port, true)), nil
}

// ProxyForRequest returns the proxy for req, or nil for a direct connection.
// Its signature matches http.Transport.Proxy:
//
//	tr.Proxy = resolver.ProxyForRequest
//
// https:// and wss:// requests follow exactly the same rules as ProxyForAddr
// (net/http then tunnels them with CONNECT, sending the host name); http://
// and ws:// requests prefer HTTP_PROXY in ModeAuto.
func (r *Resolver) ProxyForRequest(req *http.Request) (*url.URL, error) {
	if !r.Enabled() || req == nil || req.URL == nil {
		return nil, nil
	}
	if r.mode == ModeExplicit {
		return cloneURL(r.fixed), nil
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
	return cloneURL(r.pick(req.URL.Hostname(), port, secure)), nil
}

// pick applies the ModeAuto rules to one target.
func (r *Resolver) pick(host, port string, secure bool) *url.URL {
	proxy := r.secure
	if !secure && r.plain != nil {
		proxy = r.plain
	}
	if proxy == nil || !r.noProxy.useProxy(host, port) {
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
