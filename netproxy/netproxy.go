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
}

// Off returns a Resolver that never uses a proxy.
func Off() *Resolver { return &Resolver{mode: ModeOff} }

// Explicit returns a Resolver that sends every target — including loopback
// and anything NO_PROXY would exempt — through proxyURL. The URL must use
// the http or https scheme ("http://[user:pass@]host[:port]"); a URL with no
// scheme is taken as http. The port defaults to 80 for http and 443 for
// https.
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
//     use the first non-empty of HTTPS_PROXY, https_proxy, ALL_PROXY,
//     all_proxy.
//   - Plain http:// / ws:// requests use HTTP_PROXY or http_proxy when set,
//     and otherwise the same proxy as TLS targets. HTTP_PROXY (upper case) is
//     ignored when REQUEST_METHOD is set, as net/http does, so a CGI request
//     header cannot inject a proxy.
//   - NO_PROXY / no_proxy exempts targets: a comma- or space-separated list
//     of host names (matching the name and its subdomains; a leading "." or
//     "*." matches subdomains only), IP addresses, CIDR ranges, each
//     optionally with ":port", or "*" for everything. localhost and loopback
//     addresses are always exempt.
//
// An environment with no proxy variables yields a Resolver that never
// proxies (Enabled reports false). A malformed proxy URL is an error that
// never echoes the URL's credentials.
func FromEnvironment() (*Resolver, error) {
	return fromEnv(os.Getenv)
}

func fromEnv(getenv func(string) string) (*Resolver, error) {
	r := &Resolver{mode: ModeAuto}
	secureRaw, secureVar := firstEnv(getenv, "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy")
	if secureRaw != "" {
		u, err := parseProxyURL(secureRaw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", secureVar, err)
		}
		r.secure = u
	}
	plainVars := []string{"HTTP_PROXY", "http_proxy"}
	if getenv("REQUEST_METHOD") != "" {
		plainVars = plainVars[1:]
	}
	if plainRaw, plainVar := firstEnv(getenv, plainVars...); plainRaw != "" {
		u, err := parseProxyURL(plainRaw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", plainVar, err)
		}
		r.plain = u
	}
	r.noProxyRaw, _ = firstEnv(getenv, "NO_PROXY", "no_proxy")
	r.noProxy = parseNoProxy(r.noProxyRaw)
	return r, nil
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
			return "auto: no proxy in environment"
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
		return s
	}
	return ModeOff
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
func Redact(u *url.URL) string {
	if u == nil {
		return ""
	}
	var b strings.Builder
	if u.Scheme != "" {
		b.WriteString(u.Scheme)
		b.WriteString("://")
	}
	if u.User != nil {
		b.WriteString("***@")
	}
	b.WriteString(u.Host)
	return b.String()
}

// parseProxyURL validates a proxy URL. Errors never include the raw value
// when it could carry credentials.
func parseProxyURL(raw string) (*url.URL, error) {
	s := strings.TrimSpace(raw)
	if !strings.Contains(s, "://") {
		// "proxy.internal:3128" / "user:pass@proxy:3128": the scheme is
		// conventionally optional and means http.
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		if strings.Contains(s, "@") {
			return nil, errors.New("netproxy: invalid proxy URL (value withheld: it contains credentials)")
		}
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, fmt.Errorf("netproxy: invalid proxy URL: %v", err)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	switch u.Scheme {
	case "http", "https":
	default:
		return nil, fmt.Errorf("netproxy: unsupported proxy scheme %q (want http or https)", u.Scheme)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("netproxy: proxy URL %s has no host", Redact(u))
	}
	return u, nil
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
