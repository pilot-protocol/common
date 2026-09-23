// SPDX-License-Identifier: AGPL-3.0-or-later

package netproxy

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func proxyFor(t *testing.T, r *Resolver, addr string) string {
	t.Helper()
	u, err := r.ProxyForAddr(addr)
	if err != nil {
		t.Fatalf("ProxyForAddr(%q): %v", addr, err)
	}
	if u == nil {
		return ""
	}
	return u.String()
}

func proxyForURL(t *testing.T, r *Resolver, rawURL string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("NewRequest(%q): %v", rawURL, err)
	}
	u, err := r.ProxyForRequest(req)
	if err != nil {
		t.Fatalf("ProxyForRequest(%q): %v", rawURL, err)
	}
	if u == nil {
		return ""
	}
	return u.String()
}

func TestFromEnvPrecedence(t *testing.T) {
	t.Parallel()
	const target = "registry.pilotprotocol.network:443"
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"none", map[string]string{}, ""},
		{"HTTPS_PROXY", map[string]string{"HTTPS_PROXY": "http://a:1", "https_proxy": "http://b:1", "ALL_PROXY": "http://c:1"}, "http://a:1"},
		{"https_proxy", map[string]string{"https_proxy": "http://b:1", "ALL_PROXY": "http://c:1"}, "http://b:1"},
		{"ALL_PROXY fallback", map[string]string{"ALL_PROXY": "http://c:1", "all_proxy": "http://d:1"}, "http://c:1"},
		{"all_proxy fallback", map[string]string{"all_proxy": "http://d:1"}, "http://d:1"},
		{"blank values skipped", map[string]string{"HTTPS_PROXY": "  ", "all_proxy": "http://d:1"}, "http://d:1"},
		{"HTTP_PROXY alone does not cover TCP/TLS targets", map[string]string{"HTTP_PROXY": "http://h:1"}, ""},
		{"scheme-less value means http", map[string]string{"HTTPS_PROXY": "proxy.internal:3128"}, "http://proxy.internal:3128"},
	}
	for _, tc := range cases {
		r, err := fromEnv(envMap(tc.env))
		if err != nil {
			t.Fatalf("%s: fromEnv: %v", tc.name, err)
		}
		if r.Mode() != ModeAuto {
			t.Fatalf("%s: mode %q", tc.name, r.Mode())
		}
		if got := proxyFor(t, r, target); got != tc.want {
			t.Fatalf("%s: ProxyForAddr = %q, want %q", tc.name, got, tc.want)
		}
		if got := proxyForURL(t, r, "https://"+target+"/x"); got != tc.want {
			t.Fatalf("%s: ProxyForRequest(https) = %q, want %q", tc.name, got, tc.want)
		}
		if got := proxyForURL(t, r, "wss://"+target+"/x"); got != tc.want {
			t.Fatalf("%s: ProxyForRequest(wss) = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestFromEnvPlainHTTPRequests(t *testing.T) {
	t.Parallel()
	r, err := fromEnv(envMap(map[string]string{"HTTPS_PROXY": "http://secure:1", "HTTP_PROXY": "http://plain:1"}))
	if err != nil {
		t.Fatal(err)
	}
	if got := proxyForURL(t, r, "http://example.pilot.invalid/"); got != "http://plain:1" {
		t.Fatalf("http:// request proxy = %q, want HTTP_PROXY", got)
	}
	if got := proxyForURL(t, r, "ws://example.pilot.invalid/"); got != "http://plain:1" {
		t.Fatalf("ws:// request proxy = %q, want HTTP_PROXY", got)
	}
	if got := proxyForURL(t, r, "https://example.pilot.invalid/"); got != "http://secure:1" {
		t.Fatalf("https:// request proxy = %q, want HTTPS_PROXY", got)
	}

	// Without HTTP_PROXY, plain requests share the TLS proxy: in a sandbox
	// where direct egress is killed, "no proxy" is never the safer default.
	r, _ = fromEnv(envMap(map[string]string{"HTTPS_PROXY": "http://secure:1"}))
	if got := proxyForURL(t, r, "http://example.pilot.invalid/"); got != "http://secure:1" {
		t.Fatalf("http:// request proxy = %q, want the HTTPS_PROXY fallback", got)
	}

	// CGI: a request header can set HTTP_PROXY, so it is ignored when
	// REQUEST_METHOD is present; lower-case http_proxy still counts.
	r, _ = fromEnv(envMap(map[string]string{"REQUEST_METHOD": "GET", "HTTP_PROXY": "http://evil:1"}))
	if r.Enabled() {
		t.Fatalf("HTTP_PROXY honoured under CGI: %s", r)
	}
	r, _ = fromEnv(envMap(map[string]string{"REQUEST_METHOD": "GET", "HTTP_PROXY": "http://evil:1", "http_proxy": "http://ok:1"}))
	if got := proxyForURL(t, r, "http://example.pilot.invalid/"); got != "http://ok:1" {
		t.Fatalf("CGI http_proxy = %q", got)
	}
}

func TestFromEnvironmentReadsProcessEnv(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://user:pw@proxy.pilot.invalid:3128")
	t.Setenv("NO_PROXY", ".internal")
	r, err := FromEnvironment()
	if err != nil {
		t.Fatalf("FromEnvironment: %v", err)
	}
	if got := proxyFor(t, r, "registry.pilotprotocol.network:443"); got != "http://user:pw@proxy.pilot.invalid:3128" {
		t.Fatalf("proxy = %q", got)
	}
	if got := proxyFor(t, r, "db.internal:5432"); got != "" {
		t.Fatalf("NO_PROXY target proxied via %q", got)
	}
	// Parse("auto") and Parse("") are the same thing.
	for _, spec := range []string{"auto", "AUTO", " auto ", ""} {
		p, err := Parse(spec)
		if err != nil || p.Mode() != ModeAuto || !p.Enabled() {
			t.Fatalf("Parse(%q) = %v, %v", spec, p, err)
		}
	}
}

func TestAutoAlwaysBypassesLoopback(t *testing.T) {
	t.Parallel()
	r, _ := fromEnv(envMap(map[string]string{"HTTPS_PROXY": "http://p:1"}))
	for _, addr := range []string{"localhost:443", "LOCALHOST:1", "127.0.0.1:9000", "127.9.9.9:1", "[::1]:443"} {
		if got := proxyFor(t, r, addr); got != "" {
			t.Fatalf("%s proxied via %q", addr, got)
		}
	}
	if got := proxyFor(t, r, "10.0.0.1:443"); got != "http://p:1" {
		t.Fatalf("non-loopback IP not proxied: %q", got)
	}
}

func TestExplicitProxiesEverything(t *testing.T) {
	t.Parallel()
	r := mustExplicit(t, "http://user:pw@proxy.internal:3128")
	if r.Mode() != ModeExplicit || !r.Enabled() {
		t.Fatalf("mode %q enabled %v", r.Mode(), r.Enabled())
	}
	for _, addr := range []string{"registry.pilotprotocol.network:443", "localhost:1", "127.0.0.1:9000"} {
		if got := proxyFor(t, r, addr); got != "http://user:pw@proxy.internal:3128" {
			t.Fatalf("%s: proxy %q", addr, got)
		}
	}
	if got := proxyForURL(t, r, "http://plain.pilot.invalid/"); got != "http://user:pw@proxy.internal:3128" {
		t.Fatalf("plain request: proxy %q", got)
	}
	// Returned URLs are copies.
	u, _ := r.ProxyForAddr("a.invalid:1")
	u.Host = "mutated:1"
	if got := proxyFor(t, r, "a.invalid:1"); !strings.Contains(got, "proxy.internal:3128") {
		t.Fatalf("resolver state mutated through a returned URL: %q", got)
	}
}

func TestOffAndNilNeverProxy(t *testing.T) {
	t.Parallel()
	var nilResolver *Resolver
	off, err := Parse(" OFF ")
	if err != nil {
		t.Fatal(err)
	}
	for name, r := range map[string]*Resolver{"nil": nilResolver, "Off()": Off(), "Parse(off)": off} {
		if r.Enabled() || r.Mode() != ModeOff || r.String() != "off" {
			t.Fatalf("%s: enabled=%v mode=%q string=%q", name, r.Enabled(), r.Mode(), r.String())
		}
		if got := proxyFor(t, r, "registry.pilotprotocol.network:443"); got != "" {
			t.Fatalf("%s: proxied via %q", name, got)
		}
		if got := proxyForURL(t, r, "https://registry.pilotprotocol.network/"); got != "" {
			t.Fatalf("%s: request proxied via %q", name, got)
		}
		if u, err := r.ProxyForRequest(nil); u != nil || err != nil {
			t.Fatalf("%s: ProxyForRequest(nil) = %v, %v", name, u, err)
		}
	}
}

func TestParseExplicitURLs(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"http://proxy:3128":           "http://proxy:3128",
		"HTTP://Proxy:3128":           "http://Proxy:3128",
		"https://u:p@proxy.example":   "https://u:p@proxy.example",
		"proxy.example:8080":          "http://proxy.example:8080",
		"u:p@proxy.example:8080":      "http://u:p@proxy.example:8080",
		"  http://[::1]:3128  ":       "http://[::1]:3128",
		"http://u%40corp:p%3Aw@h:1/x": "http://u%40corp:p%3Aw@h:1/x",
	}
	for in, want := range cases {
		r, err := Parse(in)
		if err != nil {
			t.Fatalf("Parse(%q): %v", in, err)
		}
		if r.Mode() != ModeExplicit {
			t.Fatalf("Parse(%q) mode %q", in, r.Mode())
		}
		if got := proxyFor(t, r, "t.invalid:1"); got != want {
			t.Fatalf("Parse(%q) proxy = %q, want %q", in, got, want)
		}
	}
	// Percent-encoded userinfo is decoded before it goes on the wire.
	r := mustExplicit(t, "http://u%40corp:p%3Aw@h:1")
	u, _ := r.ProxyForAddr("t.invalid:1")
	if pw, _ := u.User.Password(); u.User.Username() != "u@corp" || pw != "p:w" {
		t.Fatalf("userinfo decoded to %q / %q", u.User.Username(), pw)
	}
}

func TestParseErrorsNeverLeakCredentials(t *testing.T) {
	t.Parallel()
	bad := []string{
		"socks5://user:hunter2@proxy:1080",
		"http://user:hunter2@proxy:bad-port",
		"http://user:hunter2@",
		"http://user:hunter2@proxy%zz:1",
		"ftp://proxy:21",
		"http://",
	}
	for _, raw := range bad {
		_, err := Explicit(raw)
		if err == nil {
			t.Fatalf("Explicit(%q) accepted", raw)
		}
		if strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "user:") {
			t.Fatalf("Explicit(%q) error leaks credentials: %v", raw, err)
		}
		_, err = fromEnv(envMap(map[string]string{"HTTPS_PROXY": raw}))
		if err == nil {
			t.Fatalf("HTTPS_PROXY=%q accepted", raw)
		}
		if strings.Contains(err.Error(), "hunter2") {
			t.Fatalf("HTTPS_PROXY=%q error leaks credentials: %v", raw, err)
		}
		if !strings.HasPrefix(err.Error(), "HTTPS_PROXY: ") {
			t.Fatalf("env error should name the variable: %v", err)
		}
	}
	if _, err := Explicit("   "); err == nil {
		t.Fatal("empty explicit URL accepted")
	}
	// An unusable HTTP_PROXY is a warning, not an error (see
	// TestFromEnvVariablesAreIndependent), and is just as tight-lipped.
	r, err := fromEnv(envMap(map[string]string{"HTTP_PROXY": "gopher://user:hunter2@x:1"}))
	if err != nil {
		t.Fatalf("bad HTTP_PROXY failed the resolver: %v", err)
	}
	w := r.Warnings()
	if len(w) != 1 || !strings.HasPrefix(w[0].Error(), "HTTP_PROXY: ") || strings.Contains(w[0].Error(), "hunter2") || strings.Contains(w[0].Error(), "user") {
		t.Fatalf("bad HTTP_PROXY warning: %v", w)
	}
}

// A proxy variable that cannot be used must not take down another one that
// can: a Muse-style VM with a valid HTTPS_PROXY and an http_proxy that Go
// cannot use still proxies registry traffic.
func TestFromEnvVariablesAreIndependent(t *testing.T) {
	t.Parallel()
	const (
		registry = "registry.pilotprotocol.network:443"
		secure   = "http://u:p@egress:3128"
	)
	cases := []struct {
		name       string
		env        map[string]string
		wantTLS    string   // proxy for registry and https:// requests
		wantPlain  string   // proxy for http:// requests
		wantWarned []string // variables reported by Warnings, in order
	}{
		{
			name:       "socks HTTP_PROXY beside a valid HTTPS_PROXY",
			env:        map[string]string{"HTTPS_PROXY": secure, "HTTP_PROXY": "socks5://proxy:1080"},
			wantTLS:    secure,
			wantPlain:  secure,
			wantWarned: []string{"HTTP_PROXY"},
		},
		{
			name:       "garbage http_proxy beside a valid https_proxy",
			env:        map[string]string{"https_proxy": secure, "http_proxy": "garbage with space"},
			wantTLS:    secure,
			wantPlain:  secure,
			wantWarned: []string{"http_proxy"},
		},
		{
			name:       "unusable HTTP_PROXY falls through to http_proxy",
			env:        map[string]string{"HTTPS_PROXY": secure, "HTTP_PROXY": "socks5h://x:1", "http_proxy": "http://plain:8080"},
			wantTLS:    secure,
			wantPlain:  "http://plain:8080",
			wantWarned: []string{"HTTP_PROXY"},
		},
		{
			name:       "socks ALL_PROXY alone is ignored",
			env:        map[string]string{"ALL_PROXY": "socks5://127.0.0.1:1080"},
			wantWarned: []string{"ALL_PROXY"},
		},
		{
			name:       "unusable ALL_PROXY falls through to all_proxy",
			env:        map[string]string{"ALL_PROXY": "socks5://127.0.0.1:1080", "all_proxy": secure},
			wantTLS:    secure,
			wantPlain:  secure,
			wantWarned: []string{"ALL_PROXY"},
		},
		{
			name:       "everything unusable except HTTPS_PROXY",
			env:        map[string]string{"HTTPS_PROXY": secure, "ALL_PROXY": "socks5://a:1", "HTTP_PROXY": "http://bad port", "http_proxy": "ftp://c:21"},
			wantTLS:    secure,
			wantPlain:  secure,
			wantWarned: []string{"HTTP_PROXY", "http_proxy"},
		},
	}
	for _, tc := range cases {
		r, err := fromEnv(envMap(tc.env))
		if err != nil {
			t.Fatalf("%s: fromEnv: %v", tc.name, err)
		}
		if r.Enabled() != (tc.wantTLS != "") {
			t.Fatalf("%s: Enabled() = %v", tc.name, r.Enabled())
		}
		if got := proxyFor(t, r, registry); got != tc.wantTLS {
			t.Fatalf("%s: registry proxy = %q, want %q", tc.name, got, tc.wantTLS)
		}
		if got := proxyForURL(t, r, "https://"+registry+"/"); got != tc.wantTLS {
			t.Fatalf("%s: https proxy = %q, want %q", tc.name, got, tc.wantTLS)
		}
		if got := proxyForURL(t, r, "http://plain.pilot.invalid/"); got != tc.wantPlain {
			t.Fatalf("%s: http proxy = %q, want %q", tc.name, got, tc.wantPlain)
		}
		var warned []string
		for _, w := range r.Warnings() {
			var ee *EnvError
			if !errors.As(w, &ee) {
				t.Fatalf("%s: warning %v is not an *EnvError", tc.name, w)
			}
			if !strings.HasPrefix(w.Error(), ee.Var+": netproxy: ") {
				t.Fatalf("%s: warning %q does not name its variable", tc.name, w)
			}
			warned = append(warned, ee.Var)
		}
		if strings.Join(warned, ",") != strings.Join(tc.wantWarned, ",") {
			t.Fatalf("%s: warned about %q, want %q", tc.name, warned, tc.wantWarned)
		}
		if s := r.String(); !strings.Contains(s, "(ignored unusable "+strings.Join(tc.wantWarned, ", ")+")") || strings.Contains(s, "u:p") {
			t.Fatalf("%s: String() = %q", tc.name, s)
		}
	}

	// Warnings are a copy, and absent for non-environment resolvers.
	r, _ := fromEnv(envMap(map[string]string{"HTTP_PROXY": "socks5://x:1"}))
	r.Warnings()[0] = nil
	if r.Warnings()[0] == nil {
		t.Fatal("Warnings exposed the resolver's slice")
	}
	var nilResolver *Resolver
	for _, other := range []*Resolver{nilResolver, Off(), mustExplicit(t, secure)} {
		if w := other.Warnings(); w != nil {
			t.Fatalf("%s: Warnings() = %v", other, w)
		}
	}
	if got := r.String(); got != "auto: no proxy in environment (ignored unusable HTTP_PROXY)" {
		t.Fatalf("String() = %q", got)
	}
}

// Only the variables that explicitly name the TLS proxy are fatal when
// unusable; the error names the variable and withholds the value.
func TestFromEnvUnusableTLSProxyIsAnError(t *testing.T) {
	t.Parallel()
	for _, env := range []map[string]string{
		{"HTTPS_PROXY": "socks5://user:hunter2@a:1", "https_proxy": "http://ok:1", "HTTP_PROXY": "http://ok:1"},
		{"https_proxy": "http://user:hunter2@a:bad", "ALL_PROXY": "http://ok:1"},
	} {
		_, err := fromEnv(envMap(env))
		var ee *EnvError
		if !errors.As(err, &ee) {
			t.Fatalf("%v: err = %v, want *EnvError", env, err)
		}
		if _, set := env["HTTPS_PROXY"]; (set && ee.Var != "HTTPS_PROXY") || (!set && ee.Var != "https_proxy") {
			t.Fatalf("%v: error names %q", env, ee.Var)
		}
		if strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "user") {
			t.Fatalf("%v: error leaks credentials: %v", env, err)
		}
	}
}

// Proxy credentials often hold unescaped '/', '?' or '#' (base64 tokens).
// url.Parse ends the authority at the first of those, which would turn part
// of the secret into the proxy host. The userinfo runs to the LAST '@', so
// the credentials decode intact and never appear in String, Redact, errors
// or a DNS lookup.
func TestUnescapedDelimitersInUserinfo(t *testing.T) {
	t.Parallel()
	cases := []struct {
		raw, user, pass, host string
		hasPass               bool
		secrets               []string
	}{
		{"http://abcDEF/ghi+jkl@proxy.muse:3128", "abcDEF/ghi+jkl", "", "proxy.muse:3128", false, []string{"abcDEF", "ghi"}},
		{"http://user:9876/zz@proxy:3128", "user", "9876/zz", "proxy:3128", true, []string{"user", "9876"}},
		{"http://user:9876?zz@proxy:3128", "user", "9876?zz", "proxy:3128", true, []string{"user", "9876"}},
		{"http://user:98#76@proxy:3128", "user", "98#76", "proxy:3128", true, []string{"user", "98"}},
		{"http://AbC/dEf+ghi==@proxy:3128", "AbC/dEf+ghi==", "", "proxy:3128", false, []string{"AbC", "dEf"}},
		{"https://tok:a/b?c#d@egress.internal", "tok", "a/b?c#d", "egress.internal", true, []string{"tok", "a/b"}},
		{"user:pa/ss@proxy:3128", "user", "pa/ss", "proxy:3128", true, []string{"user", "pa/ss"}},
		{"user:pa://ss@proxy:3128", "user", "pa://ss", "proxy:3128", true, []string{"user", "pa:"}},
		{"http://us@er:p@ss@proxy:3128", "us@er", "p@ss", "proxy:3128", true, []string{"us@er", "p@ss"}},
		{"http://u%2Fx:p%23w/q@proxy:3128/", "u/x", "p#w/q", "proxy:3128", true, []string{"u%2F", "p%23"}},
	}
	for _, tc := range cases {
		explicit, err := Explicit(tc.raw)
		if err != nil {
			t.Fatalf("Explicit(%q): %v", tc.raw, err)
		}
		auto, err := fromEnv(envMap(map[string]string{"HTTPS_PROXY": tc.raw}))
		if err != nil {
			t.Fatalf("HTTPS_PROXY=%q: %v", tc.raw, err)
		}
		for _, r := range []*Resolver{explicit, auto} {
			u, err := r.ProxyForAddr("registry.pilotprotocol.network:443")
			if err != nil || u == nil {
				t.Fatalf("%q: ProxyForAddr = %v, %v", tc.raw, u, err)
			}
			if u.Host != tc.host {
				t.Fatalf("%q: proxy host %q, want %q", tc.raw, u.Host, tc.host)
			}
			pass, hasPass := u.User.Password()
			if u.User.Username() != tc.user || pass != tc.pass || hasPass != tc.hasPass {
				t.Fatalf("%q: userinfo %q/%q/%v, want %q/%q/%v", tc.raw, u.User.Username(), pass, hasPass, tc.user, tc.pass, tc.hasPass)
			}
			// The URL round-trips: what net/http reads back is the same.
			if back, err := url.Parse(u.String()); err != nil || back.Host != tc.host || back.User.String() != u.User.String() {
				t.Fatalf("%q: String() %q does not round-trip: %v", tc.raw, u.String(), err)
			}
			for _, logged := range []string{r.String(), Redact(u)} {
				if !strings.Contains(logged, "***@"+tc.host) {
					t.Fatalf("%q: logged form %q does not show the real host", tc.raw, logged)
				}
				for _, secret := range tc.secrets {
					if strings.Contains(logged, secret) {
						t.Fatalf("%q: logged form %q leaks %q", tc.raw, logged, secret)
					}
				}
			}
		}
	}
}

// Values that stay unusable are rejected without echoing any part of the
// credentials, however the delimiters fall.
func TestUnusableUserinfoNeverLeaks(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		"http://se/cret:hunter2@proxy:bad-port",
		"http://se?cret:hun#ter2@",
		"http://se/cret:hun%zzter2@proxy:1",
		"http://se/cret:hunter2\x7f@proxy:1",
		"http://se/cret:hunter2@proxy%zz:1",
		"secret://hunter2@proxy:1",
		"socks5://se/cret:hunter2@proxy:1",
	} {
		_, err := Explicit(raw)
		if err == nil {
			t.Fatalf("Explicit(%q) accepted", raw)
		}
		for _, secret := range []string{"se/cret", "se?cret", "cret", "hunter2", "hun", "secret"} {
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("Explicit(%q) error %q leaks %q", raw, err, secret)
			}
		}
	}
}

func TestRedactMisparsedURL(t *testing.T) {
	t.Parallel()
	// URLs built by url.Parse from unescaped credentials: the secret sits
	// in Host (and Path/Query/Fragment), the real host after the last '@'.
	cases := map[string]string{
		"http://abcDEF/ghi+jkl@proxy.muse:3128": "http://***@proxy.muse:3128",
		"http://user:9876/zz@proxy:3128":        "http://***@proxy:3128",
		"http://user:9876?zz@proxy:3128":        "http://***@proxy:3128",
		"http://user:98#76@proxy:3128":          "http://***@proxy:3128",
		"http://u@x/pa@ss@proxy:3128/":          "http://***@proxy:3128",
		"http:user/pw@proxy:1":                  "http://***@proxy:1",
	}
	for in, want := range cases {
		u, err := url.Parse(in)
		if err != nil {
			t.Fatalf("url.Parse(%q): %v", in, err)
		}
		if got := Redact(u); got != want {
			t.Fatalf("Redact(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestProxyForAddrRejectsMalformedAddr(t *testing.T) {
	t.Parallel()
	r, _ := fromEnv(envMap(map[string]string{"HTTPS_PROXY": "http://p:1"}))
	if _, err := r.ProxyForAddr("no-port"); err == nil {
		t.Fatal("expected an error for an address without a port")
	}
}

func TestProxyForRequestDefaultPorts(t *testing.T) {
	t.Parallel()
	// Port-scoped NO_PROXY entries see the scheme's default port.
	r, _ := fromEnv(envMap(map[string]string{"HTTPS_PROXY": "http://p:1", "NO_PROXY": "a.invalid:443,b.invalid:80"}))
	if got := proxyForURL(t, r, "https://a.invalid/"); got != "" {
		t.Fatalf("https default port not matched: %q", got)
	}
	if got := proxyForURL(t, r, "https://b.invalid/"); got == "" {
		t.Fatal("b.invalid:80 entry wrongly matched an https request")
	}
	if got := proxyForURL(t, r, "http://b.invalid/"); got != "" {
		t.Fatalf("http default port not matched: %q", got)
	}
}

func TestRedact(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"http://user:pass@proxy:3128":        "http://***@proxy:3128",
		"http://user@proxy:3128":             "http://***@proxy:3128",
		"https://proxy.example":              "https://proxy.example",
		"http://u:p@proxy:1/path?token=x#fr": "http://***@proxy:1",
		"http://u:p@[::1]:3128":              "http://***@[::1]:3128",
	}
	for in, want := range cases {
		u, err := url.Parse(in)
		if err != nil {
			t.Fatal(err)
		}
		if got := Redact(u); got != want {
			t.Fatalf("Redact(%q) = %q, want %q", in, got, want)
		}
	}
	if Redact(nil) != "" {
		t.Fatal("Redact(nil) should be empty")
	}
}

func TestResolverStringRedacts(t *testing.T) {
	t.Parallel()
	if got := mustExplicit(t, "http://user:pw@proxy:3128").String(); got != "http://***@proxy:3128" {
		t.Fatalf("explicit String = %q", got)
	}
	r, _ := fromEnv(envMap(map[string]string{"HTTPS_PROXY": "http://user:pw@proxy:3128", "NO_PROXY": "localhost,.corp"}))
	if got := r.String(); got != "auto: http://***@proxy:3128 (NO_PROXY=localhost,.corp)" {
		t.Fatalf("auto String = %q", got)
	}
	r, _ = fromEnv(envMap(map[string]string{"HTTPS_PROXY": "http://u:pw@a:1", "HTTP_PROXY": "http://u:pw@b:1"}))
	if got := r.String(); got != "auto: http://***@a:1, http http://***@b:1" {
		t.Fatalf("auto String with HTTP_PROXY = %q", got)
	}
	r, _ = fromEnv(envMap(map[string]string{"HTTP_PROXY": "http://u:pw@b:1"}))
	if got := r.String(); got != "auto: http-only http://***@b:1" {
		t.Fatalf("auto http-only String = %q", got)
	}
	r, _ = fromEnv(envMap(nil))
	if got := r.String(); got != "auto: no proxy in environment" {
		t.Fatalf("empty auto String = %q", got)
	}
}

func TestNoProxyMatching(t *testing.T) {
	t.Parallel()
	cases := []struct {
		noProxy string
		host    string
		port    string
		bypass  bool
	}{
		{"", "registry.pilotprotocol.network", "443", false},
		{"*", "anything.example", "1", true},
		{"example.com", "example.com", "443", true},
		{"example.com", "api.example.com", "443", true},
		{"example.com", "notexample.com", "443", false},
		{".example.com", "api.example.com", "443", true},
		{".example.com", "example.com", "443", false},
		{"*.example.com", "api.example.com", "443", true},
		{"*.example.com", "example.com", "443", false},
		{"EXAMPLE.com", "Api.Example.COM", "443", true},
		{"example.com:8443", "example.com", "8443", true},
		{"example.com:8443", "example.com", "443", false},
		{"10.1.2.3", "10.1.2.3", "443", true},
		{"10.1.2.3:9000", "10.1.2.3", "443", false},
		{"10.1.2.3:9000", "10.1.2.3", "9000", true},
		{"10.0.0.0/8", "10.200.1.1", "443", true},
		{"10.0.0.0/8", "11.0.0.1", "443", false},
		{"fd00::/8", "fd00::1", "443", true},
		{"[2001:db8::1]:443", "2001:db8::1", "443", true},
		{"2001:db8::1", "2001:db8::1", "80", true},
		{" a.invalid ,\tb.invalid  c.invalid ", "c.invalid", "1", true},
		{",,:443,.,*.,", "x.invalid", "1", false},
		{"example.com", "10.0.0.1", "443", false},
	}
	for _, tc := range cases {
		n := parseNoProxy(tc.noProxy)
		if got := !n.useProxy(tc.host, tc.port); got != tc.bypass {
			t.Fatalf("NO_PROXY=%q host=%s:%s bypass=%v, want %v", tc.noProxy, tc.host, tc.port, got, tc.bypass)
		}
	}
}

func TestConnectErrorMessage(t *testing.T) {
	t.Parallel()
	e := &ConnectError{Target: "registry.pilotprotocol.network:443", StatusCode: 407}
	if e.Error() != "proxy CONNECT registry.pilotprotocol.network:443: 407 Proxy Authentication Required" {
		t.Fatalf("ConnectError = %q", e.Error())
	}
}
