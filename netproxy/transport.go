// SPDX-License-Identifier: AGPL-3.0-or-later

package netproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync/atomic"
)

// RefreshingTransport returns an http.RoundTripper for HTTP clients behind
// a proxy that rotates its credentials. It sends requests through a copy of
// base (http.DefaultTransport when base is nil) whose Proxy is
// r.ProxyForRequest, so every new connection uses the current credentials,
// and, when the proxy rejects them on CONNECT, refreshes r and retries the
// request once — only when the refresh produced different credentials, and
// only for a request that can be sent again:
//
//   - GET, HEAD, OPTIONS and TRACE requests, and requests carrying an
//     Idempotency-Key or X-Idempotency-Key header, without a body or with
//     GetBody set;
//   - after a 407, any request with GetBody set: the proxy refused the
//     tunnel, so the server never saw the first attempt.
//
// A request that cannot be replayed (a POST whose body cannot be rewound,
// say) gets the error, but the refresh still happens, so the next request
// goes out with fresh credentials.
//
// net/http reports a refused CONNECT only as an error holding the proxy's
// reason phrase — "Proxy Authentication Required", "unknown status code"
// when there is none, or whatever text the proxy chose — without the status
// code. RefreshingTransport therefore reads the status from the CONNECT
// response itself (http.Transport.OnProxyConnectResponse, chained after
// base's own hook) and turns every non-200 answer into a *ConnectError,
// whose message never includes proxy-supplied text.
//
// A CONNECT response net/http cannot parse ("malformed HTTP status code",
// say), which is how some proxies' rejections surface, also triggers a
// refresh, and its error likewise says only what was wrong with the
// response, never its text. That holds only while the tunnel is being set
// up: once net/http has a connection to send the request on, an unparseable
// response came from the server through the tunnel, and its error is
// returned untouched, without a refresh. Having no status code to prove it
// a refusal, such a rejection is retried only for the idempotent methods
// above.
//
// net/http pools connections by proxy URL, credentials included, so once a
// refresh changes the proxy settings, the idle connections opened under the
// old ones can never be picked again. The first request after such a change
// therefore closes the idle connections (in-flight ones finish normally).
// The returned RoundTripper has a CloseIdleConnections method, so
// http.Client.CloseIdleConnections reaches the copy of base.
func RefreshingTransport(base *http.Transport, r *Resolver) http.RoundTripper {
	var tr *http.Transport
	switch dt, ok := http.DefaultTransport.(*http.Transport); {
	case base != nil:
		tr = base.Clone()
	case ok:
		tr = dt.Clone()
	default:
		tr = &http.Transport{}
	}
	tr.Proxy = func(req *http.Request) (*url.URL, error) {
		u, err := r.ProxyForRequest(req)
		if a, ok := req.Context().Value(attemptKey{}).(*attempt); ok {
			a.proxy.Store(u)
		}
		return u, err
	}
	next := tr.OnProxyConnectResponse
	tr.OnProxyConnectResponse = func(ctx context.Context, proxyURL *url.URL, connectReq *http.Request, res *http.Response) error {
		if next != nil {
			if err := next(ctx, proxyURL, connectReq, res); err != nil {
				return err
			}
		}
		// net/http itself accepts exactly 200.
		if res.StatusCode == http.StatusOK {
			return nil
		}
		ce := &ConnectError{Target: connectReq.Host, StatusCode: res.StatusCode}
		if res.StatusCode == http.StatusProxyAuthRequired {
			return &authRejectedError{ConnectError: ce, proxy: cloneURL(proxyURL)}
		}
		return ce
	}
	t := &refreshingTransport{tr: tr, r: r}
	t.pooled.Store(r.snapshot())
	return t
}

type refreshingTransport struct {
	tr *http.Transport
	r  *Resolver

	// pooled is the Resolver's reading that the connections in tr's idle
	// pool were (last known to be) opened under.
	pooled atomic.Pointer[proxyState]
}

// attempt records, for one try of a request, what net/http did with it.
// It travels in the request's context.
type attempt struct {
	// proxy is what the Proxy function returned for the latest connection
	// lookup: the proxy URL, with the credentials, that a refused CONNECT
	// was sent with.
	proxy atomic.Pointer[url.URL]
	// connected is set once net/http has a connection to send the request
	// on, so any CONNECT for it succeeded. It is reset whenever net/http
	// starts looking for a connection, since it retries some failures on a
	// new one.
	connected atomic.Bool
}

type attemptKey struct{}

// authRejectedError is a 407 answer to a CONNECT, with the proxy URL (and
// so the credentials) it was sent with. Its message is the ConnectError's.
type authRejectedError struct {
	*ConnectError
	proxy *url.URL // never printed
}

func (e *authRejectedError) Unwrap() error { return e.ConnectError }

func (t *refreshingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Noted before the lookup, so a timed refresh the lookup starts counts as
	// having happened after it (see Resolver.reauth).
	start := t.r.attemptCount()
	t.dropStrandedConns()
	resp, rej, err := t.send(req)
	if rej.proxy == nil {
		return resp, err
	}
	_, retry, refreshErr := t.r.reauth(req.Context(), start, rej.proxy, func(st *proxyState) *url.URL {
		return t.r.pickRequest(st, req)
	})
	if !retry || !canReplay(req, rej.refused) {
		return nil, withRefreshError(err, refreshErr)
	}
	again, rewindErr := rewind(req)
	if rewindErr != nil {
		return nil, err
	}
	resp, _, err = t.send(again)
	return resp, err
}

// rejection describes a CONNECT the proxy turned down.
type rejection struct {
	// proxy is the proxy URL, with the credentials, the CONNECT was sent
	// with; nil when the proxy did not reject the credentials.
	proxy *url.URL
	// refused is set for a 407: the tunnel was never opened, so the server
	// cannot have seen the request.
	refused bool
}

// send runs one try of req. When the proxy rejected the credentials it also
// says with which ones, and it replaces net/http's error for an unparseable
// CONNECT response with one that does not quote the response.
func (t *refreshingTransport) send(req *http.Request) (*http.Response, rejection, error) {
	a := new(attempt)
	ctx := context.WithValue(req.Context(), attemptKey{}, a)
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GetConn: func(string) { a.connected.Store(false) },
		GotConn: func(httptrace.GotConnInfo) { a.connected.Store(true) },
	})
	resp, err := t.tr.RoundTrip(req.WithContext(ctx))
	if err == nil {
		resp.Request = req // not the copy carrying the trace
		return resp, rejection{}, nil
	}
	var ae *authRejectedError
	if errors.As(err, &ae) {
		return nil, rejection{proxy: ae.proxy, refused: true}, err
	}
	// Without a connection, the response net/http could not parse was the
	// proxy's answer to CONNECT; with one, it came from the server.
	used := a.proxy.Load()
	if fault := responseFault(err); fault != "" && used != nil && tunnelled(req) && !a.connected.Load() {
		return nil, rejection{proxy: used}, fmt.Errorf("proxy CONNECT %s: %w", connectTarget(req.URL), &badConnectResponse{what: fault})
	}
	return nil, rejection{}, err
}

// dropStrandedConns closes the idle connections once the Resolver's proxy
// settings have changed since they were opened: net/http keys its pool by
// proxy URL, credentials included, and would never pick them again.
func (t *refreshingTransport) dropStrandedConns() {
	cur := t.r.snapshot()
	if prev := t.pooled.Swap(cur); prev != cur && !prev.sameProxies(cur) {
		t.tr.CloseIdleConnections()
	}
}

// connectTarget is the "host:port" net/http sends CONNECT for u.
func connectTarget(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(u.Hostname(), port)
}

// CloseIdleConnections closes the idle connections of the underlying
// transport.
func (t *refreshingTransport) CloseIdleConnections() { t.tr.CloseIdleConnections() }

// tunnelled reports whether net/http reaches req's target through a CONNECT
// tunnel when it uses a proxy.
func tunnelled(req *http.Request) bool {
	switch strings.ToLower(req.URL.Scheme) {
	case "https", "wss":
		return true
	}
	return false
}

// canReplay reports whether req may be sent again. neverSent says the first
// attempt certainly did not reach the server (the proxy refused the
// tunnel), so any request whose body can be rewound qualifies; otherwise
// only idempotent ones do, as in net/http's own retry rules.
func canReplay(req *http.Request, neverSent bool) bool {
	if req.Body != nil && req.Body != http.NoBody && req.GetBody == nil {
		return false
	}
	if neverSent && req.GetBody != nil {
		return true
	}
	switch req.Method {
	case "", http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	}
	_, key := req.Header["Idempotency-Key"]
	_, xkey := req.Header["X-Idempotency-Key"]
	return key || xkey
}

// rewind returns a copy of req to send again, with a fresh body from
// GetBody. The RoundTripper contract forbids modifying req itself.
func rewind(req *http.Request) (*http.Request, error) {
	again := req.Clone(req.Context())
	if req.Body != nil && req.Body != http.NoBody {
		body, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		again.Body = body
	}
	return again, nil
}
