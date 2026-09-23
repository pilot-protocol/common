// SPDX-License-Identifier: AGPL-3.0-or-later

package netproxy

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
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
// whose message never includes proxy-supplied text. A CONNECT response
// net/http cannot parse ("malformed HTTP status code"), which is how some
// proxies' rejections surface, also triggers a refresh; since such an error
// could in principle come from the server instead, it is retried only for
// the idempotent methods above.
//
// Connections already open, including tunnels in the idle pool, are left
// alone; they keep working until the proxy or the server closes them. The
// returned RoundTripper has a CloseIdleConnections method, so
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
	tr.Proxy = r.ProxyForRequest
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
	return &refreshingTransport{tr: tr, r: r}
}

type refreshingTransport struct {
	tr *http.Transport
	r  *Resolver
}

// authRejectedError is a 407 answer to a CONNECT, with the proxy URL (and
// so the credentials) it was sent with. Its message is the ConnectError's.
type authRejectedError struct {
	*ConnectError
	proxy *url.URL // never printed
}

func (e *authRejectedError) Unwrap() error { return e.ConnectError }

func (t *refreshingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Noted before the lookup, so a timed refresh the lookup runs counts as
	// having happened after it (see Resolver.reauth).
	start := t.r.attemptCount()
	used, _ := t.r.ProxyForRequest(req)
	resp, err := t.tr.RoundTrip(req)
	if err == nil {
		return resp, nil
	}

	var rejectedWith *url.URL
	var replayable bool
	var ae *authRejectedError
	switch {
	case errors.As(err, &ae):
		rejectedWith = ae.proxy
		replayable = canReplay(req, true)
	case used != nil && tunnelled(req) && isMalformedResponse(err):
		rejectedWith = used
		replayable = canReplay(req, false)
	default:
		return nil, err
	}
	_, retry, refreshErr := t.r.reauth(req.Context(), start, rejectedWith, func(st *proxyState) *url.URL {
		return t.r.pickRequest(st, req)
	})
	if !retry || !replayable {
		return nil, withRefreshError(err, refreshErr)
	}
	again, rewindErr := rewind(req)
	if rewindErr != nil {
		return nil, err
	}
	return t.tr.RoundTrip(again)
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
