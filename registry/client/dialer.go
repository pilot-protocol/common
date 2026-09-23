// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"context"
	"crypto/tls"
	"net"
)

// DialContextFunc opens a raw stream connection. It has the signature of
// (*net.Dialer).DialContext and (*netproxy.Dialer).DialContext, so either
// method value can be passed to WithDialer.
type DialContextFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// DialOption customises how a Client or BinaryClient establishes its
// connections. Options are accepted by every Dial* constructor.
type DialOption func(*dialOptions)

type dialOptions struct {
	dial DialContextFunc
}

// WithDialer makes the client open EVERY connection through dial: the
// initial connection, each pool connection, and every reconnect. The
// registry address is passed to dial unresolved, so a proxy dialer (for
// example netproxy.Dialer.DialContext, which issues an HTTP CONNECT by host
// name) sees the registry host name, never a locally resolved IP.
//
// For the TLS constructors the TLS handshake runs on top of the returned
// conn, end-to-end with the registry. When the tls.Config has no ServerName
// the host part of the registry address is used, exactly as a direct TLS
// dial does, so SNI, CA verification and DialTLSPinned's fingerprint check
// behave the same through the dialer. dial is called with a context bounded
// by the client's per-attempt dial timeout.
//
// A nil dial (or not passing WithDialer) keeps the default direct dial.
func WithDialer(dial DialContextFunc) DialOption {
	return func(o *dialOptions) { o.dial = dial }
}

func applyDialOptions(opts []DialOption) dialOptions {
	var o dialOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	return o
}

// dialConn opens one registry connection to addr, plus a TLS handshake when
// tlsCfg is non-nil, bounded by ctx and dialTimeout.
//
// With a nil dial it performs exactly the direct dials the client always
// has: a TLS dial that observes ctx, and a plain TCP dial bounded only by
// dialTimeout (the reconnect loops check ctx between attempts).
func dialConn(ctx context.Context, dial DialContextFunc, addr string, tlsCfg *tls.Config) (net.Conn, error) {
	if dial == nil {
		if tlsCfg != nil {
			d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: dialTimeout}, Config: tlsCfg}
			return d.DialContext(ctx, "tcp", addr)
		}
		return net.DialTimeout("tcp", addr, dialTimeout)
	}

	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	raw, err := dial(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if tlsCfg == nil {
		return raw, nil
	}
	cfg := tlsCfg
	if cfg.ServerName == "" {
		// Mirror crypto/tls.Dial: the SNI / verification name is the host
		// part of the dialed address.
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		cfg = cfg.Clone()
		cfg.ServerName = host
	}
	tc := tls.Client(raw, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return tc, nil
}
