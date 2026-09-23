// SPDX-License-Identifier: AGPL-3.0-or-later

package netproxy

import (
	"net"
	"strings"
)

// noProxy is a parsed NO_PROXY list. The matching rules follow
// golang.org/x/net/http/httpproxy (what net/http.ProxyFromEnvironment uses),
// reimplemented here so the common module stays dependency-free.
type noProxy struct {
	all     bool
	ips     []ipMatch
	cidrs   []*net.IPNet
	domains []domainMatch
}

type ipMatch struct {
	ip   net.IP
	port string // "" matches any port
}

type domainMatch struct {
	// suffix always starts with ".", e.g. ".example.com".
	suffix string
	port   string // "" matches any port
	// matchHost also matches the bare domain ("example.com" itself); false
	// for entries written as ".example.com" or "*.example.com".
	matchHost bool
}

// parseNoProxy parses a NO_PROXY value. Entries are separated by commas
// and/or whitespace; malformed entries are ignored, as net/http does.
func parseNoProxy(s string) noProxy {
	var n noProxy
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	for _, p := range fields {
		p = strings.ToLower(p)
		if p == "*" {
			return noProxy{all: true}
		}
		if _, cidr, err := net.ParseCIDR(p); err == nil {
			n.cidrs = append(n.cidrs, cidr)
			continue
		}
		host, port, err := net.SplitHostPort(p)
		if err == nil {
			if host == "" {
				continue
			}
		} else {
			host, port = p, ""
		}
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
		if ip := net.ParseIP(host); ip != nil {
			n.ips = append(n.ips, ipMatch{ip: ip, port: port})
			continue
		}
		if host == "" {
			continue
		}
		host = strings.TrimPrefix(host, "*")
		matchHost := false
		if !strings.HasPrefix(host, ".") {
			matchHost = true
			host = "." + host
		}
		if host == "." {
			continue
		}
		n.domains = append(n.domains, domainMatch{suffix: host, port: port, matchHost: matchHost})
	}
	return n
}

// useProxy reports whether a connection to host:port should go through the
// proxy. localhost and loopback addresses never do.
func (n *noProxy) useProxy(host, port string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return true
	}
	if host == "localhost" {
		return false
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.IsLoopback() {
		return false
	}
	if n.all {
		return false
	}
	if ip != nil {
		for _, m := range n.ips {
			if m.ip.Equal(ip) && (m.port == "" || m.port == port) {
				return false
			}
		}
		for _, c := range n.cidrs {
			if c.Contains(ip) {
				return false
			}
		}
		return true
	}
	for _, m := range n.domains {
		if strings.HasSuffix(host, m.suffix) || (m.matchHost && host == m.suffix[1:]) {
			if m.port == "" || m.port == port {
				return false
			}
		}
	}
	return true
}
