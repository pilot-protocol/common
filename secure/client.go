// SPDX-License-Identifier: AGPL-3.0-or-later

package secure

import (
	"github.com/pilot-protocol/common/driver"
	"github.com/pilot-protocol/common/protocol"
)

// Dial connects to a remote agent's secure port and performs the handshake.
// Returns an encrypted connection that implements net.Conn.
func Dial(d *driver.Driver, addr protocol.Addr, auth ...*HandshakeConfig) (*SecureConn, error) {
	conn, err := d.DialAddr(addr, protocol.PortSecure)
	if err != nil {
		return nil, err
	}

	sc, err := Handshake(conn, false, auth...)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return sc, nil
}
