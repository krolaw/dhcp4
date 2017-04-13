// +build !linux

package conn

import (
	"net"

	"golang.org/x/net/ipv4"
)

type serveIfConn struct {
	ifIndex int
	conn    *ipv4.PacketConn
	cm      *ipv4.ControlMessage
}

func (s *serveIfConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	for { // Filter all other interfaces
		n, s.cm, addr, err = s.conn.ReadFrom(b)
		if err != nil || s.cm == nil || s.cm.IfIndex == s.ifIndex {
			break
		}
	}
	return
}

func (s *serveIfConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {

	// ipv4 docs state that Src is "specify only", however testing by tfheen
	// shows that Src IS populated.  Therefore, to reuse the control message,
	// we set Src to nil to avoid the error "write udp4: invalid argument"
	s.cm.Src = nil
	return s.conn.WriteTo(b, s.cm, addr)
}

func (s *serveIfConn) Close() error { return s.conn.Close() }

// NewUDP4BoundListener creates a listening socket bound to a given interface.
// In truth this
// This is a work around connection.  It really listens on all interfaces
func NewUDP4BoundListener(interfaceName, laddr string) (c *serveIfConn, e error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return err
	}
	l, err := net.ListenPacket("udp4", ":67")
	if err != nil {
		return err
	}
	defer func() {
		if e != nil {
			l.Close()
		}
	}()
	p := ipv4.NewPacketConn(l)
	if err := p.SetControlMessage(ipv4.FlagInterface, true); err != nil {
		return nil, err
	}
	return &serveIfConn{ifIndex: ifIndex, conn: p}, nil
}
