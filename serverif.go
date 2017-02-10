package dhcp4

import (
	"net"

	"golang.org/x/net/ipv4"
)

type serveIfConn struct {
	ifIndices []int
	conn      *ipv4.PacketConn
	cm        *ipv4.ControlMessage
}

func (s *serveIfConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	n, s.cm, addr, err = s.conn.ReadFrom(b)
	if len(s.ifIndices) > 0 && s.cm != nil { // Filter all other interfaces
		for _, v := range s.ifIndices {
			if v == s.cm.IfIndex {
				return
			}
		}
		n = 0 // Packets < 240 are filtered in Serve().
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

// ServeIfs does the same job as Serve(), but listens and responds on the
// specified network interfaces (by index), or all if none specified.  It also
// doubles as an example of how to leverage the dhcp4.ServeConn interface.
//
// If your target only has one interface, use Serve(). ServeIf() requires an
// import outside the std library.
func ServeIfs(conn net.PacketConn, handler Handler, ifIndices ...int) error {
	p := ipv4.NewPacketConn(conn)
	if err := p.SetControlMessage(ipv4.FlagInterface, true); err != nil {
		return err
	}
	return Serve(&serveIfConn{ifIndices: ifIndices, conn: p}, handler)
}

// ServeIf has been deprecated in favour of ServeIfs
func ServeIf(ifIndex int, conn net.PacketConn, handler Handler) error {
	return ServeIfs(conn, handler, ifIndex)
}

// ListenAndServeIfs listens on the specified UDP network interfaces (or all if
// unspecifed) and then calls Serve to handle incoming packet requests.
// i.e. ListenAndServeIfs(handler,"eth0","eth1")
func ListenAndServeIfs(handler Handler, interfaceNames ...string) error {
	ifaces := make([]int, len(interfaceNames))
	for i, v := range interfaceNames {
		iface, err := net.InterfaceByName(v)
		if err != nil {
			return err
		}
		ifaces[i] = iface.Index
	}
	l, err := net.ListenPacket("udp4", ":67")
	if err != nil {
		return err
	}
	defer l.Close()
	return ServeIfs(l, handler, ifaces...)
}

// ListenAndServeIf has been deprecated in favour of ListenAndServeIfs
func ListenAndServeIf(interfaceName string, handler Handler) error {
	return ListenAndServeIfs(handler, interfaceName)
}
