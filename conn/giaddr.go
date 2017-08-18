package conn

import (
	dhcp "github.com/krolaw/dhcp4"

	"errors"
	"net"
)

// NewGIADDRConn returns a wrapper for dhcp.ServeConn that diverts reply packets
// to GIADDR (when specified by client), instead of request source. If
// a non-zero GIADDR is not listed in permittedGIADDR the packet will be
// ignored.  Any GIADDR is accepted if permittedGIADDR is nil.
func NewGIARRConn(permittedGIADDR []net.IP, conn dhcp.ServeConn) *giaddrConn {
	return &giaddrConn{
		permittedGIADDR: permittedGIADDR,
		conn:            conn,
	}
}

type giaddrConn struct {
	permittedGIADDR []net.IP
	conn            dhcp.ServeConn
	giaddr          net.IP
}

func (r *giaddrConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
start:
	n, addr, err = r.conn.ReadFrom(b)
	if err != nil {
		return
	}
	if n < 240 { // Packet too small to be DHCP
		goto start
	}
	req := dhcp.Packet(b[:n])
	if gi := req.GIAddr(); !gi.Equal(net.IPv4zero) {
		if r.permittedGIADDR != nil {
			for _, pr := range r.permittedGIADDR {
				if pr.Equal(gi) {
					goto permitted
				}
			}
			goto start // filter non-permitted Packet
		}
	permitted:
		r.giaddr = gi
	}
	return
}

func (r *giaddrConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	if r.giaddr != nil {
		uaddr, ok := addr.(*net.UDPAddr)
		if !ok {
			return 0, errors.New("Packet not UDP")
		}
		uaddr.IP = r.giaddr
		r.giaddr = nil
	}
	return r.conn.WriteTo(b, addr)
}
