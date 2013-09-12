package dhcp4

import (
	"net"
)

type Handler interface {
	ServeDHCP(req Packet, msgType MessageType, options Options) Packet
}

// A Server defines parameters for running a DHCP server.
type Server struct {
	Handler  Handler
	ServerIP net.IP // Used to bind to interface to send broadcast packets from
}

// ListenAndServe listens on the UDP network address s.Addr and then
// calls Serve to handle requests on incoming packets.  If
// s.Addr is blank, ":67" is used.
func (s *Server) ListenAndServe() error {
	l, err := net.ListenPacket("udp4", ":67")
	if err != nil {
		return err
	}
	defer l.Close()
	return s.Serve(l, 68)
}

func (s *Server) Serve(l net.PacketConn, replyPort int) error {
	var srcAddr *net.UDPAddr
	if s.ServerIP != nil {
		srcAddr = &net.UDPAddr{IP: s.ServerIP}
	}
	buffer := make([]byte, 1500)
	for {
		n, _, err := l.ReadFrom(buffer)
		if err != nil {
			return err
		}
		if n < 240 {
			continue
		}
		p := Packet(buffer[:n])
		options := p.ParseOptions()
		msgType := options[OptionDHCPMessageType]
		if len(msgType) != 1 {
			return nil
		}

		// TODO consider more packet validity checks
		if res := s.Handler.ServeDHCP(p, MessageType(msgType[0]), options); res != nil {
			dstIP := net.IPv4(255, 255, 255, 255)
			/*if !p.Broadcast() {
				dstIP = net.IP(p.CIAddr())
			}*/
			r, err := net.DialUDP("udp", srcAddr, &net.UDPAddr{IP: dstIP, Port: replyPort})
			if err == nil {
				defer r.Close()
				r.Write(res)
			}

		}
	}
	return nil
}

// ListenAndServe listens on the UDP network address addr
// and then calls Serve with handler to handle requests
// on incoming packets.
func ListenAndServe(handler Handler) error {
	return (&Server{Handler: handler}).ListenAndServe()
}
