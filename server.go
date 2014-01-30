package dhcp4

import (
	"net"

	"code.google.com/p/go.net/ipv4"
)

type Handler interface {
	ServeDHCP(ifindex int, req Packet, reqtype MessageType, options Options) Packet
}

// Serve takes a net.PacketConn that it uses for both reading and writing DHCP
// packets. Every packet is passed to the handler, which can process it and
// optionally return a response packet. A response packet is then written back
// to the network.
//
// To capture limited broadcast packets (sent to 255.255.255.255), you must
// listen on a socket bound to IP_ADDRANY (0.0.0.0). This means that broadcast
// packets sent to any interface on the system may be delivered to this socket.
// The network interface index a DHCP packet was received on is passed to the
// handler, which is responsible for filtering packets by network interface.
//
// Response packets are sent via the same network interface their corresponding
// request was received on.
func Serve(conn net.PacketConn, handler Handler) error {
	p := ipv4.NewPacketConn(conn)
	if err := p.SetControlMessage(ipv4.FlagInterface, true); err != nil {
		return err
	}

	buffer := make([]byte, 1500)
	for {
		n, cm, addr, err := p.ReadFrom(buffer)
		if err != nil {
			return err
		}

		if n < 240 { // Packet too small to be DHCP
			continue
		}

		src := *addr.(*net.UDPAddr)
		dst := src
		req := Packet(buffer[:n])
		options := req.ParseOptions()

		reqtype := MessageType(0)
		if t := options[OptionDHCPMessageType]; len(t) != 1 {
			continue
		} else {
			reqtype = MessageType(t[0])
			if reqtype < Discover || reqtype > Inform {
				continue
			}
		}

		// TODO consider more packet validity checks
		if res := handler.ServeDHCP(cm.IfIndex, req, reqtype, options); res != nil {
			if src.IP.Equal(net.IPv4zero) || req.Broadcast() { // If IP not available, broadcast
				dst.IP = net.IPv4bcast
			}

			// Inherit control message for interface index
			if _, err := p.WriteTo(res, cm, &dst); err != nil {
				return err
			}
		}
	}
}

// ListenAndServe listens on the UDP network address addr
// and then calls Serve with handler to handle requests
// on incoming packets.
func ListenAndServe(handler Handler) error {
	l, err := net.ListenPacket("udp4", ":67")
	if err != nil {
		return err
	}
	defer l.Close()
	return Serve(l, handler)
}
