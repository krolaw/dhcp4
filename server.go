package dhcp4

import (
	"net"
	"strconv"
)

type Handler interface {
	ServeDHCP(req Packet, msgType MessageType, options Options) Packet
}

// ServeConn is the bare minimum connection functions required by Serve()
// It allows you to create custom connections for greater control,
// such as ServeIfConn (see serverif.go), which locks to a given interface.
type ServeConn interface {
	ReadFrom(b []byte) (n int, addr net.Addr, err error)
	WriteTo(b []byte, addr net.Addr) (n int, err error)
}

// destIP selects the destination IP address to which to send the reply message
// as per https://tools.ietf.org/html/rfc2131#section-4.1
func destIP(req Packet) net.IP {
	if !req.GIAddr().Equal(net.IPv4zero) {
		return req.GIAddr() //  BOOTP relay agent
	}

	if !req.CIAddr().Equal(net.IPv4zero) {
		return req.CIAddr()
	}

	if req.Broadcast() {
		return net.IPv4bcast
	}

	if !req.YIAddr().Equal(net.IPv4zero) {
		return req.YIAddr()
	}

	return net.IPv4bcast
}

func destAddr(addr net.Addr, req Packet) *net.UDPAddr {
	_, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		portStr = "68"
	}
	port, _ := strconv.Atoi(portStr)
	return &net.UDPAddr{IP: destIP(req), Port: port}
}

// Serve takes a ServeConn (such as a net.PacketConn or dhcp4/conn) for reading
// and writing DHCP packets. If either ReadFrom or WriteTo error (such as a
// closed conn, or just time to exit), Serve exits and passes up the error.
//
// Every packet is passed to the Handler's ServeDHCP func.
//
//
//
// which processes it and optionally return a response packet for writing back
// to the network.
//
// To capture limited broadcast packets (sent to 255.255.255.255), you must
// listen on a socket bound to IP_ADDRANY (0.0.0.0). This means that broadcast
// packets sent to any interface on the system may be delivered to this
// socket.  See: https://code.google.com/p/go/issues/detail?id=7106
//
// Additionally, response packets may not return to the same
// interface that the request was received from.  Writing a custom ServeConn,
// or using ServeIf() can provide a workaround to this problem.
func Serve(conn ServeConn, handler Handler) error {
	buffer := make([]byte, 1500)
	for {
		n, addr, err := conn.ReadFrom(buffer)
		if err != nil {
			return err
		}
		if n < 240 { // Packet too small to be DHCP
			continue
		}
		req := Packet(buffer[:n])
		if req.HLen() > 16 { // Invalid size
			continue
		}
		options := req.ParseOptions()
		var reqType MessageType
		if t := options[OptionDHCPMessageType]; len(t) != 1 {
			continue
		} else {
			reqType = MessageType(t[0])
			if reqType < Discover || reqType > Inform {
				continue
			}
		}
		if req.YIAddr().Equal(net.IPv4zero) {
			if ipStr, _, err := net.SplitHostPort(addr.String()); err == nil {
				req.SetYIAddr(net.ParseIP(ipStr))
			}
		}
		if res := handler.ServeDHCP(req, reqType, options); res != nil {
			addr := destAddr(addr, req)
			res.SetBroadcast(addr.IP.Equal(net.IPv4bcast))
			if _, e := conn.WriteTo(res, addr); e != nil {
				return e
			}
		}
	}
}

// ListenAndServe listens on the UDP network address addr and then calls
// Serve with handler to handle requests on incoming packets.
func ListenAndServe(handler Handler) error {
	l, err := net.ListenPacket("udp4", ":67")
	if err != nil {
		return err
	}
	defer l.Close()
	return Serve(l, handler)
}
