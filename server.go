package dhcp4

import (
	"io"
	"log"
	"net"
)

type Handler interface {
	ServeDHCP(req Packet, msgType MessageType, options Options) Packet
}

type NetReaderFrom interface {
	ReadFrom([]byte) (n int, addr net.Addr, err error)
}

// Serve listens on the listen net.PacketConn, passes DHCP packets to handler and sends
// the result to the respond PacketConn.
//
// Listen and respond are separate to support devices (such as a router)
// with multiple interfaces, since Go's net library doesn't currently support binding broadcast
// listeners to a particular interface.  See Examples or https://code.google.com/p/go/issues/detail?id=6935 for more info.
//
func Serve(listen NetReaderFrom, respond io.Writer, handler Handler) error {
	buffer := make([]byte, 1500)
	for {
		n, _, err := listen.ReadFrom(buffer)
		if err != nil {
			return err
		}
		if n < 240 { // Packet too small to be DHCP
			continue
		}
		p := Packet(buffer[:n])
		options := p.ParseOptions()
		msgType := options[OptionDHCPMessageType]
		if len(msgType) != 1 {
			return nil
		}
		// TODO consider more packet validity checks
		if res := handler.ServeDHCP(p, MessageType(msgType[0]), options); res != nil {
			if _, e := r.Write(res); e != nil {
				log.Fatal("Write Error:", e.Error())
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
	return Serve(l, l, handler)
}
