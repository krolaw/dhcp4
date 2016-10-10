package dhcp4

import (
	"context"
	"net"
	"testing"
	"time"
)

type readFromReturn struct {
	b    []byte
	n    int
	addr net.Addr
	err  error
}

type writeToArgs struct {
	b    []byte
	addr net.Addr
}

type writeToReturn struct {
	n   int
	err error
}

type TestConn struct {
	readFromArgs   chan bool
	readFromReturn chan readFromReturn
	writeToArgs    chan writeToArgs
	writeToReturn  chan writeToReturn
}

func (t *TestConn) ReadFrom(b []byte) (int, net.Addr, error) {
	t.readFromArgs <- true
	r := <-t.readFromReturn
	copy(b, r.b)
	return r.n, r.addr, r.err
}

func (t *TestConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	t.writeToArgs <- writeToArgs{b, addr}
	w := <-t.writeToReturn
	return w.n, w.err
}

type serveDHCPArgs struct {
	p       Packet
	msgType MessageType
	options Options
}

type TestHandler struct {
	serveDHCPArgs   chan serveDHCPArgs
	serveDHCPReturn chan Packet
}

func (h *TestHandler) ServeDHCP(p Packet, msgType MessageType, options Options) (d Packet) {
	h.serveDHCPArgs <- serveDHCPArgs{p, msgType, options}
	return <-h.serveDHCPReturn
}

func TestServe(t *testing.T) {
	l := &TestConn{
		readFromArgs:   make(chan bool),
		readFromReturn: make(chan readFromReturn),
		writeToArgs:    make(chan writeToArgs),
		writeToReturn:  make(chan writeToReturn),
	}
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	h := &TestHandler{
		serveDHCPArgs:   make(chan serveDHCPArgs),
		serveDHCPReturn: make(chan Packet),
	}
	done := make(chan struct{})
	go func() {
		ServeContext(ctx, l, h)
		close(done)
	}()

	// Transmit a DHCP request.
	p := RequestPacket(
		Discover,
		net.HardwareAddr([]byte("abcdef")),
		net.IP([]byte{192, 168, 1, 1}),
		[]byte{0, 1, 2, 3},
		true, nil)
	<-l.readFromArgs
	l.readFromReturn <- readFromReturn{
		[]byte(p),
		len(p),
		&net.UDPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 68},
		nil,
	}

	// Answer a DHCP offer.
	dargs := <-h.serveDHCPArgs
	if dargs.msgType != Discover {
		t.Fatalf("ServeDHCP didn't receive Discover, got %d", dargs.msgType)
	}
	p = ReplyPacket(
		p,
		Offer,
		[]byte{192, 168, 1, 1},
		[]byte{192, 168, 1, 1},
		60*time.Second,
		nil)
	h.serveDHCPReturn <- p

	// Receive a DHCP offer
	wargs := <-l.writeToArgs
	l.writeToReturn <- writeToReturn{
		len(wargs.b),
		nil,
	}

	// On cancel, the server should stop
	cancel()
	<-done
}
