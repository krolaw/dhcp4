// DHCP4 Library written in Go.
//
// Copyright 2013 Skagerrak Software - http://www.skagerraksoftware.com/
//
// Author: http://richard.warburton.it/
//
// Example of minimal DHCP server:
package dhcp4_test

import (
	dhcp "github.com/krolaw/dhcp4"
	"log"
	"math/rand"
	"net"
	"time"
)

type DHCPHandler struct {
	ip            net.IP        // Server IP to use
	options       dhcp.Options  // Options to send to DHCP Clients
	start         net.IP        // Start of IP range to distribute
	leaseRange    int           // Number of IPs to distribute (starting from start)
	leaseDuration time.Duration // Lease period
	leases        map[int]lease // Map to keep track of leases
}

type lease struct {
	nic    string    // Client's CHAddr
	expiry time.Time // When the lease expires
}

func SetupHandler() *DHCPHandler {
	handler := &DHCPHandler{
		ip:            net.IP{172, 30, 0, 1},
		leaseDuration: 2 * time.Hour,
		start:         net.IP{172, 30, 0, 2},
		leaseRange:    50,
		leases:        make(map[int]lease, 10),
	}
	handler.options = dhcp.Options{
		dhcp.OptionSubnetMask:       []byte{255, 255, 240, 0},
		dhcp.OptionRouter:           []byte(handler.ip), // Presuming Server is also your router
		dhcp.OptionDomainNameServer: []byte(handler.ip), // Presuming Server is also your DNS server
	}
	return handler
}

// Example using DHCP with a single network interface
func ExampleListenAndServe() {
	log.Fatal(dhcp.ListenAndServe(handler))
}

// Example using DHCP on one interface, with a device with multiple interfaces.
func ExampleServe() {
	// The only way to listen to broadcast packets is to listen on all interfaces at the same time.
	// If you attempt to bind to one interface by specifying an IP, broadcast packets will ignored.
	// The recommended workaround is to firewall incoming destination port 67 on the undesired interfaces.
	in, err := net.ListenPacket("udp4", ":67")
	if err != nil {
		return err
	}
	defer in.Close()

	// Packets written to the broadcast listener are sent through the main interface.
	// On a router this isn't desirable, as the main interface usually connects to the gateway.  Users
	// of the router are usually on another interface.  To compensate, we create a new connection bound
	// to the desired interface.  Unfortunately, the source port cannot be set to 67 (required by some
	// clients) as this is being used by the listener.  The recommended workaround is to use the firewall
	// to SNAT destination port 68 outgoing packets --to-source :67.
	out, err := net.DialUDP("udp", &net.UDPAddr{IP: net.IPv4(192, 168, 1, 20)},
		&net.UDPAddr{IP: net.IPv4(255, 255, 255, 255), Port: 68})
	if err != nil {
		return err
	}
	defer out.Close()

	log.Fatal(dhcp.Serve(in, out, handler))
}

func (h *DHCPHandler) ServeDHCP(p dhcp.Packet, msgType dhcp.MessageType, options dhcp.Options) (d dhcp.Packet) {
	switch msgType {
	case dhcp.Discover:
		free, nic := -1, p.CHAddr().String()
		for i, v := range h.leases { // Find previous lease
			if v.nic == nic {
				free = i
				goto reply
			}
		}
		if free = h.freeLease(); free == -1 {
			return
		}
	reply:
		return dhcp.ReplyPacket(p, dhcp.Offer, h.ip, dhcp.IPAdd(h.start, free), h.leaseDuration,
			h.options.SelectOrderOrAll(options[dhcp.OptionParameterRequestList]))
	case dhcp.Request:
		if server, ok := options[dhcp.OptionServerIdentifier]; ok && !net.IP(server).Equal(h.ip) {
			return nil // Message not for this dhcp server
		}
		if reqIP := net.IP(options[dhcp.OptionRequestedIPAddress]); len(reqIP) == 4 {
			if leaseNum := dhcp.IPRange(h.start, reqIP) - 1; leaseNum >= 0 && leaseNum < s.leaseRange {
				if l, exists := h.leases[leaseNum]; !exists || l.nic == p.CHAddr().String() {
					h.leases[leaseNum] = lease{nic: p.CHAddr().String(), expiry: time.Now().Add(h.leaseDuration)}
					return dhcp.ReplyPacket(p, dhcp.ACK, h.ip, net.IP(options[dhcp.OptionRequestedIPAddress]), h.leaseDuration,
						h.options.SelectOrderOrAll(options[dhcp.OptionParameterRequestList]))
				}
			}
		}
		return dhcp.ReplyPacket(p, dhcp.NAK, h.ip, nil, 0, nil)
	case dhcp.Release, dhcp.Decline:
		nic := p.CHAddr().String()
		for i, v := range h.leases {
			if v.nic == nic {
				delete(h.leases, i)
				break
			}
		}
	}
	return nil
}

func (h *DHCPHandler) freeLease() int {
	now := time.Now()
	b := rand.Intn(h.leaseRange) // Try random first
	for _, v := range [][]int{[]int{b, h.leaseRange}, []int{0, b}} {
		for i := v[0]; i < v[1]; i++ {
			if l, ok := h.leases[i]; !ok || l.expiry.Before(now) {
				return i
			}
		}
	}
	return -1
}
