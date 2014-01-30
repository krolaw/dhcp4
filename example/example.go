// DHCP4 Library written in Go.
//
// Copyright 2013 Skagerrak Software - http://www.skagerraksoftware.com/
//
// Author: http://richard.warburton.it/
//
// Example of minimal DHCP server:
package main

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"time"

	dhcp "github.com/krolaw/dhcp4"
)

type DHCPHandler struct {
	ifindex       int           // Index of network interface to use
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

// Find index of the network interface the given IP is associated with.
func LookupInterfaceIndexForIP(ip net.IP) int {
	is, err := net.Interfaces()
	if err != nil {
		panic(err)
	}
	for _, i := range is {
		as, err := i.Addrs()
		if err != nil {
			panic(err)
		}
		for _, a := range as {
			if a.(*net.IPNet).IP.String() == ip.String() {
				return i.Index
			}
		}
	}
	panic(fmt.Sprintf("Cannot find network interface for %s", ip))
}

func SetupHandler() *DHCPHandler {
	handler := &DHCPHandler{
		ip:            net.IP{172, 16, 205, 1},
		leaseDuration: 2 * time.Hour,
		start:         net.IP{172, 16, 205, 2},
		leaseRange:    50,
		leases:        make(map[int]lease, 10),
	}
	handler.ifindex = LookupInterfaceIndexForIP(handler.ip)
	handler.options = dhcp.Options{
		dhcp.OptionSubnetMask:       []byte{255, 255, 240, 0},
		dhcp.OptionRouter:           []byte(handler.ip), // Presuming Server is also your router
		dhcp.OptionDomainNameServer: []byte(handler.ip), // Presuming Server is also your DNS server
	}
	return handler
}

func (h *DHCPHandler) ServeDHCP(ifindex int, p dhcp.Packet, msgType dhcp.MessageType, options dhcp.Options) (d dhcp.Packet) {
	if ifindex != h.ifindex {
		return nil
	}
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
			if leaseNum := dhcp.IPRange(h.start, reqIP) - 1; leaseNum >= 0 && leaseNum < h.leaseRange {
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

func main() {
	log.Fatal(dhcp.ListenAndServe(SetupHandler()))
}
