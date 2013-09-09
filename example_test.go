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
	"math/rand"
	"net"
	"time"
)

type DHCPServer struct {
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

func ExampleServer() {
	server := &DHCPServer{
		ip:            net.IP{172, 30, 0, 1},
		leaseDuration: 2 * time.Hour,
		start:         net.IP{172, 30, 0, 2},
		leaseRange:    50,
		leases:        make(map[int]lease, 10),
	}
	server.options = dhcp.Options{
		dhcp.OptionSubnetMask:       []byte{255, 255, 240, 0},
		dhcp.OptionRouter:           []byte(server.ip), // Presuming Server is also your router
		dhcp.OptionDomainNameServer: []byte(server.ip), // Presuming Server is also your DNS server
	}
	//panic(dhcp.ListenAndServe(server).Error())
	panic((&dhcp.Server{Handler: server, ServerIP: server.ip}).ListenAndServe().Error())
}

func (s *DHCPServer) ServeDHCP(p dhcp.Packet, msgType dhcp.MessageType, options dhcp.Options) (d dhcp.Packet) {
	switch msgType {
	case dhcp.Discover:
		free, nic := -1, p.CHAddr().String()
		for i, v := range s.leases { // Find previous lease
			if v.nic == nic {
				free = i
				goto reply
			}
		}
		if free = s.freeLease(); free == -1 {
			return
		}
	reply:
		return dhcp.ReplyPacket(p, dhcp.Offer, s.ip, dhcp.IPAdd(s.start, free), s.leaseDuration,
			s.options.SelectOrderOrAll(options[dhcp.OptionParameterRequestList]))
	case dhcp.Request:
		if server, ok := options[dhcp.OptionServerIdentifier]; ok && !net.IP(server).Equal(s.ip) {
			return nil // Message not for this dhcp server
		}
		if reqIP := net.IP(options[dhcp.OptionRequestedIPAddress]); len(reqIP) == 4 {
			if leaseNum := dhcp.IPRange(s.start, reqIP); leaseNum >= 0 && leaseNum < s.leaseRange {
				if l, exists := s.leases[leaseNum]; !exists || l.nic == p.CHAddr().String() {
					s.leases[leaseNum] = lease{nic: p.CHAddr().String(), expiry: time.Now().Add(s.leaseDuration)}
					return dhcp.ReplyPacket(p, dhcp.ACK, s.ip, net.IP(options[dhcp.OptionRequestedIPAddress]), s.leaseDuration,
						s.options.SelectOrderOrAll(options[dhcp.OptionParameterRequestList]))
				}
			}
		}
		return dhcp.ReplyPacket(p, dhcp.NAK, s.ip, nil, 0, nil)
	case dhcp.Release, dhcp.Decline:
		nic := p.CHAddr().String()
		for i, v := range s.leases {
			if v.nic == nic {
				delete(s.leases, i)
				break
			}
		}
	}
	return nil
}

func (s *DHCPServer) freeLease() int {
	now := time.Now()
	b := rand.Intn(s.leaseRange) // Try random first
	for _, v := range [][]int{[]int{b, s.leaseRange}, []int{s.leaseRange, b}} {
		for i := v[0]; i < v[1]; i++ {
			if l, ok := s.leases[i]; !ok || l.expiry.Before(now) {
				return i
			}
		}
	}
	return -1
}
