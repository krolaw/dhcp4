package dhcp4

import (
	"bytes"
	"net"
	"testing"
)

func TestIPRange(t *testing.T) {
	var tests = []struct {
		start  net.IP
		stop   net.IP
		result int
	}{
		{
			start:  net.IPv4(192, 168, 1, 1),
			stop:   net.IPv4(192, 168, 1, 1),
			result: 1,
		},
		{
			start:  net.IPv4(192, 168, 1, 1),
			stop:   net.IPv4(192, 168, 1, 254),
			result: 254,
		},
		{
			start:  net.IPv4(192, 168, 1, 1),
			stop:   net.IPv4(192, 168, 10, 1),
			result: 2305,
		},
		{
			start:  net.IPv4(172, 16, 1, 1),
			stop:   net.IPv4(192, 168, 1, 1),
			result: 345505793,
		},
	}

	for _, tt := range tests {
		if result := IPRange(tt.start, tt.stop); result != tt.result {
			t.Fatalf("IPRange(%s, %s), unexpected result: %v != %v",
				tt.start, tt.stop, result, tt.result)
		}
	}
}

func TestIPAdd(t *testing.T) {
	var tests = []struct {
		start  net.IP
		add    int
		result net.IP
	}{
		{
			start:  net.IPv4(192, 168, 1, 1),
			add:    0,
			result: net.IPv4(192, 168, 1, 1),
		},
		{
			start:  net.IPv4(192, 168, 1, 1),
			add:    253,
			result: net.IPv4(192, 168, 1, 254),
		},
		{
			start:  net.IPv4(192, 168, 1, 1),
			add:    1024,
			result: net.IPv4(192, 168, 5, 1),
		},
		{
			start:  net.IPv4(192, 168, 1, 1),
			add:    4096,
			result: net.IPv4(192, 168, 17, 1),
		},
	}

	for _, tt := range tests {
		if result := IPAdd(tt.start, tt.add); !result.Equal(tt.result) {
			t.Fatalf("IPAdd(%s, %d), unexpected result: %v != %v",
				tt.start, tt.add, result, tt.result)
		}
	}
}

func TestIPLess(t *testing.T) {
	var tests = []struct {
		a      net.IP
		b      net.IP
		result bool
	}{
		{
			a:      net.IPv4(192, 168, 1, 1),
			b:      net.IPv4(192, 168, 1, 1),
			result: false,
		},
		{
			a:      net.IPv4(192, 168, 1, 1),
			b:      net.IPv4(192, 168, 0, 1),
			result: false,
		},
		{
			a:      net.IPv4(192, 168, 0, 1),
			b:      net.IPv4(192, 168, 1, 1),
			result: true,
		},
		{
			a:      net.IPv4(192, 168, 0, 1),
			b:      net.IPv4(192, 168, 10, 1),
			result: true,
		},
	}

	for _, tt := range tests {
		if result := IPLess(tt.a, tt.b); result != tt.result {
			t.Fatalf("IPLess(%s, %s), unexpected result: %v != %v",
				tt.a, tt.b, result, tt.result)
		}
	}
}

func TestIPInRange(t *testing.T) {
	var tests = []struct {
		start  net.IP
		stop   net.IP
		ip     net.IP
		result bool
	}{
		{
			start:  net.IPv4(192, 168, 1, 1),
			stop:   net.IPv4(192, 168, 2, 1),
			ip:     net.IPv4(192, 168, 3, 1),
			result: false,
		},
		{
			start:  net.IPv4(192, 168, 1, 1),
			stop:   net.IPv4(192, 168, 10, 1),
			ip:     net.IPv4(192, 168, 0, 1),
			result: false,
		},
		{
			start:  net.IPv4(192, 168, 1, 1),
			stop:   net.IPv4(192, 168, 10, 1),
			ip:     net.IPv4(192, 168, 5, 1),
			result: true,
		},
		{
			start:  net.IPv4(192, 168, 1, 1),
			stop:   net.IPv4(192, 168, 3, 1),
			ip:     net.IPv4(192, 168, 3, 0),
			result: true,
		},
		{
			start:  net.IPv4(192, 168, 1, 1),
			stop:   net.IPv4(192, 168, 1, 1),
			ip:     net.IPv4(192, 168, 1, 1),
			result: true,
		},
	}

	for _, tt := range tests {
		if result := IPInRange(tt.start, tt.stop, tt.ip); result != tt.result {
			t.Fatalf("IPInRange(%s, %s, %s), unexpected result: %v != %v",
				tt.start, tt.stop, tt.ip, result, tt.result)
		}
	}
}

func TestJoinIPs(t *testing.T) {
	var tests = []struct {
		ips    []net.IP
		result []byte
	}{
		{
			ips:    []net.IP{net.IPv4(10, 0, 0, 1)},
			result: []byte{10, 0, 0, 1},
		},
		{
			ips:    []net.IP{net.IPv4(192, 168, 1, 1), net.IPv4(192, 168, 2, 1)},
			result: []byte{192, 168, 1, 1, 192, 168, 2, 1},
		},
		{
			ips:    []net.IP{net.IPv4(10, 0, 0, 1), net.IPv4(255, 255, 255, 254)},
			result: []byte{10, 0, 0, 1, 255, 255, 255, 254},
		},
		{
			ips:    []net.IP{net.IPv4(8, 8, 8, 8), net.IPv4(8, 8, 4, 4), net.IPv4(192, 168, 1, 1)},
			result: []byte{8, 8, 8, 8, 8, 8, 4, 4, 192, 168, 1, 1},
		},
	}

	for _, tt := range tests {
		if result := JoinIPs(tt.ips); !bytes.Equal(result, tt.result) {
			t.Fatalf("JoinIPs(%s), unexpected result: %v != %v",
				tt.ips, result, tt.result)
		}
	}
}
