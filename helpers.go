package dhcp4

import (
	"net"
	"time"
)

// SelectOrderOrAll has same functionality as SelectOrder, except if the order
// param is nil, whereby all options are added (in arbitary order).
func (o Options) SelectOrderOrAll(order []byte) []Option {
	if order == nil {
		opts := make([]Option, 0, len(o))
		for i, v := range o {
			opts = append(opts, Option{Code: i, Value: v})
		}
		return opts
	}
	return o.SelectOrder(order)
}

// SelectOrder returns a slice of options ordered and selected by a byte array
// usually defined by OptionParameterRequestList.  This result is expected to be
// used in ReplyPacket()'s []Option parameter.
func (o Options) SelectOrder(order []byte) []Option {
	opts := make([]Option, 0, len(order))
	for _, v := range order {
		if data, ok := o[optionCode(v)]; ok {
			opts = append(opts, Option{Code: optionCode(v), Value: data})
		}
	}
	return opts
}

// IPRange returns how many ips in the ip range from start to stop (inclusive)
func IPRange(start, stop net.IP) int {
	return int(Uvarint([]byte(stop))-Uvarint([]byte(start))) + 1
}

// IPAdd returns a copy of start + add.
// IPAdd(net.IP{192,168,1,1},30) returns net.IP{192.168.1.31}
func IPAdd(start net.IP, add int) net.IP { // IPv4 only
	v := Uvarint([]byte(start))
	result := make(net.IP, len(start))
	PutUvarint([]byte(result), v+uint64(add))
	return result
}

// IPLess returns where IP a is less than IP b.
func IPLess(a net.IP, b net.IP) bool {
	for i, ai := range a {
		if ai != b[i] {
			return ai < b[i]
		}
	}
	return false
}

// IPInRange returns true if ip is between (inclusive) start and stop.
func IPInRange(start, stop, ip net.IP) bool {
	return !(IPLess(ip, start) || IPLess(stop, ip))
}

// OptionsLeaseTime - converts a time.Duration to a 4 byte slice, compatible
// with OptionIPAddressLeaseTime.
func OptionsLeaseTime(d time.Duration) []byte {
	leaseBytes := make([]byte, 4)
	PutUvarint(leaseBytes, uint64(d/time.Second))
	return leaseBytes
}

// JoinIPs returns a byte slice of IP addresses, one immediately after the other
// This may be useful for creating multiple IP options such as OptionRouter.
func JoinIPs(ips []net.IP) (b []byte) {
	for _, v := range ips {
		b = append(b, v...)
	}
	return
}

// PutUvarint writes value to a byte slice.
func PutUvarint(data []byte, value uint64) {
	for i := len(data) - 1; i >= 0; i-- {
		data[i] = byte(value % 256)
		value /= 256
	}
}

// Uvarint returns a value from a byte slice.
// Values requiring more than 64bits, won't work correctly
func Uvarint(data []byte) (ans uint64) {
	for _, b := range data {
		ans <<= 8
		ans += uint64(b)
	}
	return
}
