package dhcp4

import (
	"net"
	"time"
)

type Option struct {
	Code  optionCode
	Value []byte
}
type optionCode byte
type opCode byte
type MessageType byte // Option 53

// A DHCP packet
type Packet []byte

func (p Packet) OpCode() opCode           { return opCode(p[0]) }
func (p Packet) HType() byte              { return p[1] }
func (p Packet) HLen() byte               { return p[2] }
func (p Packet) Hops() byte               { return p[3] } // Never Used?
func (p Packet) XId() []byte              { return p[4:8] }
func (p Packet) Secs() []byte             { return p[8:10] } // Never Used?
func (p Packet) Flags() []byte            { return p[10:12] }
func (p Packet) CIAddr() net.IP           { return net.IP(p[12:16]) }
func (p Packet) YIAddr() net.IP           { return net.IP(p[16:20]) }
func (p Packet) SIAddr() net.IP           { return net.IP(p[20:24]) }
func (p Packet) GIAddr() net.IP           { return net.IP(p[24:28]) }
func (p Packet) CHAddr() net.HardwareAddr { return net.HardwareAddr(p[28 : 28+p.HLen()]) } // max endPos 44
// 192 bytes of zeros BOOTP legacy
func (p Packet) Cookie() []byte { return p[236:240] }
func (p Packet) Options() []byte {
	if len(p) > 240 {
		return p[240:]
	}
	return nil
}

func (p Packet) Broadcast() bool { return p.Flags()[0] > 127 }

func (p Packet) SetBroadcast(broadcast bool) {
	if p.Broadcast() != broadcast {
		p.Flags()[0] ^= 128
	}
}

func (p Packet) SetOpCode(c opCode) { p[0] = byte(c) }
func (p Packet) SetCHAddr(a net.HardwareAddr) {
	copy(p[28:44], a)
	p[2] = byte(len(a))
}
func (p Packet) SetHType(hType byte)     { p[1] = hType }
func (p Packet) SetCookie(cookie []byte) { copy(p.Cookie(), cookie) }
func (p Packet) SetXId(xId []byte)       { copy(p.XId(), xId) }
func (p Packet) SetSecs(secs []byte)     { copy(p.Secs(), secs) }
func (p Packet) SetFlags(flags []byte)   { copy(p.Flags(), flags) }
func (p Packet) SetCIAddr(ip net.IP)     { copy(p.CIAddr(), ip) }
func (p Packet) SetYIAddr(ip net.IP)     { copy(p.YIAddr(), ip) }
func (p Packet) SetSIAddr(ip net.IP)     { copy(p.SIAddr(), ip) }
func (p Packet) SetGIAddr(ip net.IP)     { copy(p.GIAddr(), ip) }

// Map of DHCP options
type Options map[optionCode][]byte

// Parses the packet's options into an Options map
func (p Packet) ParseOptions() Options {
	opts := p.Options()
	options := make(Options, 10)
	for len(opts) >= 2 && optionCode(opts[0]) != End {
		if optionCode(opts[0]) == Pad {
			opts = opts[1:]
			continue
		}
		size := int(opts[1])
		if len(opts) >= 2+size {
			options[optionCode(opts[0])] = opts[2 : 2+size]
		}
		opts = opts[2+size:]
	}
	return options
}

func NewPacket(opCode opCode) Packet {
	p := make(Packet, 241)
	p.SetOpCode(opCode)
	p.SetHType(1) // Ethernet
	p.SetCookie([]byte{99, 130, 83, 99})
	p[240] = byte(End)
	return p
}

// Appends a DHCP option to the end of a packet
func (p *Packet) AddOption(o optionCode, value []byte) {
	*p = append((*p)[:len(*p)-1], []byte{byte(o), byte(len(value))}...)
	*p = append(*p, append(value, byte(End))...)
}

// Removes all options from packet.
func (p *Packet) StripOptions() {
	*p = append((*p)[:240], byte(End))
}

// Creates a request packet that a Client would send to a server.
func RequestPacket(mt MessageType, chAddr net.HardwareAddr, cIAddr net.IP, xId []byte, broadcast bool, options []Option) Packet {
	p := NewPacket(BootRequest)
	p.SetCHAddr(chAddr)
	p.SetXId(xId)
	if cIAddr != nil {
		p.SetCIAddr(cIAddr)
	}
	p.SetBroadcast(broadcast)
	p.AddOption(OptionDHCPMessageType, []byte{byte(mt)})
	for _, o := range options {
		p.AddOption(o.Code, o.Value)
	}
	p.PadToMinSize()
	return p
}

// ReplyPacket creates a reply packet that a Server would send to a client.
// It uses the req Packet param to copy across common/necessary fields to
// associate the reply the request.
func ReplyPacket(req Packet, mt MessageType, serverId, yIAddr net.IP, leaseDuration time.Duration, options []Option) Packet {
	p := NewPacket(BootReply)
	p.SetXId(req.XId())
	p.SetFlags(req.Flags())
	p.SetYIAddr(yIAddr)
	p.SetGIAddr(req.GIAddr())
	p.SetCHAddr(req.CHAddr())
	p.SetSecs(req.Secs())
	p.AddOption(OptionDHCPMessageType, []byte{byte(mt)})
	p.AddOption(OptionServerIdentifier, []byte(serverId))
	p.AddOption(OptionIPAddressLeaseTime, OptionsLeaseTime(leaseDuration))
	for _, o := range options {
		p.AddOption(o.Code, o.Value)
	}
	p.PadToMinSize()
	return p
}

// PadToMinSize pads a packet so that when sent over UDP, the entire packet,
// is 300 bytes (BOOTP min), to be compatible with really old devices.
var padder [272]byte

func (p *Packet) PadToMinSize() {
	if n := len(*p); n < 272 {
		*p = append(*p, padder[:272-n]...)
	}
}

// OpCodes
const (
	BootRequest opCode = 1 // From Client
	BootReply   opCode = 2 // From Server
)

// DHCP Message Type 53
const (
	Discover MessageType = 1 // Broadcast Packet From Client - Can I have an IP?
	Offer    MessageType = 2 // Broadcast From Server - Here's an IP
	Request  MessageType = 3 // Broadcast From Client - I'll take that IP (Also start for renewals)
	Decline  MessageType = 4 // Broadcast From Client - Sorry I can't use that IP
	ACK      MessageType = 5 // From Server, Yes you can have that IP
	NAK      MessageType = 6 // From Server, No you cannot have that IP
	Release  MessageType = 7 // From Client, I don't need that IP anymore
	Inform   MessageType = 8 // From Client, I have this IP and there's nothing you can do about it
)

// DHCP Options
const (
	End                          optionCode = 255
	Pad                          optionCode = 0
	OptionSubnetMask             optionCode = 1
	OptionTimeOffset             optionCode = 2
	OptionRouter                 optionCode = 3
	OptionTimeServer             optionCode = 4
	OptionNameServer             optionCode = 5
	OptionDomainNameServer       optionCode = 6
	OptionLogServer              optionCode = 7
	OptionCookieServer           optionCode = 8
	OptionLPRServer              optionCode = 9
	OptionImpressServer          optionCode = 10
	OptionResourceLocationServer optionCode = 11
	OptionHostName               optionCode = 12
	OptionBootFileSize           optionCode = 13
	OptionMeritDumpFile          optionCode = 14
	OptionDomainName             optionCode = 15
	OptionSwapServer             optionCode = 16
	OptionRootPath               optionCode = 17
	OptionExtensionsPath         optionCode = 18

	// IP Layer Parameters per Host
	OptionIPForwardingEnableDisable          optionCode = 19
	OptionNonLocalSourceRoutingEnableDisable optionCode = 20
	OptionPolicyFilter                       optionCode = 21
	OptionMaximumDatagramReassemblySize      optionCode = 22
	OptionDefaultIPTimeToLive                optionCode = 23
	OptionPathMTUAgingTimeout                optionCode = 24
	OptionPathMTUPlateauTable                optionCode = 25

	// IP Layer Parameters per Interface
	OptionInterfaceMTU              optionCode = 26
	OptionAllSubnetsAreLocal        optionCode = 27
	OptionBroadcastAddress          optionCode = 28
	OptionPerformMaskDiscovery      optionCode = 29
	OptionMaskSupplier              optionCode = 30
	OptionPerformRouterDiscovery    optionCode = 31
	OptionRouterSolicitationAddress optionCode = 32
	OptionStaticRoute               optionCode = 33

	// Link Layer Parameters per Interface
	OptionLinkLayerParametersPerInterface optionCode = 34
	OptionTrailerEncapsulation            optionCode = 34
	OptionARPCacheTimeout                 optionCode = 35
	OptionEthernetEncapsulation           optionCode = 36

	// TCP Parameters
	OptionTCPDefaultTTL        optionCode = 37
	OptionTCPKeepaliveInterval optionCode = 38
	OptionTCPKeepaliveGarbage  optionCode = 39

	// Application and Service Parameters
	OptionNetworkInformationServiceDomain            optionCode = 40
	OptionNetworkInformationServers                  optionCode = 41
	OptionNetworkTimeProtocolServers                 optionCode = 42
	OptionVendorSpecificInformation                  optionCode = 43
	OptionNetBIOSOverTCPIPNameServer                 optionCode = 44
	OptionNetBIOSOverTCPIPDatagramDistributionServer optionCode = 45
	OptionNetBIOSOverTCPIPNodeType                   optionCode = 46
	OptionNetBIOSOverTCPIPScope                      optionCode = 47
	OptionXWindowSystemFontServer                    optionCode = 48
	OptionXWindowSystemDisplayManager                optionCode = 49
	OptionNetworkInformationServicePlusDomain        optionCode = 64
	OptionNetworkInformationServicePlusServers       optionCode = 65
	OptionMobileIPHomeAgent                          optionCode = 68
	OptionSimpleMailTransportProtocol                optionCode = 69
	OptionPostOfficeProtocolServer                   optionCode = 70
	OptionNetworkNewsTransportProtocol               optionCode = 71
	OptionDefaultWorldWideWebServer                  optionCode = 72
	OptionDefaultFingerServer                        optionCode = 73
	OptionDefaultInternetRelayChatServer             optionCode = 74
	OptionStreetTalkServer                           optionCode = 75
	OptionStreetTalkDirectoryAssistance              optionCode = 76

	// DHCP Extensions
	OptionRequestedIPAddress     optionCode = 50
	OptionIPAddressLeaseTime     optionCode = 51
	OptionOverload               optionCode = 52
	OptionDHCPMessageType        optionCode = 53
	OptionServerIdentifier       optionCode = 54
	OptionParameterRequestList   optionCode = 55
	OptionMessage                optionCode = 56
	OptionMaximumDHCPMessageSize optionCode = 57
	OptionRenewalTimeValue       optionCode = 58
	OptionRebindingTimeValue     optionCode = 59
	OptionVendorClassIdentifier  optionCode = 60
	OptionClientIdentifier       optionCode = 61

	OptionTFTPServerName optionCode = 66
	OptionBootFileName   optionCode = 67

	OptionTZPOSIXString    optionCode = 100
	OptionTZDatabaseString optionCode = 101

	OptionClasslessRouteFormat optionCode = 121
)

/* Notes
A DHCP server always returns its own address in the 'server identifier' option.
DHCP defines a new 'client identifier' option that is used to pass an explicit client identifier to a DHCP server.
*/
