// Implement reflect helpers for unmarshal JSON object into Options map

package reflectDHCP

import (
	"github.com/krolaw/dhcp4"
	"reflect"
	"encoding/json"
	"net"
	"strings"
	"encoding/binary"
	"errors"
)

/* = Helper-types =================================== */

// Convert net.IP to []byte when unmarshal
type ipV4_byte          []byte   // "255.255.255.0"           -> [255 255 255 0]
type ipV4_byteArr       []byte   // ["1.2.3.4","10.20.30.40"] -> [1 2 3 4 10 20 30 40]
type ipV4Double_byte    []byte   // "1.2.3.4 255.255.255.0"   -> [1 2 3 4 255 255 255 0]
type ipV4Double_byteArr []byte   // ["1.2.3.4 255.255.255.0", "10.20.30.40 255.255.0.0"] -> [1 2 3 4 255 255 255 0 10 20 30 40 255 255 0 0]

// Convert *int* to []byte (big-endian) when unmarshal
type  int32_byte    []byte   // "-124"   -> [255 255 255 132]
type uint32_byte    []byte   //  "124"   -> [0 0 0 124]
type uint16_byte    []byte   //  "124"   -> [0 124]
type uint8_byte     []byte   //  "124"   -> [124]
type uint16_byteArr []byte   //  [1,2,4] -> [0 1 0 2 0 4]

// Convert bool-flag to []byte when unmarshal
type flag_byte []byte     // true -> [1]

// Convert string to []byte when unmarshal
type string_byte []byte   // "localhost" -> ['l' 'o' 'c' 'a' 'l' 'h' 'o' 's' 't']

/* =============================== End Helper-types = */

/* = Unmarshal functions for helper-types =========== */

func (ipb *ipV4_byte)            UnmarshalJSON(b []byte) error {
	str := strings.Trim(string(b), `"`)

	if ip := net.ParseIP(str); ip != nil {
		if ip=ip.To4(); ip != nil {
			*ipb = []byte(ip)
			return nil
		}
	}

	return errors.New("Is not correct IPv4: " + str);
}
func (ipba *ipV4_byteArr)        UnmarshalJSON(b []byte) error {
	var ipb []ipV4_byte;

	var err = json.Unmarshal(b, &ipb);
	if err == nil {
		for _, ip := range ipb {
			*ipba = append(*ipba, ip...)
		}
	}

	return err
}
func (ipdb *ipV4Double_byte)     UnmarshalJSON(b []byte) error {
	str := strings.SplitN(strings.Trim(string(b), `"`)," ",2)

	if ip0,ip1 := net.ParseIP(str[0]),net.ParseIP(str[1]); ip0 != nil && ip1 != nil {
		if ip0,ip1 = ip0.To4(),ip1.To4(); ip0 != nil && ip1 != nil {
			*ipdb = append([]byte(ip0), []byte(ip1)...)
			return nil
		}
	}

	return errors.New("Is not correct IPv4: " + str[0] + " - " + str[1])
}
func (ipdba *ipV4Double_byteArr) UnmarshalJSON(b []byte) error {
	var ipdb []ipV4Double_byte;

	var err = json.Unmarshal(b, &ipdb);
	if err == nil {
		for _, ip := range ipdb {
			*ipdba = append(*ipdba, ip...)
		}
	}

	return err
}

func (i  *int32_byte)     UnmarshalJSON(b []byte) error {
	var it int32

	var err = json.Unmarshal(b, &it)
	if err == nil {
		*i = make([]byte,4)
		var uit uint32;

		if it >= 0 { uit = uint32(it)
		}else      { uit = ^uint32(0)-uint32(^it) }

		binary.BigEndian.PutUint32(*i, uit)
	}

	return err
}
func (i *uint32_byte)     UnmarshalJSON(b []byte) error {
	var it uint32

	var err = json.Unmarshal(b, &it)
	if err == nil {
		*i = make([]byte,4)
		binary.BigEndian.PutUint32(*i, it)
	}

	return err
}
func (i *uint16_byte)     UnmarshalJSON(b []byte) error {
	var it uint16

	var err = json.Unmarshal(b, &it)
	if err == nil {
		*i = make([]byte,2)
		binary.BigEndian.PutUint16(*i, it)
	}

	return err
}
func (i *uint8_byte)      UnmarshalJSON(b []byte) error {
	var it uint8

	var err = json.Unmarshal(b, &it)
	if err == nil {
		*i = []byte{byte(it)}
	}

	return err
}
func (ia *uint16_byteArr) UnmarshalJSON(b []byte) error {
	var ib []uint16_byte;

	var err = json.Unmarshal(b, &ib);
	if err == nil {
		for _, ii := range ib {
			*ia = append(*ia, ii...)
		}
	}

	return err
}

func (f *flag_byte)   UnmarshalJSON(b []byte) error {
	var bt bool

	var err = json.Unmarshal(b, &bt)
	if err == nil {
		if bt { *f = []byte{1}
		}else { *f = []byte{0} }
	}

	return err
}

func (s *string_byte) UnmarshalJSON(b []byte) error {
	var st string

	var err = json.Unmarshal(b, &st)
	if err == nil {
		*s = []byte(st)
	}

	return err
}

/* ======= End Unmarshal functions for helper-types = */

// Struct defining type of DHCP options
type optionsAll_byte struct{
	SubnetMask             ipV4_byte
	TimeOffset             int32_byte
	Router                 ipV4_byteArr
	TimeServer             ipV4_byteArr
	NameServer             ipV4_byteArr
	DomainNameServer       ipV4_byteArr
	LogServer              ipV4_byteArr
	CookieServer           ipV4_byteArr
	LPRServer              ipV4_byteArr
	ImpressServer          ipV4_byteArr
	ResourceLocationServer ipV4_byteArr
	HostName               string_byte
	BootFileSize           uint16_byte
	MeritDumpFile          string_byte
	DomainName             string_byte
	SwapServer             ipV4_byte
	RootPath               string_byte
	ExtensionsPath         string_byte
	
	// IP Layer Parameters per Host
	IPForwardingEnableDisable          flag_byte
	NonLocalSourceRoutingEnableDisable flag_byte
	PolicyFilter                       ipV4Double_byteArr // IP Mask
	MaximumDatagramReassemblySize      uint16_byte
	DefaultIPTimeToLive                uint8_byte
	PathMTUAgingTimeout                uint32_byte
	PathMTUPlateauTable                uint16_byteArr

	// IP Layer Parameters per Interface
	InterfaceMTU              uint16_byte
	AllSubnetsAreLocal        flag_byte
	BroadcastAddress          ipV4_byte
	PerformMaskDiscovery      flag_byte
	MaskSupplier              flag_byte
	PerformRouterDiscovery    flag_byte
	RouterSolicitationAddress ipV4_byte
	StaticRoute               ipV4Double_byteArr // IP Router
	
	// Link Layer Parameters per Interface
	//LinkLayerParametersPerInterface Code = 34 //Double in packet.go ?
	TrailerEncapsulation            flag_byte
	ARPCacheTimeout                 uint32_byte
	EthernetEncapsulation           flag_byte
	
	// TCP Parameters
	TCPDefaultTTL        uint8_byte
	TCPKeepaliveInterval uint32_byte
	TCPKeepaliveGarbage  flag_byte
	
	// Application and Service Parameters
	NetworkInformationServiceDomain            string_byte
	NetworkInformationServers                  ipV4_byteArr
	NetworkTimeProtocolServers                 ipV4_byteArr
	VendorSpecificInformation                  []byte
	NetBIOSOverTCPIPNameServer                 ipV4_byteArr
	NetBIOSOverTCPIPDatagramDistributionServer ipV4_byteArr
	NetBIOSOverTCPIPNodeType                   uint8_byte
	NetBIOSOverTCPIPScope                      string_byte
	XWindowSystemFontServer                    ipV4_byteArr
	XWindowSystemDisplayManager                ipV4_byteArr
	NetworkInformationServicePlusDomain        string_byte
	NetworkInformationServicePlusServers       ipV4_byteArr
	MobileIPHomeAgent                          ipV4_byteArr
	SimpleMailTransportProtocol                ipV4_byteArr
	PostOfficeProtocolServer                   ipV4_byteArr
	NetworkNewsTransportProtocol               ipV4_byteArr
	DefaultWorldWideWebServer                  ipV4_byteArr
	DefaultFingerServer                        ipV4_byteArr
	DefaultInternetRelayChatServer             ipV4_byteArr
	StreetTalkServer                           ipV4_byteArr
	StreetTalkDirectoryAssistance              ipV4_byteArr

	//===================================================

	RelayAgentInformation []byte
	
	// DHCP Extensions
	RequestedIPAddress     ipV4_byte
	IPAddressLeaseTime     uint32_byte
	Overload               uint8_byte
	DHCPMessageType        uint8_byte
	ServerIdentifier       ipV4_byte
	ParameterRequestList   []byte
	Message                string_byte
	MaximumDHCPMessageSize uint16_byte
	RenewalTimeValue       uint32_byte
	RebindingTimeValue     uint32_byte
	VendorClassIdentifier  string_byte
	ClientIdentifier       []byte
	
	TFTPServerName string_byte
	BootFileName   string_byte
	
	TZPOSIXString    string_byte
	TZDatabaseString string_byte
	
	ClasslessRouteFormat []byte
}
/* Notes
 http://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml
 http://www.opennet.ru:8101/man.shtml?topic=dhcp-options&category=5&russian=0
 http://linux.die.net/man/5/dhcp-options
*/

// Local dhcp4.OptionCode
type OptionCode dhcp4.OptionCode

// UnmarshalJSON implements the json.Unmarshaler interface.
// The option code is expected to be a quoted string.
func (oc *OptionCode) UnmarshalJSON(b []byte) error {
	var oct = (*dhcp4.OptionCode)(oc)
	str := strings.Trim(string(b), `"`)

	switch str {
	case "End":                    *oct = dhcp4.End
	case "Pad":                    *oct = dhcp4.Pad
	case "SubnetMask":             *oct = dhcp4.OptionSubnetMask
	case "TimeOffset":             *oct = dhcp4.OptionTimeOffset
	case "Router":                 *oct = dhcp4.OptionRouter
	case "TimeServer":             *oct = dhcp4.OptionTimeServer
	case "NameServer":             *oct = dhcp4.OptionNameServer
	case "DomainNameServer":       *oct = dhcp4.OptionDomainNameServer
	case "LogServer":              *oct = dhcp4.OptionLogServer
	case "CookieServer":           *oct = dhcp4.OptionCookieServer
	case "LPRServer":              *oct = dhcp4.OptionLPRServer
	case "ImpressServer":          *oct = dhcp4.OptionImpressServer
	case "ResourceLocationServer": *oct = dhcp4.OptionResourceLocationServer
	case "HostName":               *oct = dhcp4.OptionHostName
	case "BootFileSize":           *oct = dhcp4.OptionBootFileSize
	case "MeritDumpFile":          *oct = dhcp4.OptionMeritDumpFile
	case "DomainName":             *oct = dhcp4.OptionDomainName
	case "SwapServer":             *oct = dhcp4.OptionSwapServer
	case "RootPath":               *oct = dhcp4.OptionRootPath
	case "ExtensionsPath":         *oct = dhcp4.OptionExtensionsPath

		// IP Layer Parameters per Host
	case "IPForwardingEnableDisable":          *oct = dhcp4.OptionIPForwardingEnableDisable
	case "NonLocalSourceRoutingEnableDisable": *oct = dhcp4.OptionNonLocalSourceRoutingEnableDisable
	case "PolicyFilter":                       *oct = dhcp4.OptionPolicyFilter
	case "MaximumDatagramReassemblySize":      *oct = dhcp4.OptionMaximumDatagramReassemblySize
	case "DefaultIPTimeToLive":                *oct = dhcp4.OptionDefaultIPTimeToLive
	case "PathMTUAgingTimeout":                *oct = dhcp4.OptionPathMTUAgingTimeout
	case "PathMTUPlateauTable":                *oct = dhcp4.OptionPathMTUPlateauTable

		// IP Layer Parameters per Interface
	case "InterfaceMTU":              *oct = dhcp4.OptionInterfaceMTU
	case "AllSubnetsAreLocal":        *oct = dhcp4.OptionAllSubnetsAreLocal
	case "BroadcastAddress":          *oct = dhcp4.OptionBroadcastAddress
	case "PerformMaskDiscovery":      *oct = dhcp4.OptionPerformMaskDiscovery
	case "MaskSupplier":              *oct = dhcp4.OptionMaskSupplier
	case "PerformRouterDiscovery":    *oct = dhcp4.OptionPerformRouterDiscovery
	case "RouterSolicitationAddress": *oct = dhcp4.OptionRouterSolicitationAddress
	case "StaticRoute":               *oct = dhcp4.OptionStaticRoute

		// Link Layer Parameters per Interface
		//case "LinkLayerParametersPerInterface": *oc = dhcp4.OptionLinkLayerParametersPerInterface
	case "TrailerEncapsulation":            *oct = dhcp4.OptionTrailerEncapsulation
	case "ARPCacheTimeout":                 *oct = dhcp4.OptionARPCacheTimeout
	case "EthernetEncapsulation":           *oct = dhcp4.OptionEthernetEncapsulation

		// TCP Parameters
	case "TCPDefaultTTL":        *oct = dhcp4.OptionTCPDefaultTTL
	case "TCPKeepaliveInterval": *oct = dhcp4.OptionTCPKeepaliveInterval
	case "TCPKeepaliveGarbage":  *oct = dhcp4.OptionTCPKeepaliveGarbage

		// Application and Service Parameters
	case "NetworkInformationServiceDomain":            *oct = dhcp4.OptionNetworkInformationServiceDomain
	case "NetworkInformationServers":                  *oct = dhcp4.OptionNetworkInformationServers
	case "NetworkTimeProtocolServers":                 *oct = dhcp4.OptionNetworkTimeProtocolServers
	case "VendorSpecificInformation":                  *oct = dhcp4.OptionVendorSpecificInformation
	case "NetBIOSOverTCPIPNameServer":                 *oct = dhcp4.OptionNetBIOSOverTCPIPNameServer
	case "NetBIOSOverTCPIPDatagramDistributionServer": *oct = dhcp4.OptionNetBIOSOverTCPIPDatagramDistributionServer
	case "NetBIOSOverTCPIPNodeType":                   *oct = dhcp4.OptionNetBIOSOverTCPIPNodeType
	case "NetBIOSOverTCPIPScope":                      *oct = dhcp4.OptionNetBIOSOverTCPIPScope
	case "XWindowSystemFontServer":                    *oct = dhcp4.OptionXWindowSystemFontServer
	case "XWindowSystemDisplayManager":                *oct = dhcp4.OptionXWindowSystemDisplayManager
	case "NetworkInformationServicePlusDomain":        *oct = dhcp4.OptionNetworkInformationServicePlusDomain
	case "NetworkInformationServicePlusServers":       *oct = dhcp4.OptionNetworkInformationServicePlusServers
	case "MobileIPHomeAgent":                          *oct = dhcp4.OptionMobileIPHomeAgent
	case "SimpleMailTransportProtocol":                *oct = dhcp4.OptionSimpleMailTransportProtocol
	case "PostOfficeProtocolServer":                   *oct = dhcp4.OptionPostOfficeProtocolServer
	case "NetworkNewsTransportProtocol":               *oct = dhcp4.OptionNetworkNewsTransportProtocol
	case "DefaultWorldWideWebServer":                  *oct = dhcp4.OptionDefaultWorldWideWebServer
	case "DefaultFingerServer":                        *oct = dhcp4.OptionDefaultFingerServer
	case "DefaultInternetRelayChatServer":             *oct = dhcp4.OptionDefaultInternetRelayChatServer
	case "StreetTalkServer":                           *oct = dhcp4.OptionStreetTalkServer
	case "StreetTalkDirectoryAssistance":              *oct = dhcp4.OptionStreetTalkDirectoryAssistance

	case "RelayAgentInformation": *oct = dhcp4.OptionRelayAgentInformation

		// DHCP Extensions
	case "RequestedIPAddress":     *oct = dhcp4.OptionRequestedIPAddress
	case "IPAddressLeaseTime":     *oct = dhcp4.OptionIPAddressLeaseTime
	case "Overload":               *oct = dhcp4.OptionOverload
	case "DHCPMessageType":        *oct = dhcp4.OptionDHCPMessageType
	case "ServerIdentifier":       *oct = dhcp4.OptionServerIdentifier
	case "ParameterRequestList":   *oct = dhcp4.OptionParameterRequestList
	case "Message":                *oct = dhcp4.OptionMessage
	case "MaximumDHCPMessageSize": *oct = dhcp4.OptionMaximumDHCPMessageSize
	case "RenewalTimeValue":       *oct = dhcp4.OptionRenewalTimeValue
	case "RebindingTimeValue":     *oct = dhcp4.OptionRebindingTimeValue
	case "VendorClassIdentifier":  *oct = dhcp4.OptionVendorClassIdentifier
	case "ClientIdentifier":       *oct = dhcp4.OptionClientIdentifier

	case "TFTPServerName": *oct = dhcp4.OptionTFTPServerName
	case "BootFileName":   *oct = dhcp4.OptionBootFileName

	case "TZPOSIXString":    *oct = dhcp4.OptionTZPOSIXString
	case "TZDatabaseString": *oct = dhcp4.OptionTZDatabaseString

	case "ClasslessRouteFormat": *oct = dhcp4.OptionClasslessRouteFormat


	default: return errors.New("DHCP Option name is not correct: " + str);
	}

	return nil
}

// Local dhcp4.Options
type Options dhcp4.Options

// UnmarshalJSON implements the json.Unmarshaler interface.
// The options is expected to be a valid JSON object.
func (o *Options) UnmarshalJSON(b []byte) error {
	var opt optionsAll_byte

	var err = json.Unmarshal(b, &opt)
	if err == nil {
		var s = reflect.ValueOf(&opt).Elem()

		for i := 0; i < s.NumField(); i++ {
			var oc OptionCode

			if err = oc.UnmarshalJSON([]byte(s.Type().Field(i).Name)); err == nil {
				if val := s.Field(i).Bytes(); len(val) != 0 {
					(*o)[dhcp4.OptionCode(oc)] = val
				}
			}
		}
	}

	return err
}

