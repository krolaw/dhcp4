package dhcp4

import (
	"strings"
	"errors"
	"net"
	"encoding/json"
	"reflect"
)

type IPv4byte []byte
type IPv4byteArr []byte
type IPv4Doublebyte []byte
type IPv4DoublebyteArr []byte

type  int32byte []byte
type uint32byte []byte
type uint16byte []byte
type uint8byte  []byte

type uint16byteArr []byte

type flagByte []byte

type stringByte []byte


func (ipb *IPv4byte)            UnmarshalJSON(b []byte) error {
	str := strings.Trim(string(b), `"`)

	if ip := net.ParseIP(str); ip != nil {
		if ip=ip.To4(); ip != nil {
			*ipb = []byte(ip)
			return nil
		}
	}

	return errors.New("Is not correct IPv4: " + str);
}
func (ipba *IPv4byteArr)        UnmarshalJSON(b []byte) error {
	var ipb []IPv4byte;

	var err = json.Unmarshal(b, &ipb);
	if err == nil {
		for _, ip := range ipb {
			*ipba = append(*ipba, ip...)
		}
	}

	return err
}
func (ipdb *IPv4Doublebyte)     UnmarshalJSON(b []byte) error {
	str := strings.SplitN(strings.Trim(string(b), `"`)," ",2)

	if ip0,ip1 := net.ParseIP(str[0]),net.ParseIP(str[1]); ip0 != nil && ip1 != nil {
		if ip0,ip1 = ip0.To4(),ip1.To4(); ip0 != nil && ip1 != nil {
			*ipdb = append([]byte(ip0), []byte(ip1)...)
			return nil
		}
	}

	return errors.New("Is not correct IPv4: " + str[0] + " - " + str[1])
}
func (ipdba *IPv4DoublebyteArr) UnmarshalJSON(b []byte) error {
	var ipdb []IPv4Doublebyte;

	var err = json.Unmarshal(b, &ipdb);
	if err == nil {
		for _, ip := range ipdb {
			*ipdba = append(*ipdba, ip...)
		}
	}

	return err
}

func (i  *int32byte) UnmarshalJSON(b []byte) error {
	var it int32

	var err = json.Unmarshal(b, &it)
	if err == nil {
		*i = []byte{byte(it)}
	}

	return err
}
func (i *uint32byte) UnmarshalJSON(b []byte) error {
	var it uint32

	var err = json.Unmarshal(b, &it)
	if err == nil {
		*i = []byte{byte(it)}
	}

	return err
}
func (i *uint16byte) UnmarshalJSON(b []byte) error {
	var it uint16

	var err = json.Unmarshal(b, &it)
	if err == nil {
		*i = []byte{byte(it)}
	}

	return err
}
func (i *uint8byte)  UnmarshalJSON(b []byte) error {
	var it uint8

	var err = json.Unmarshal(b, &it)
	if err == nil {
		*i = []byte{byte(it)}
	}

	return err
}

func (ia *uint16byteArr) UnmarshalJSON(b []byte) error {
	var ib []uint16byte;

	var err = json.Unmarshal(b, &ib);
	if err == nil {
		for _, ii := range ib {
			*ia = append(*ia, ii...)
		}
	}

	return err
}

func (f *flagByte)       UnmarshalJSON(b []byte) error {
	var bt bool

	var err = json.Unmarshal(b, &bt)
	if err == nil {
		if bt { *f = []byte{1}
		}else { *f = []byte{0} }
	}

	return err
}

func (s *stringByte)     UnmarshalJSON(b []byte) error {
	var st string

	var err = json.Unmarshal(b, &st)
	if err == nil {
		*s = []byte(st)
	}

	return err
}

// http://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml
// http://www.opennet.ru:8101/man.shtml?topic=dhcp-options&category=5&russian=0
// http://linux.die.net/man/5/dhcp-options

//http://stackoverflow.com/questions/9452897/how-to-decode-json-with-type-convert-from-string-to-float64-in-golang

// Struct of all DHCP options
type OptionsAll struct{
	SubnetMask             IPv4byte
	TimeOffset             int32byte
	Router                 IPv4byteArr
	TimeServer             IPv4byteArr
	NameServer             IPv4byteArr
	DomainNameServer       IPv4byteArr
	LogServer              IPv4byteArr
	CookieServer           IPv4byteArr
	LPRServer              IPv4byteArr
	ImpressServer          IPv4byteArr
	ResourceLocationServer IPv4byteArr
	HostName               stringByte
	BootFileSize           uint16byte
	MeritDumpFile          stringByte
	DomainName             stringByte
	SwapServer             IPv4byte
	RootPath               stringByte
	ExtensionsPath         stringByte
	
	// IP Layer Parameters per Host
	IPForwardingEnableDisable          flagByte
	NonLocalSourceRoutingEnableDisable flagByte
	PolicyFilter                       IPv4DoublebyteArr // IP Mask
	MaximumDatagramReassemblySize      uint16byte
	DefaultIPTimeToLive                uint8byte
	PathMTUAgingTimeout                uint32byte
	PathMTUPlateauTable                uint16byteArr

	// IP Layer Parameters per Interface
	InterfaceMTU              uint16byte
	AllSubnetsAreLocal        flagByte
	BroadcastAddress          IPv4byte
	PerformMaskDiscovery      flagByte
	MaskSupplier              flagByte
	PerformRouterDiscovery    flagByte
	RouterSolicitationAddress IPv4byte
	StaticRoute               IPv4DoublebyteArr // IP Router
	
	// Link Layer Parameters per Interface
	//LinkLayerParametersPerInterface Code = 34 //Bug in packet.go ?
	TrailerEncapsulation            flagByte
	ARPCacheTimeout                 uint32byte
	EthernetEncapsulation           flagByte
	
	// TCP Parameters
	TCPDefaultTTL        uint8byte
	TCPKeepaliveInterval uint32byte
	TCPKeepaliveGarbage  flagByte
	
	// Application and Service Parameters
	NetworkInformationServiceDomain            stringByte
	NetworkInformationServers                  IPv4byteArr
	NetworkTimeProtocolServers                 IPv4byteArr
	VendorSpecificInformation                  []byte
	NetBIOSOverTCPIPNameServer                 IPv4byteArr
	NetBIOSOverTCPIPDatagramDistributionServer IPv4byteArr
	NetBIOSOverTCPIPNodeType                   uint8byte
	NetBIOSOverTCPIPScope                      stringByte
	XWindowSystemFontServer                    IPv4byteArr
	XWindowSystemDisplayManager                IPv4byteArr
	NetworkInformationServicePlusDomain        stringByte
	NetworkInformationServicePlusServers       IPv4byteArr
	MobileIPHomeAgent                          IPv4byteArr
	SimpleMailTransportProtocol                IPv4byteArr
	PostOfficeProtocolServer                   IPv4byteArr
	NetworkNewsTransportProtocol               IPv4byteArr
	DefaultWorldWideWebServer                  IPv4byteArr
	DefaultFingerServer                        IPv4byteArr
	DefaultInternetRelayChatServer             IPv4byteArr
	StreetTalkServer                           IPv4byteArr
	StreetTalkDirectoryAssistance              IPv4byteArr

	//===================================================

	RelayAgentInformation []byte
	
	// DHCP Extensions
	RequestedIPAddress     IPv4byte
	IPAddressLeaseTime     uint32byte
	Overload               uint8byte
	DHCPMessageType        uint8byte
	ServerIdentifier       IPv4byte
	ParameterRequestList   []byte
	Message                stringByte
	MaximumDHCPMessageSize uint16byte
	RenewalTimeValue       uint32byte
	RebindingTimeValue     uint32byte
	VendorClassIdentifier  stringByte
	ClientIdentifier       []byte
	
	TFTPServerName stringByte
	BootFileName   stringByte
	
	TZPOSIXString    stringByte
	TZDatabaseString stringByte
	
	ClasslessRouteFormat []byte
}

func (oc *OptionCode) UnmarshalJSON(b []byte) error {
	str := strings.Trim(string(b), `"`)

	switch str {
	case "End":                    *oc = End
	case "Pad":                    *oc = Pad
	case "SubnetMask":             *oc = OptionSubnetMask
	case "TimeOffset":             *oc = OptionTimeOffset
	case "Router":                 *oc = OptionRouter
	case "TimeServer":             *oc = OptionTimeServer
	case "NameServer":             *oc = OptionNameServer
	case "DomainNameServer":       *oc = OptionDomainNameServer
	case "LogServer":              *oc = OptionLogServer
	case "CookieServer":           *oc = OptionCookieServer
	case "LPRServer":              *oc = OptionLPRServer
	case "ImpressServer":          *oc = OptionImpressServer
	case "ResourceLocationServer": *oc = OptionResourceLocationServer
	case "HostName":               *oc = OptionHostName
	case "BootFileSize":           *oc = OptionBootFileSize
	case "MeritDumpFile":          *oc = OptionMeritDumpFile
	case "DomainName":             *oc = OptionDomainName
	case "SwapServer":             *oc = OptionSwapServer
	case "RootPath":               *oc = OptionRootPath
	case "ExtensionsPath":         *oc = OptionExtensionsPath

		// IP Layer Parameters per Host
	case "IPForwardingEnableDisable":          *oc = OptionIPForwardingEnableDisable
	case "NonLocalSourceRoutingEnableDisable": *oc = OptionNonLocalSourceRoutingEnableDisable
	case "PolicyFilter":                       *oc = OptionPolicyFilter
	case "MaximumDatagramReassemblySize":      *oc = OptionMaximumDatagramReassemblySize
	case "DefaultIPTimeToLive":                *oc = OptionDefaultIPTimeToLive
	case "PathMTUAgingTimeout":                *oc = OptionPathMTUAgingTimeout
	case "PathMTUPlateauTable":                *oc = OptionPathMTUPlateauTable

		// IP Layer Parameters per Interface
	case "InterfaceMTU":              *oc = OptionInterfaceMTU
	case "AllSubnetsAreLocal":        *oc = OptionAllSubnetsAreLocal
	case "BroadcastAddress":          *oc = OptionBroadcastAddress
	case "PerformMaskDiscovery":      *oc = OptionPerformMaskDiscovery
	case "MaskSupplier":              *oc = OptionMaskSupplier
	case "PerformRouterDiscovery":    *oc = OptionPerformRouterDiscovery
	case "RouterSolicitationAddress": *oc = OptionRouterSolicitationAddress
	case "StaticRoute":               *oc = OptionStaticRoute

		// Link Layer Parameters per Interface
		//case "LinkLayerParametersPerInterface": *oc = OptionLinkLayerParametersPerInterface
	case "TrailerEncapsulation":            *oc = OptionTrailerEncapsulation
	case "ARPCacheTimeout":                 *oc = OptionARPCacheTimeout
	case "EthernetEncapsulation":           *oc = OptionEthernetEncapsulation

		// TCP Parameters
	case "TCPDefaultTTL":        *oc = OptionTCPDefaultTTL
	case "TCPKeepaliveInterval": *oc = OptionTCPKeepaliveInterval
	case "TCPKeepaliveGarbage":  *oc = OptionTCPKeepaliveGarbage

		// Application and Service Parameters
	case "NetworkInformationServiceDomain":            *oc = OptionNetworkInformationServiceDomain
	case "NetworkInformationServers":                  *oc = OptionNetworkInformationServers
	case "NetworkTimeProtocolServers":                 *oc = OptionNetworkTimeProtocolServers
	case "VendorSpecificInformation":                  *oc = OptionVendorSpecificInformation
	case "NetBIOSOverTCPIPNameServer":                 *oc = OptionNetBIOSOverTCPIPNameServer
	case "NetBIOSOverTCPIPDatagramDistributionServer": *oc = OptionNetBIOSOverTCPIPDatagramDistributionServer
	case "NetBIOSOverTCPIPNodeType":                   *oc = OptionNetBIOSOverTCPIPNodeType
	case "NetBIOSOverTCPIPScope":                      *oc = OptionNetBIOSOverTCPIPScope
	case "XWindowSystemFontServer":                    *oc = OptionXWindowSystemFontServer
	case "XWindowSystemDisplayManager":                *oc = OptionXWindowSystemDisplayManager
	case "NetworkInformationServicePlusDomain":        *oc = OptionNetworkInformationServicePlusDomain
	case "NetworkInformationServicePlusServers":       *oc = OptionNetworkInformationServicePlusServers
	case "MobileIPHomeAgent":                          *oc = OptionMobileIPHomeAgent
	case "SimpleMailTransportProtocol":                *oc = OptionSimpleMailTransportProtocol
	case "PostOfficeProtocolServer":                   *oc = OptionPostOfficeProtocolServer
	case "NetworkNewsTransportProtocol":               *oc = OptionNetworkNewsTransportProtocol
	case "DefaultWorldWideWebServer":                  *oc = OptionDefaultWorldWideWebServer
	case "DefaultFingerServer":                        *oc = OptionDefaultFingerServer
	case "DefaultInternetRelayChatServer":             *oc = OptionDefaultInternetRelayChatServer
	case "StreetTalkServer":                           *oc = OptionStreetTalkServer
	case "StreetTalkDirectoryAssistance":              *oc = OptionStreetTalkDirectoryAssistance

	case "RelayAgentInformation": *oc = OptionRelayAgentInformation

		// DHCP Extensions
	case "RequestedIPAddress":     *oc = OptionRequestedIPAddress
	case "IPAddressLeaseTime":     *oc = OptionIPAddressLeaseTime
	case "Overload":               *oc = OptionOverload
	case "DHCPMessageType":        *oc = OptionDHCPMessageType
	case "ServerIdentifier":       *oc = OptionServerIdentifier
	case "ParameterRequestList":   *oc = OptionParameterRequestList
	case "Message":                *oc = OptionMessage
	case "MaximumDHCPMessageSize": *oc = OptionMaximumDHCPMessageSize
	case "RenewalTimeValue":       *oc = OptionRenewalTimeValue
	case "RebindingTimeValue":     *oc = OptionRebindingTimeValue
	case "VendorClassIdentifier":  *oc = OptionVendorClassIdentifier
	case "ClientIdentifier":       *oc = OptionClientIdentifier

	case "TFTPServerName": *oc = OptionTFTPServerName
	case "BootFileName":   *oc = OptionBootFileName

	case "TZPOSIXString":    *oc = OptionTZPOSIXString
	case "TZDatabaseString": *oc = OptionTZDatabaseString

	case "ClasslessRouteFormat": *oc = OptionClasslessRouteFormat


	default: return errors.New("DHCP Option name is not correct: " + str);
	}

	return nil
}

//TODO: rewrite
// crutch !!!
func (o *Options) UnmarshalJSON(b []byte) error {
	var opt OptionsAll

	var err = json.Unmarshal(b, &opt)
	if err == nil {
		var s = reflect.ValueOf(&opt).Elem()

		for i := 0; i < s.NumField(); i++ {
			var oc OptionCode

			if err = oc.UnmarshalJSON([]byte(s.Type().Field(i).Name)); err == nil {
				if val := s.Field(i).Bytes(); len(val) != 0 {
					(*o)[oc] = val
				}
			}
		}
	}

	return err
}

