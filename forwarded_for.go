package forwarded_for

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

type RemoteAddressParser struct {
	trustedProxiesv4 []*net.IPNet
	trustedProxiesv6 []*net.IPNet
}

func NewRemoteAddressParser(env string) (*RemoteAddressParser, error) {
	var trustedProxiesv4 []*net.IPNet
	var trustedProxiesv6 []*net.IPNet

	for _, cidr := range strings.Split(env, ",") {
		cidr = strings.TrimSpace(cidr)
		if cidr != "" {
			if strings.Contains(cidr, "/") {
				_, ipnet, err := net.ParseCIDR(cidr)
				if err != nil {
					return nil, fmt.Errorf("can't parse trusted proxy string: %#v: %w", cidr, err)
				}
				if ipnet.IP.To4() != nil {
					trustedProxiesv4 = append(trustedProxiesv4, ipnet)
				} else if ipnet.IP.To16() != nil {
					trustedProxiesv6 = append(trustedProxiesv6, ipnet)
				} else {
					return nil, fmt.Errorf("can't parse trusted proxy string: %#v: invalid IP", cidr)
				}
			} else {
				ip := net.ParseIP(cidr)
				if ipv4 := ip.To4(); ipv4 != nil {
					ipnet := &net.IPNet{
						IP:   ipv4,
						Mask: net.CIDRMask(32, 32),
					}
					trustedProxiesv4 = append(trustedProxiesv4, ipnet)
				} else if ipv6 := ip.To16(); ipv6 != nil {
					ipnet := &net.IPNet{
						IP:   ipv6,
						Mask: net.CIDRMask(128, 128),
					}
					trustedProxiesv6 = append(trustedProxiesv6, ipnet)
				} else {
					return nil, fmt.Errorf("can't parse trusted proxy string: %#v: invalid IP", cidr)
				}
			}
		}
	}

	return &RemoteAddressParser{
		trustedProxiesv4: trustedProxiesv4,
		trustedProxiesv6: trustedProxiesv6,
	}, nil
}

func (p *RemoteAddressParser) isTrustedProxy(address string) bool {
	ip := net.ParseIP(address)
	if ipv4 := ip.To4(); ipv4 != nil {
		for _, proxy := range p.trustedProxiesv4 {
			if proxy.Contains(ipv4) {
				return true
			}
		}
	} else if ipv6 := ip.To16(); ipv6 != nil {
		for _, proxy := range p.trustedProxiesv6 {
			if proxy.Contains(ipv6) {
				return true
			}
		}
	}
	return false
}

func GetIpFromAddressAndPort(addressPort string) string {
	portSep := strings.LastIndexByte(addressPort, ':')
	if portSep == -1 {
		return ""
	}
	ip := addressPort[0:portSep]
	if ip[0] == '[' && ip[len(ip)-1] == ']' {
		ip = ip[1 : len(ip)-1]
	}
	return ip
}

func (p *RemoteAddressParser) GetRemoteAddress(req *http.Request) string {
	address := GetIpFromAddressAndPort(req.RemoteAddr)

	// End now if that address is not a trusted proxy
	if !p.isTrustedProxy(address) {
		return address
	}

	// Get the list of reported addresses from headers
	var addresses []string
	for _, header := range req.Header.Values("X-Forwarded-For") {
		for _, item := range strings.Split(header, ",") {
			item = strings.TrimSpace(item)
			if item != "" {
				addresses = append(addresses, item)
			}
		}
	}

	// Go over them in reverse order, as long as the last address was trusted
	for len(addresses) > 0 && p.isTrustedProxy(address) {
		address = addresses[len(addresses)-1]
		addresses = addresses[:len(addresses)-1]
	}

	return address
}
