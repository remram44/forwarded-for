package forwarded_for

import (
	"net"
	"net/http"
	"slices"
	"testing"
)

func listsEqual(a []*net.IPNet, b []*net.IPNet) bool {
	if len(a) != len(b) {
		return false
	}

	for i := 0; i < len(a); i += 1 {
		if !slices.Equal(a[i].IP, b[i].IP) || !slices.Equal(a[i].Mask, b[i].Mask) {
			return false
		}
	}

	return true
}

func TestParseEnv(t *testing.T) {
	test := func(env string, v4 []*net.IPNet, v6 []*net.IPNet) {
		parser, err := NewRemoteAddressParser(env)
		if err != nil {
			t.Fatal(err)
		}
		if !listsEqual(parser.trustedProxiesv4, v4) {
			t.Fatalf("parsing empty env failed: v4: %#v != {}", parser.trustedProxiesv4)
		}
		if !listsEqual(parser.trustedProxiesv6, v6) {
			t.Fatalf("parsing empty env failed: v6: %#v != {}", parser.trustedProxiesv6)
		}
	}

	test("", []*net.IPNet{}, []*net.IPNet{})
	test(
		"127.0.0.1",
		[]*net.IPNet{
			&net.IPNet{IP: net.IP{127, 0, 0, 1}, Mask: net.CIDRMask(32, 32)},
		},
		[]*net.IPNet{},
	)

	test("", []*net.IPNet{}, []*net.IPNet{})
	test(
		"127.0.0.1 , 2000::/60",
		[]*net.IPNet{
			&net.IPNet{IP: net.IP{127, 0, 0, 1}, Mask: net.CIDRMask(32, 32)},
		},
		[]*net.IPNet{
			&net.IPNet{IP: net.IP{32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, Mask: net.CIDRMask(60, 128)},
		},
	)
	test(
		"2001::1, 2000::/48",
		[]*net.IPNet{},
		[]*net.IPNet{
			&net.IPNet{IP: net.IP{32, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, Mask: net.CIDRMask(128, 128)},
			&net.IPNet{IP: net.IP{32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, Mask: net.CIDRMask(48, 128)},
		},
	)
}

func TestGetIP(t *testing.T) {
	parser, err := NewRemoteAddressParser("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}

	req := &http.Request{
		RemoteAddr: "10.1.2.3:1234",
		Header:     make(http.Header),
	}
	req.Header.Add("X-Forwarded-For", "1.2.3.4, 5.6.7.8, 10.4.5.6")
	req.Header.Add("X-Forwarded-For", "10.7.8.9")
	address := parser.GetRemoteAddress(req)
	if address != "5.6.7.8" {
		t.Fatalf("%#v != 5.6.7.8", address)
	}

	req = &http.Request{
		RemoteAddr: "10.1.2.3:1234",
		Header:     make(http.Header),
	}
	req.Header.Add("X-Forwarded-For", "1.2.3.4")
	address = parser.GetRemoteAddress(req)
	if address != "1.2.3.4" {
		t.Fatalf("%#v != 1.2.3.4", address)
	}

	req = &http.Request{
		RemoteAddr: "10.1.2.3:1234",
		Header:     make(http.Header),
	}
	address = parser.GetRemoteAddress(req)
	if address != "10.1.2.3" {
		t.Fatalf("%#v != 10.1.2.3", address)
	}
}
