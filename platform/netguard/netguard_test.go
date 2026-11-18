package netguard

import (
	"errors"
	"net"
	"net/netip"
	"testing"
)

func TestCheckIP_DeniesNonPublicRanges(t *testing.T) {
	for _, raw := range []string{
		"127.0.0.1", "127.255.255.254", // loopback
		"10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1", // RFC1918
		"169.254.169.254", "169.254.0.1", // link-local / cloud metadata
		"0.0.0.0", "0.1.2.3", // unspecified / "this network"
		"100.64.0.1", "100.127.255.254", // CGNAT shared space
		"224.0.0.1", "239.255.255.250", "255.255.255.255", "240.0.0.1", // multicast / reserved / broadcast
		"::1", "::", // IPv6 loopback / unspecified
		"fc00::1", "fd00::1", "fd12:3456:789a::1", // IPv6 ULA
		"fe80::1",                // IPv6 link-local
		"ff02::1",                // IPv6 multicast
		"::ffff:127.0.0.1",       // v4-mapped loopback
		"::ffff:169.254.169.254", // v4-mapped metadata
		"::ffff:10.0.0.1",        // v4-mapped RFC1918
		"64:ff9b::7f00:1",        // NAT64 of 127.0.0.1
		"64:ff9b::a9fe:a9fe",     // NAT64 of 169.254.169.254
	} {
		ip := net.ParseIP(raw)
		if ip == nil {
			t.Fatalf("bad fixture %q", raw)
		}
		if err := CheckIP(ip); !errors.Is(err, ErrBlocked) {
			t.Errorf("CheckIP(%s) = %v, want ErrBlocked", raw, err)
		}
	}
}

func TestCheckIP_AllowsPublic(t *testing.T) {
	for _, raw := range []string{
		"8.8.8.8", "93.184.216.34", "1.1.1.1",
		"2606:4700:4700::1111", "2001:4860:4860::8888",
		"64:ff9b::808:808", // NAT64 of a public v4
	} {
		if err := CheckIP(net.ParseIP(raw)); err != nil {
			t.Errorf("CheckIP(%s) = %v, want nil", raw, err)
		}
	}
}

func TestCheckIP_NilIsBlocked(t *testing.T) {
	if err := CheckIP(nil); !errors.Is(err, ErrBlocked) {
		t.Errorf("CheckIP(nil) = %v, want ErrBlocked", err)
	}
}

func TestCheckHost_BlocksLiteralsAndKnownNamesWithoutDNS(t *testing.T) {
	for _, host := range []string{
		"127.0.0.1", "10.1.2.3", "169.254.169.254", "::1", "fd00::1", "::ffff:127.0.0.1",
		"localhost", "LOCALHOST", "localhost.", "api.localhost", "localhost.localdomain",
		"metadata.google.internal", "metadata.google.internal.", "metadata",
		"",
	} {
		if err := CheckHost(host); !errors.Is(err, ErrBlocked) {
			t.Errorf("CheckHost(%q) = %v, want ErrBlocked", host, err)
		}
	}
}

func TestCheckHost_AllowsPublicNameAndIP(t *testing.T) {
	// No resolver is consulted: "does-not-resolve.invalid" must pass CheckHost;
	// address enforcement happens at dial time.
	for _, host := range []string{"example.com", "hooks.example.com", "does-not-resolve.invalid", "8.8.8.8", "2606:4700:4700::1111"} {
		if err := CheckHost(host); err != nil {
			t.Errorf("CheckHost(%q) = %v, want nil", host, err)
		}
	}
}

// Review follow-up on #84: transition / deprecated IPv6 forms that embed or
// alias internal IPv4 space.
func TestCheckAddr_DeniesTransitionAndDeprecatedV6(t *testing.T) {
	cases := map[string]string{
		"64:ff9b:1::1":         "local-use NAT64 64:ff9b:1::/48",
		"64:ff9b:1:ffff::a9fe": "local-use NAT64 64:ff9b:1::/48",
		"2002:7f00:1::1":       "6to4 of 127.0.0.1",
		"2002:a9fe:a9fe::":     "6to4 of 169.254.169.254",
		"2002:a00:1::":         "6to4 of 10.0.0.1",
		"fec0::1":              "deprecated site-local fec0::/10",
		"feff::1":              "deprecated site-local fec0::/10",
		"::ffff:0:7f00:1":      "SIIT ::ffff:0:0:0/96 of 127.0.0.1",
		"::ffff:0:a9fe:a9fe":   "SIIT of 169.254.169.254",
		"::7f00:1":             "IPv4-compatible ::/96 of 127.0.0.1",
		"::808:808":            "IPv4-compatible ::/96 (deprecated, denied outright)",
	}
	for raw, why := range cases {
		if err := CheckAddr(netip.MustParseAddr(raw)); !errors.Is(err, ErrBlocked) {
			t.Errorf("CheckAddr(%s) [%s] = %v, want ErrBlocked", raw, why, err)
		}
	}
}

func TestCheckAddr_AllowsTransitionFormsOfPublicV4(t *testing.T) {
	for _, raw := range []string{"2002:808:808::1", "::ffff:0:808:808"} {
		if err := CheckAddr(netip.MustParseAddr(raw)); err != nil {
			t.Errorf("CheckAddr(%s) = %v, want nil (embeds public 8.8.8.8)", raw, err)
		}
	}
}
