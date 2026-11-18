// Package netguard is the single outbound-egress (SSRF) policy for the
// platform. Anything that connects to a user-supplied destination — webfetch,
// webhook delivery — dials through a Guard so that the deny-list is enforced
// on the address actually connected to, not on a separate DNS lookup that a
// short-TTL name can answer differently a moment later (DNS rebinding).
//
// There is exactly one copy of the policy: CheckIP (addresses) and CheckHost
// (URL hosts, before any DNS). Do not re-implement either elsewhere.
package netguard

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
)

// ErrBlocked is returned (wrapped) whenever a destination is refused.
var ErrBlocked = errors.New("netguard: destination blocked by egress policy")

// deniedV4 lists IPv4 ranges outbound traffic may never reach, beyond what
// the netip predicates (loopback, private, link-local, multicast,
// unspecified) already cover.
var deniedV4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),     // "this network"
	netip.MustParsePrefix("100.64.0.0/10"), // CGNAT shared space (often in-cluster)
	netip.MustParsePrefix("192.0.0.0/24"),  // IETF protocol assignments
	netip.MustParsePrefix("198.18.0.0/15"), // benchmarking
	netip.MustParsePrefix("240.0.0.0/4"),   // reserved + limited broadcast
}

// IPv6 forms that embed an IPv4 address the network will deliver to. Each
// is judged as the embedded v4.
var (
	nat64  = netip.MustParsePrefix("64:ff9b::/96")    // well-known NAT64: low 32 bits
	siit   = netip.MustParsePrefix("::ffff:0:0:0/96") // SIIT IPv4-translated: low 32 bits
	sixTo4 = netip.MustParsePrefix("2002::/16")       // 6to4: bits 16..47
)

// deniedV6 lists IPv6 ranges refused outright.
var deniedV6 = []netip.Prefix{
	netip.MustParsePrefix("64:ff9b:1::/48"), // local-use NAT64 (RFC 8215): site-defined translation
	netip.MustParsePrefix("fec0::/10"),      // deprecated site-local
	netip.MustParsePrefix("::/96"),          // deprecated IPv4-compatible (incl. :: and ::1)
}

// CheckIP returns nil when ip is a destination outbound traffic may reach and
// an error wrapping ErrBlocked otherwise. A nil or invalid ip is blocked.
func CheckIP(ip net.IP) error {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return fmt.Errorf("%w: invalid IP %v", ErrBlocked, ip)
	}
	return CheckAddr(addr)
}

// CheckAddr is CheckIP for a netip.Addr.
func CheckAddr(addr netip.Addr) error {
	addr = addr.Unmap() // ::ffff:a.b.c.d is judged as a.b.c.d
	if addr.Is6() {
		for _, p := range deniedV6 {
			if p.Contains(addr) {
				return fmt.Errorf("%w: reserved IPv6 (%s) address %s", ErrBlocked, p, addr)
			}
		}
		b := addr.As16()
		switch {
		case nat64.Contains(addr), siit.Contains(addr):
			addr = netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
		case sixTo4.Contains(addr):
			addr = netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]})
		}
	}
	reason := ""
	switch {
	case !addr.IsValid():
		reason = "invalid"
	case addr.IsLoopback():
		reason = "loopback"
	case addr.IsPrivate():
		reason = "private (RFC 1918 / IPv6 ULA)"
	case addr.IsLinkLocalUnicast():
		reason = "link-local (incl. cloud metadata)"
	case addr.IsUnspecified():
		reason = "unspecified"
	case addr.IsMulticast(), addr.IsLinkLocalMulticast(), addr.IsInterfaceLocalMulticast():
		reason = "multicast"
	}
	if reason == "" && addr.Is4() {
		for _, p := range deniedV4 {
			if p.Contains(addr) {
				reason = "reserved (" + p.String() + ")"
				break
			}
		}
	}
	if reason != "" {
		return fmt.Errorf("%w: %s address %s", ErrBlocked, reason, addr)
	}
	return nil
}

// CheckHost applies the policy to a URL host (u.Hostname(): no port, no
// brackets) without DNS: literal IPs go through CheckAddr and well-known
// internal names are refused. A hostname that passes still has its resolved
// address checked at dial time by a Guard.
func CheckHost(host string) error {
	if host == "" {
		return fmt.Errorf("%w: empty host", ErrBlocked)
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return CheckAddr(addr)
	}
	name := strings.TrimSuffix(strings.ToLower(host), ".")
	switch {
	case name == "localhost", strings.HasSuffix(name, ".localhost"),
		name == "localhost.localdomain",
		name == "metadata", name == "metadata.google.internal":
		return fmt.Errorf("%w: host %q is internal", ErrBlocked, host)
	}
	return nil
}

// Control is a net.Dialer.Control hook: it runs after name resolution, on the
// exact address the socket is about to connect to, so the address checked is
// the address dialed. Anything that is not a literal ip:port is refused.
func Control(network, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("%w: unparseable dial address %q", ErrBlocked, address)
	}
	return CheckAddr(ap.Addr())
}
