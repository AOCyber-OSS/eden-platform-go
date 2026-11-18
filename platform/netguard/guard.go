package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"
)

// DefaultDialTimeout bounds a single connect when Guard.Dialer is nil.
const DefaultDialTimeout = 10 * time.Second

// Resolver is the subset of *net.Resolver a Guard needs. Tests substitute a
// stub to simulate rebinding and lookup failures.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// Guard dials outbound connections under the egress policy. The zero value
// is ready to use (system resolver, DefaultDialTimeout).
//
// DialContext resolves the host ONCE, refuses the whole host if any answer
// is denied or the lookup fails (fail closed), then connects to those exact
// addresses — never re-resolving — through a net.Dialer whose Control hook
// re-checks the connected address. A short-TTL name therefore cannot pass
// the check with a public answer and then connect to loopback or metadata.
type Guard struct {
	// Resolver answers lookups; nil means net.DefaultResolver.
	Resolver Resolver
	// Dialer supplies timeouts/keep-alive. It is copied; its Control field
	// is always replaced by the policy hook. nil means a dialer with
	// DefaultDialTimeout.
	Dialer *net.Dialer
	// AllowHost, when set and true for the dial host (the URL host as the
	// HTTP transport passes it, before resolution), bypasses the address
	// policy for that host. For trusted intranet targets and tests only.
	AllowHost func(host string) bool

	// dial replaces the socket dial in tests (addr is always a literal ip:port).
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (g *Guard) resolver() Resolver {
	if g.Resolver != nil {
		return g.Resolver
	}
	return net.DefaultResolver
}

func (g *Guard) baseDialer() net.Dialer {
	if g.Dialer != nil {
		return *g.Dialer
	}
	return net.Dialer{Timeout: DefaultDialTimeout}
}

// DialContext implements the http.Transport DialContext contract under the
// egress policy.
func (g *Guard) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("%w: bad dial address %q: %v", ErrBlocked, addr, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("%w: bad dial port %q", ErrBlocked, portStr)
	}

	if g.AllowHost != nil && g.AllowHost(host) {
		if g.dial != nil {
			return g.dial(ctx, network, addr)
		}
		d := g.baseDialer()
		d.Control = nil
		return d.DialContext(ctx, network, addr)
	}

	var addrs []netip.Addr
	if ip, perr := netip.ParseAddr(host); perr == nil {
		addrs = []netip.Addr{ip}
	} else {
		if err := CheckHost(host); err != nil {
			return nil, err
		}
		answers, lerr := g.resolver().LookupIPAddr(ctx, host)
		if lerr != nil {
			return nil, fmt.Errorf("%w: resolve %q: %v", ErrBlocked, host, lerr)
		}
		for _, a := range answers {
			ip, ok := netip.AddrFromSlice(a.IP)
			if !ok {
				return nil, fmt.Errorf("%w: resolve %q: invalid answer %v", ErrBlocked, host, a.IP)
			}
			addrs = append(addrs, ip.Unmap())
		}
		if len(addrs) == 0 {
			return nil, fmt.Errorf("%w: resolve %q: no addresses", ErrBlocked, host)
		}
	}
	// Refuse the whole host if any answer is denied: a mixed answer set is
	// a rebinding/poisoning signal, and the dial order is not ours to pick.
	for _, ip := range addrs {
		if err := CheckAddr(ip); err != nil {
			return nil, fmt.Errorf("%w (host %q)", err, host)
		}
	}

	dial := g.dial
	if dial == nil {
		d := g.baseDialer()
		d.Control = Control
		dial = d.DialContext
	}
	var errs []error
	for _, ip := range addrs {
		conn, derr := dial(ctx, network, netip.AddrPortFrom(ip, uint16(port)).String())
		if derr == nil {
			return conn, nil
		}
		errs = append(errs, derr)
		if ctx.Err() != nil {
			break
		}
	}
	return nil, errors.Join(errs...)
}

// Transport returns an *http.Transport that dials only through g and never
// uses an environment proxy (a proxy would make the connected address the
// proxy's, defeating the policy).
func (g *Guard) Transport() *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           g.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
}
