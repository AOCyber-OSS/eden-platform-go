package netguard

import (
	"context"
	"errors"
	"net"
	"sync"
)

// stubResolver answers LookupIPAddr from a per-host script. Each call to a
// host consumes the next answer; the last answer repeats. It records how
// many lookups each host received so rebinding tests can assert that the
// guard resolved exactly once per dial.
type stubResolver struct {
	mu      sync.Mutex
	answers map[string][][]string // host -> sequence of answers (each a list of IPs)
	errs    map[string]error
	calls   map[string]int
}

func newStubResolver() *stubResolver {
	return &stubResolver{answers: map[string][][]string{}, errs: map[string]error{}, calls: map[string]int{}}
}

func (r *stubResolver) answer(host string, ips ...string) *stubResolver {
	r.answers[host] = append(r.answers[host], ips)
	return r
}

func (r *stubResolver) fail(host string, err error) *stubResolver {
	r.errs[host] = err
	return r
}

func (r *stubResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := r.calls[host]
	r.calls[host] = n + 1
	if err, ok := r.errs[host]; ok {
		return nil, err
	}
	seq, ok := r.answers[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	if n >= len(seq) {
		n = len(seq) - 1
	}
	out := make([]net.IPAddr, 0, len(seq[n]))
	for _, s := range seq[n] {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	return out, nil
}

func (r *stubResolver) count(host string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[host]
}

// recordingDial stands in for the socket dial so tests never touch the
// network: it records each address it was asked to connect to and returns
// one end of a net.Pipe.
type recordingDial struct {
	mu    sync.Mutex
	addrs []string
}

func (d *recordingDial) dial(_ context.Context, _, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.addrs = append(d.addrs, addr)
	d.mu.Unlock()
	c, s := net.Pipe()
	_ = s.Close()
	return c, nil
}

func (d *recordingDial) dialed() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.addrs...)
}

var errStubDNS = errors.New("stub: SERVFAIL")
