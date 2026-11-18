package netguard

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
)

func TestControl_ChecksTheConnectedAddress(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:80", "[::1]:443", "169.254.169.254:80", "[::ffff:10.0.0.1]:80", "[fd00::1]:8080"} {
		if err := Control("tcp", addr, nil); !errors.Is(err, ErrBlocked) {
			t.Errorf("Control(%s) = %v, want ErrBlocked", addr, err)
		}
	}
	for _, addr := range []string{"93.184.216.34:443", "[2606:4700:4700::1111]:443"} {
		if err := Control("tcp", addr, nil); err != nil {
			t.Errorf("Control(%s) = %v, want nil", addr, err)
		}
	}
	// Fail closed: an address that is not ip:port is refused.
	for _, addr := range []string{"example.com:80", "garbage", ""} {
		if err := Control("tcp", addr, nil); !errors.Is(err, ErrBlocked) {
			t.Errorf("Control(%q) = %v, want ErrBlocked", addr, err)
		}
	}
}

func TestGuardDial_LookupFailureFailsClosed(t *testing.T) {
	res := newStubResolver().fail("flaky.example", errStubDNS)
	rec := &recordingDial{}
	g := &Guard{Resolver: res, dial: rec.dial}

	_, err := g.DialContext(context.Background(), "tcp", "flaky.example:443")
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("DialContext = %v, want ErrBlocked on lookup failure", err)
	}
	if got := rec.dialed(); len(got) != 0 {
		t.Fatalf("dialed %v after a failed lookup, want nothing", got)
	}
}

func TestGuardDial_EmptyAnswerFailsClosed(t *testing.T) {
	res := newStubResolver().answer("empty.example")
	rec := &recordingDial{}
	g := &Guard{Resolver: res, dial: rec.dial}
	if _, err := g.DialContext(context.Background(), "tcp", "empty.example:443"); !errors.Is(err, ErrBlocked) {
		t.Fatalf("DialContext = %v, want ErrBlocked on empty answer", err)
	}
	if got := rec.dialed(); len(got) != 0 {
		t.Fatalf("dialed %v, want nothing", got)
	}
}

func TestGuardDial_MixedAnswerRefusesWholeHost(t *testing.T) {
	res := newStubResolver().answer("mixed.example", "93.184.216.34", "127.0.0.1")
	rec := &recordingDial{}
	g := &Guard{Resolver: res, dial: rec.dial}
	if _, err := g.DialContext(context.Background(), "tcp", "mixed.example:443"); !errors.Is(err, ErrBlocked) {
		t.Fatalf("DialContext = %v, want ErrBlocked when any answer is private", err)
	}
	if got := rec.dialed(); len(got) != 0 {
		t.Fatalf("dialed %v, want nothing (not even the public answer)", got)
	}
}

// TestGuardDial_RebindingCannotReachLoopback simulates a short-TTL name that
// answers a public address first and loopback afterwards. The guard must
// (a) dial exactly the address it checked, with ONE lookup per dial — no
// second resolution between check and connect — and (b) refuse the
// rebound loopback answer, never handing 127.0.0.1 to the socket layer.
func TestGuardDial_RebindingCannotReachLoopback(t *testing.T) {
	res := newStubResolver().
		answer("rebind.example", "93.184.216.34").
		answer("rebind.example", "127.0.0.1")
	rec := &recordingDial{}
	g := &Guard{Resolver: res, dial: rec.dial}

	conn, err := g.DialContext(context.Background(), "tcp", "rebind.example:443")
	if err != nil {
		t.Fatalf("first dial (public answer) = %v, want success", err)
	}
	_ = conn.Close()
	if n := res.count("rebind.example"); n != 1 {
		t.Fatalf("lookups after first dial = %d, want exactly 1 (check and dial share one answer)", n)
	}
	if got := rec.dialed(); len(got) != 1 || got[0] != "93.184.216.34:443" {
		t.Fatalf("dialed %v, want [93.184.216.34:443] — the checked address", got)
	}

	if _, err := g.DialContext(context.Background(), "tcp", "rebind.example:443"); !errors.Is(err, ErrBlocked) {
		t.Fatalf("second dial (rebound to loopback) = %v, want ErrBlocked", err)
	}
	for _, a := range rec.dialed() {
		if a == "127.0.0.1:443" {
			t.Fatalf("guard handed the rebound loopback address to the dialer: %v", rec.dialed())
		}
	}
}

func TestGuardDial_LiteralPrivateAndInternalNamesRefusedWithoutLookup(t *testing.T) {
	res := newStubResolver()
	rec := &recordingDial{}
	g := &Guard{Resolver: res, dial: rec.dial}
	for _, addr := range []string{"127.0.0.1:80", "[::1]:80", "169.254.169.254:80", "localhost:80", "metadata.google.internal:80", "[::ffff:192.168.0.1]:80"} {
		if _, err := g.DialContext(context.Background(), "tcp", addr); !errors.Is(err, ErrBlocked) {
			t.Errorf("DialContext(%s) = %v, want ErrBlocked", addr, err)
		}
	}
	if got := rec.dialed(); len(got) != 0 {
		t.Fatalf("dialed %v, want nothing", got)
	}
	if n := res.count("localhost"); n != 0 {
		t.Fatalf("resolved localhost %d times; internal names must be refused before DNS", n)
	}
}

func TestGuardDial_AllowHostBypassesPolicy(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	g := &Guard{AllowHost: func(h string) bool { return h == "127.0.0.1" }}
	conn, err := g.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("allow-listed loopback dial = %v, want success", err)
	}
	_ = conn.Close()

	strict := &Guard{}
	if _, err := strict.DialContext(context.Background(), "tcp", ln.Addr().String()); !errors.Is(err, ErrBlocked) {
		t.Fatalf("non-allow-listed loopback dial = %v, want ErrBlocked", err)
	}
}

// TestGuardDial_RealSocketPathUsesControl exercises the production dial path
// (no test hook): a resolver answer of loopback must be refused even though a
// listener is there to accept it.
func TestGuardDial_RealSocketPathUsesControl(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var mu sync.Mutex
	accepted := 0
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			accepted++
			mu.Unlock()
			_ = c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	g := &Guard{Resolver: newStubResolver().answer("inside.example", "127.0.0.1")}
	if _, err := g.DialContext(context.Background(), "tcp", net.JoinHostPort("inside.example", port)); !errors.Is(err, ErrBlocked) {
		t.Fatalf("DialContext = %v, want ErrBlocked", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if accepted != 0 {
		t.Fatalf("listener accepted %d connections, want 0", accepted)
	}
}
