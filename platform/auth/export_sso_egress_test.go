package auth

import (
	"crypto/x509"

	"go.aocyber.ai/eden-platform-go/platform/netguard"
)

// SetEgressForTest replaces the SSO egress policy's test seams: allowHost
// bypasses the address policy for a dial host (the netguard.Guard hook; for
// loopback httptest servers standing in for a public IdP), allowHTTP permits
// plain http, rootCAs trusts an httptest TLS certificate, and resolver
// stubs DNS. Production code has no way to set any of these.
func (s *SSOService) SetEgressForTest(allowHost func(string) bool, allowHTTP bool, rootCAs *x509.CertPool, resolver netguard.Resolver) {
	s.egress = newSSOEgress(ssoEgressOptions{allowHost: allowHost, allowHTTP: allowHTTP, rootCAs: rootCAs, resolver: resolver})
}
