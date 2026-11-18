// Package webfetch is a hardened outbound HTTP client with safe-by-default
// policy controls. Donor: aosentry/internal/webfetch (URLValidator + Fetcher).
//
// Use this everywhere a product fetches user-supplied URLs. It blocks
// SSRF vectors (private IPs, link-local, loopback) by default, caps response
// sizes, restricts redirects, and exposes per-request policy overrides.
//
// See TRD 20-02.
package webfetch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"go.aocyber.ai/eden-platform-go/platform/netguard"
)

// Defaults
const (
	DefaultMaxResponseBytes int64         = 10 * 1024 * 1024
	DefaultMaxRedirects     int           = 5
	DefaultConnectTimeout   time.Duration = 10 * time.Second
	DefaultReadTimeout      time.Duration = 60 * time.Second
	DefaultUserAgent                      = "aocyber-webfetch/1.0"
)

// Errors
var (
	ErrPolicyViolation = errors.New("webfetch: policy violation")
	ErrTooManyRedirects = errors.New("webfetch: too many redirects")
	ErrResponseTooLarge = errors.New("webfetch: response exceeded MaxResponseBytes")
)

// Policy configures the safety controls.
type Policy struct {
	AllowedSchemes         []string  // default: http, https
	DenyPrivateIPs         bool      // default: true (set false for trusted intranet)
	DenyHostsRegexp        []string  // additional host patterns to block
	AllowHostsRegexp       []string  // explicit allowlist (overrides DenyPrivateIPs)
	MaxResponseBytes       int64
	MaxRedirects           int
	AllowedRedirectSchemes []string
	ConnectTimeout         time.Duration
	ReadTimeout            time.Duration
	UserAgent              string
	AdditionalHeaders      map[string]string
	// Resolver overrides DNS resolution (nil: system resolver).
	Resolver netguard.Resolver
}

// Result is a fetched HTTP response.
type Result struct {
	URL         string
	StatusCode  int
	ContentType string
	Body        []byte
	BytesRead   int64
	Headers     http.Header
	Truncated   bool
	Redirects   []string
}

// Client is the hardened HTTP client.
type Client struct {
	policy        Policy
	httpClient    *http.Client
	denyHosts     []*regexp.Regexp
	allowHosts    []*regexp.Regexp
}

// SafeDefault returns a Policy with safe defaults for fetching user-supplied URLs.
func SafeDefault() Policy {
	return Policy{
		AllowedSchemes:         []string{"http", "https"},
		DenyPrivateIPs:         true,
		MaxResponseBytes:       DefaultMaxResponseBytes,
		MaxRedirects:           DefaultMaxRedirects,
		AllowedRedirectSchemes: []string{"http", "https"},
		ConnectTimeout:         DefaultConnectTimeout,
		ReadTimeout:            DefaultReadTimeout,
		UserAgent:              DefaultUserAgent,
	}
}

// NewClient constructs a Client. Pass SafeDefault() if you want sane
// defaults; only override fields where the caller has a reason.
func NewClient(p Policy) (*Client, error) {
	p = applyDefaults(p)

	denyHosts, err := compileRegexps(p.DenyHostsRegexp)
	if err != nil {
		return nil, fmt.Errorf("webfetch: deny regexps: %w", err)
	}
	allowHosts, err := compileRegexps(p.AllowHostsRegexp)
	if err != nil {
		return nil, fmt.Errorf("webfetch: allow regexps: %w", err)
	}

	dialer := &net.Dialer{Timeout: p.ConnectTimeout}
	dial := dialer.DialContext
	if p.DenyPrivateIPs {
		// The address policy is enforced on the connected address by the
		// shared netguard dialer (one lookup, checked, then dialed — no
		// rebinding window). Allow-listed hosts bypass it, as before.
		guard := &netguard.Guard{
			Resolver:  p.Resolver,
			Dialer:    dialer,
			AllowHost: func(host string) bool { return matchAny(allowHosts, host) },
		}
		dial = guard.DialContext
	}
	transport := &http.Transport{
		Proxy:                 nil, // an env proxy would make the connected address the proxy's
		DialContext:           dial,
		ResponseHeaderTimeout: p.ReadTimeout,
		ExpectContinueTimeout: time.Second,
		TLSHandshakeTimeout:   p.ConnectTimeout,
	}

	c := &Client{
		policy:     p,
		denyHosts:  denyHosts,
		allowHosts: allowHosts,
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   p.ReadTimeout + p.ConnectTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= p.MaxRedirects {
				return ErrTooManyRedirects
			}
			if !c.schemeAllowed(req.URL.Scheme, p.AllowedRedirectSchemes) {
				return fmt.Errorf("%w: redirect scheme %q not allowed", ErrPolicyViolation, req.URL.Scheme)
			}
			if err := c.validateURL(req.URL); err != nil {
				return err
			}
			return nil
		},
	}
	c.httpClient = httpClient

	return c, nil
}

func applyDefaults(p Policy) Policy {
	if len(p.AllowedSchemes) == 0 {
		p.AllowedSchemes = []string{"http", "https"}
	}
	if p.MaxResponseBytes <= 0 {
		p.MaxResponseBytes = DefaultMaxResponseBytes
	}
	if p.MaxRedirects <= 0 {
		p.MaxRedirects = DefaultMaxRedirects
	}
	if len(p.AllowedRedirectSchemes) == 0 {
		p.AllowedRedirectSchemes = p.AllowedSchemes
	}
	if p.ConnectTimeout <= 0 {
		p.ConnectTimeout = DefaultConnectTimeout
	}
	if p.ReadTimeout <= 0 {
		p.ReadTimeout = DefaultReadTimeout
	}
	if p.UserAgent == "" {
		p.UserAgent = DefaultUserAgent
	}
	return p
}

// Fetch fetches the URL with the configured policy.
func (c *Client) Fetch(ctx context.Context, target string) (*Result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("webfetch: new request: %w", err)
	}
	return c.FetchWith(ctx, req)
}

// FetchWith fetches with a caller-prepared http.Request (use to set custom
// methods, bodies, headers).
func (c *Client) FetchWith(ctx context.Context, req *http.Request) (*Result, error) {
	if err := c.validateURL(req.URL); err != nil {
		return nil, err
	}
	if !c.schemeAllowed(req.URL.Scheme, c.policy.AllowedSchemes) {
		return nil, fmt.Errorf("%w: scheme %q not allowed", ErrPolicyViolation, req.URL.Scheme)
	}

	if req.Header == nil {
		req.Header = make(http.Header)
	}
	req.Header.Set("User-Agent", c.policy.UserAgent)
	for k, v := range c.policy.AdditionalHeaders {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// The dial-time egress guard refused the connected address.
		if errors.Is(err, netguard.ErrBlocked) && !errors.Is(err, ErrPolicyViolation) {
			return nil, fmt.Errorf("%w: %w", ErrPolicyViolation, err)
		}
		// Surface our policy errors verbatim (CheckRedirect may have set them).
		if errors.Is(err, ErrTooManyRedirects) || errors.Is(err, ErrPolicyViolation) {
			return nil, err
		}
		// Unwrap wrapped policy errors from the http stdlib redirect path.
		if uerr, ok := err.(*url.Error); ok {
			if errors.Is(uerr.Err, ErrTooManyRedirects) || errors.Is(uerr.Err, ErrPolicyViolation) {
				return nil, uerr.Err
			}
		}
		return nil, fmt.Errorf("webfetch: request: %w", err)
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, c.policy.MaxResponseBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("webfetch: read body: %w", err)
	}

	truncated := int64(len(body)) > c.policy.MaxResponseBytes
	if truncated {
		body = body[:c.policy.MaxResponseBytes]
	}

	res := &Result{
		URL:         resp.Request.URL.String(),
		StatusCode:  resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		Body:        body,
		BytesRead:   int64(len(body)),
		Headers:     resp.Header,
		Truncated:   truncated,
	}

	if truncated {
		// Note: truncation isn't a hard error — caller can decide. We expose
		// the flag so policy-strict consumers can wrap it as ErrResponseTooLarge.
		_ = ErrResponseTooLarge // referenced for godoc
	}

	return res, nil
}

// validateURL applies SSRF / scheme / host policy.
func (c *Client) validateURL(u *url.URL) error {
	if u == nil {
		return fmt.Errorf("%w: empty URL", ErrPolicyViolation)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("%w: no host in URL", ErrPolicyViolation)
	}

	// Allowlist short-circuits everything else.
	if matchAny(c.allowHosts, host) {
		return nil
	}

	// Deny patterns.
	if matchAny(c.denyHosts, host) {
		return fmt.Errorf("%w: host %q matches deny pattern", ErrPolicyViolation, host)
	}

	// Literal IPs and well-known internal names are refused here, before any
	// DNS. Resolved addresses are checked at dial time by netguard.Guard —
	// the only place a hostname's answer is trusted, so it is the address
	// actually connected to.
	if c.policy.DenyPrivateIPs {
		if err := netguard.CheckHost(host); err != nil {
			return fmt.Errorf("%w: %w", ErrPolicyViolation, err)
		}
	}
	return nil
}

// schemeAllowed returns true if the scheme is in the allow list.
func (c *Client) schemeAllowed(scheme string, allowed []string) bool {
	for _, a := range allowed {
		if strings.EqualFold(a, scheme) {
			return true
		}
	}
	return false
}

func compileRegexps(patterns []string) ([]*regexp.Regexp, error) {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("compile %q: %w", p, err)
		}
		out = append(out, re)
	}
	return out, nil
}

func matchAny(rxs []*regexp.Regexp, s string) bool {
	for _, rx := range rxs {
		if rx.MatchString(s) {
			return true
		}
	}
	return false
}
