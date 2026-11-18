package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	"github.com/google/uuid"
	"go.aocyber.ai/eden-platform-go/platform/adminauth"
	"go.aocyber.ai/eden-platform-go/platform/auth"
	"go.aocyber.ai/eden-platform-go/platform/rbac"
)

// fakeStreamConn is a minimal connect.StreamingHandlerConn for interceptor tests.
type fakeStreamConn struct {
	procedure string
	header    http.Header
}

func newFakeStreamConn(procedure, authHeader string) *fakeStreamConn {
	h := http.Header{}
	if authHeader != "" {
		h.Set("Authorization", authHeader)
	}
	return &fakeStreamConn{procedure: procedure, header: h}
}

func (f *fakeStreamConn) Spec() connect.Spec {
	return connect.Spec{Procedure: f.procedure, StreamType: connect.StreamTypeServer}
}
func (f *fakeStreamConn) Peer() connect.Peer           { return connect.Peer{} }
func (f *fakeStreamConn) Receive(any) error            { return io.EOF }
func (f *fakeStreamConn) RequestHeader() http.Header   { return f.header }
func (f *fakeStreamConn) Send(any) error               { return nil }
func (f *fakeStreamConn) ResponseHeader() http.Header  { return http.Header{} }
func (f *fakeStreamConn) ResponseTrailer() http.Header { return http.Header{} }

func newTestJWTManager(t *testing.T) *auth.JWTManager {
	t.Helper()
	m, err := auth.NewJWTManager(auth.JWTConfig{
		Issuer:            "test",
		AccessTokenExpiry: time.Minute,
	})
	if err != nil {
		t.Fatalf("NewJWTManager: %v", err)
	}
	return m
}

// TestAuthInterceptor_Streaming_RejectsMissingOrInvalidBearer locks in the fix
// for the dormant streaming bypass: prior to this commit, NewAuthInterceptor
// returned connect.UnaryInterceptorFunc, whose WrapStreamingHandler is a
// no-op pass-through. Streaming RPCs reached the handler without auth.
func TestAuthInterceptor_Streaming_RejectsMissingOrInvalidBearer(t *testing.T) {
	mgr := newTestJWTManager(t)
	interceptor := NewAuthInterceptor(mgr, nil)

	cases := []struct {
		name, header string
	}{
		{"missing_header", ""},
		{"not_bearer_scheme", "Basic abc"},
		{"malformed_bearer", "Bearer garbage.not.a.token"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			invoked := false
			handler := connect.StreamingHandlerFunc(func(ctx context.Context, conn connect.StreamingHandlerConn) error {
				invoked = true
				return nil
			})
			wrapped := interceptor.WrapStreamingHandler(handler)

			conn := newFakeStreamConn("/Test/Stream", tc.header)
			err := wrapped(context.Background(), conn)

			var connErr *connect.Error
			if !errors.As(err, &connErr) {
				t.Fatalf("got err type %T (%v), want *connect.Error", err, err)
			}
			if connErr.Code() != connect.CodeUnauthenticated {
				t.Fatalf("got code %v, want CodeUnauthenticated", connErr.Code())
			}
			if invoked {
				t.Fatal("handler was invoked despite auth failure — security regression")
			}
		})
	}
}

// TestAuthInterceptor_Streaming_PopulatesClaimsViaCanonicalKey asserts that on
// a valid Bearer the streaming interceptor injects claims that are readable
// via BOTH platform/server.ClaimsFromContext (the local shim) AND
// platform/auth.ClaimsFromContext (the canonical helper). This is the
// streaming-side mirror of
// platform/auth/require_test.go:roundtrip_via_platform_server_re_export and
// guards the most likely regression — a future refactor that drifts the two
// context keys apart again.
func TestAuthInterceptor_Streaming_PopulatesClaimsViaCanonicalKey(t *testing.T) {
	mgr := newTestJWTManager(t)
	userID := uuid.NewString()
	companyID := uuid.NewString()
	token, err := mgr.CreateAccessToken(userID, companyID, "admin", 80, []string{companyID})
	if err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}

	interceptor := NewAuthInterceptor(mgr, nil)

	var (
		serverShimClaims *auth.Claims
		canonicalClaims  *auth.Claims
	)
	handler := connect.StreamingHandlerFunc(func(ctx context.Context, _ connect.StreamingHandlerConn) error {
		serverShimClaims = ClaimsFromContext(ctx)
		canonicalClaims = auth.ClaimsFromContext(ctx)
		return nil
	})
	wrapped := interceptor.WrapStreamingHandler(handler)

	conn := newFakeStreamConn("/Test/Stream", "Bearer "+token)
	if err := wrapped(context.Background(), conn); err != nil {
		t.Fatalf("wrapped streaming handler: unexpected err %v", err)
	}

	if serverShimClaims == nil {
		t.Fatal("server.ClaimsFromContext returned nil — streaming did not populate claims")
	}
	if canonicalClaims == nil {
		t.Fatal("auth.ClaimsFromContext returned nil — streaming bypassed canonical key (bridge contract regression)")
	}
	if serverShimClaims.UserID != userID || canonicalClaims.UserID != userID {
		t.Fatalf("UserID mismatch: shim=%q canonical=%q want %q",
			serverShimClaims.UserID, canonicalClaims.UserID, userID)
	}
	if canonicalClaims.CompanyID != companyID {
		t.Fatalf("canonical CompanyID = %q, want %q", canonicalClaims.CompanyID, companyID)
	}
}

// denyRBACStore yields a real Role but no permissions, so
// rbac.Enforcer.HasPermission returns (false, nil) for any check —
// exercising the RBAC denial path without an error code.
type denyRBACStore struct{}

func (denyRBACStore) GetRoleByID(_ context.Context, id uuid.UUID) (rbac.Role, error) {
	return rbac.Role{ID: id}, nil
}
func (denyRBACStore) ListRolesByCompany(context.Context, uuid.UUID) ([]rbac.Role, error) {
	return nil, nil
}
func (denyRBACStore) CreateRole(context.Context, uuid.UUID, string, string, rbac.RoleLevel) (rbac.Role, error) {
	return rbac.Role{}, errors.New("not implemented")
}
func (denyRBACStore) ListPermissionsByRole(context.Context, uuid.UUID) ([]rbac.Permission, error) {
	return nil, nil
}
func (denyRBACStore) ListAllPermissions(context.Context) ([]rbac.Permission, error) {
	return nil, nil
}
func (denyRBACStore) AddRolePermission(context.Context, uuid.UUID, uuid.UUID) error {
	return errors.New("not implemented")
}
func (denyRBACStore) GetUserRole(context.Context, uuid.UUID, uuid.UUID) (rbac.Role, error) {
	return rbac.Role{ID: uuid.New(), Level: 10, Name: "denied"}, nil
}
func (denyRBACStore) GetMembership(context.Context, uuid.UUID, uuid.UUID) (rbac.Membership, error) {
	return rbac.Membership{}, errors.New("no membership")
}
func (denyRBACStore) GetUserPermissions(context.Context, uuid.UUID, uuid.UUID) ([]rbac.Permission, error) {
	return nil, nil
}
func (denyRBACStore) AssignRoleToUser(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) error {
	return errors.New("not implemented")
}
func (denyRBACStore) CreateMembership(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) error {
	return errors.New("not implemented")
}
func (denyRBACStore) GetCompanyAncestors(context.Context, uuid.UUID) ([]rbac.CompanyAncestor, error) {
	return nil, nil
}
func (denyRBACStore) GetMembershipInCompany(context.Context, uuid.UUID, uuid.UUID) (*rbac.Membership, error) {
	return nil, errors.New("no membership")
}

// TestRBACInterceptor_Streaming_DeniesWithoutPermission asserts that a
// streaming procedure with a declared permission requirement is rejected with
// CodePermissionDenied when the caller's RBAC role grants no matching
// permissions, and that the underlying handler is never invoked.
func TestRBACInterceptor_Streaming_DeniesWithoutPermission(t *testing.T) {
	procedure := "/wizards.v1.WizardService/GenerateStep"
	cfg := InterceptorConfig{
		ProcedurePermissions: map[string]Permission{
			procedure: {Feature: "wizards", Action: "generate"},
		},
	}
	enforcer := rbac.NewEnforcer(denyRBACStore{}, nil)
	interceptor := NewRBACInterceptor(enforcer, cfg)

	invoked := false
	handler := connect.StreamingHandlerFunc(func(ctx context.Context, _ connect.StreamingHandlerConn) error {
		invoked = true
		return nil
	})
	wrapped := interceptor.WrapStreamingHandler(handler)

	claims := &auth.Claims{
		UserID:    uuid.NewString(),
		CompanyID: uuid.NewString(),
		Role:      "viewer",
		RoleLevel: 10,
	}
	ctx := WithClaims(context.Background(), claims)
	conn := newFakeStreamConn(procedure, "")

	err := wrapped(ctx, conn)
	var connErr *connect.Error
	if !errors.As(err, &connErr) {
		t.Fatalf("got err type %T (%v), want *connect.Error", err, err)
	}
	if connErr.Code() != connect.CodePermissionDenied {
		t.Fatalf("got code %v, want CodePermissionDenied", connErr.Code())
	}
	if invoked {
		t.Fatal("streaming handler was invoked despite RBAC deny — security regression")
	}
}

// ---------------------------------------------------------------------------
// TenantScopeInterceptor on streaming RPCs (#78).
//
// Driven over a real HTTP/2 Connect server (server-stream + bidi) with a
// JSON codec on a plain struct, so the interceptor sees exactly what a
// generated handler would. A test-only interceptor stands in for
// adminauth's mTLS CN resolution and sets the AdminIdentity from headers.
// ---------------------------------------------------------------------------

type tenantMsg struct {
	TenantID string `json:"tenant_id"`
	Note     string `json:"note,omitempty"`
}

type testJSONCodec struct{}

func (testJSONCodec) Name() string                  { return "testjson" }
func (testJSONCodec) Marshal(v any) ([]byte, error) { return json.Marshal(v) }
func (testJSONCodec) Unmarshal(b []byte, v any) error {
	return json.Unmarshal(b, v)
}

// testAdminIdentityInterceptor sets the AdminIdentity from X-Test-Admin-Tenant
// / X-Test-Super-Admin headers, for unary and streaming handlers. No header
// means no identity.
type testAdminIdentityInterceptor struct{}

func identityFromHeader(h http.Header) (adminauth.AdminIdentity, bool) {
	if h.Get("X-Test-Super-Admin") == "1" {
		return adminauth.AdminIdentity{SubjectCN: "aoid-superadmin", IsSuperAdmin: true}, true
	}
	if raw := h.Get("X-Test-Admin-Tenant"); raw != "" {
		return adminauth.AdminIdentity{SubjectCN: "aoid-admin-test", TenantID: uuid.MustParse(raw), Roles: []string{"tenant_admin"}}, true
	}
	return adminauth.AdminIdentity{}, false
}

func (testAdminIdentityInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if id, ok := identityFromHeader(req.Header()); ok {
			ctx = adminauth.WithAdminIdentity(ctx, id)
		}
		return next(ctx, req)
	}
}

func (testAdminIdentityInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		if id, ok := identityFromHeader(conn.RequestHeader()); ok {
			ctx = adminauth.WithAdminIdentity(ctx, id)
		}
		return next(ctx, conn)
	}
}

func (testAdminIdentityInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

func tenantMsgExtractor(req connect.AnyRequest) (uuid.UUID, error) {
	m, ok := req.Any().(*tenantMsg)
	if !ok {
		return uuid.Nil, fmt.Errorf("unexpected message %T", req.Any())
	}
	if m.TenantID == "" {
		return uuid.Nil, ErrNoTargetTenant
	}
	return uuid.Parse(m.TenantID)
}

type streamFixture struct {
	server      *connect.Client[tenantMsg, tenantMsg]
	bidi        *connect.Client[tenantMsg, tenantMsg]
	bidiGreeter *connect.Client[tenantMsg, tenantMsg]

	mu   sync.Mutex
	seen []string // tenant ids the handlers actually received
}

func (f *streamFixture) record(m *tenantMsg) {
	f.mu.Lock()
	f.seen = append(f.seen, m.TenantID)
	f.mu.Unlock()
}

func (f *streamFixture) received() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.seen...)
}

func newStreamFixture(t *testing.T, opts ...TenantScopeOption) *streamFixture {
	t.Helper()
	f := &streamFixture{}
	handlerOpts := []connect.HandlerOption{
		connect.WithCodec(testJSONCodec{}),
		connect.WithInterceptors(testAdminIdentityInterceptor{}, NewTenantScopeInterceptor(tenantMsgExtractor, opts...)),
	}
	mux := http.NewServeMux()
	mux.Handle("/test.v1.Tenant/ServerStream", connect.NewServerStreamHandler("/test.v1.Tenant/ServerStream",
		func(ctx context.Context, req *connect.Request[tenantMsg], stream *connect.ServerStream[tenantMsg]) error {
			f.record(req.Msg)
			return stream.Send(&tenantMsg{TenantID: req.Msg.TenantID, Note: "secret-for-" + req.Msg.TenantID})
		}, handlerOpts...))
	mux.Handle("/test.v1.Tenant/Bidi", connect.NewBidiStreamHandler("/test.v1.Tenant/Bidi",
		func(ctx context.Context, stream *connect.BidiStream[tenantMsg, tenantMsg]) error {
			for {
				m, err := stream.Receive()
				if errors.Is(err, io.EOF) {
					return nil
				}
				if err != nil {
					return err
				}
				f.record(m)
				if err := stream.Send(&tenantMsg{TenantID: m.TenantID, Note: "secret-for-" + m.TenantID}); err != nil {
					return err
				}
			}
		}, handlerOpts...))
	// A handler that sends before it has received anything: the tenant is
	// not known yet, so the send must be refused (fail closed).
	mux.Handle("/test.v1.Tenant/BidiGreeter", connect.NewBidiStreamHandler("/test.v1.Tenant/BidiGreeter",
		func(ctx context.Context, stream *connect.BidiStream[tenantMsg, tenantMsg]) error {
			return stream.Send(&tenantMsg{Note: "greeting-before-any-request"})
		}, handlerOpts...))

	srv := httptest.NewUnstartedServer(mux)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)

	clientOpts := []connect.ClientOption{connect.WithCodec(testJSONCodec{})}
	f.server = connect.NewClient[tenantMsg, tenantMsg](srv.Client(), srv.URL+"/test.v1.Tenant/ServerStream", clientOpts...)
	f.bidi = connect.NewClient[tenantMsg, tenantMsg](srv.Client(), srv.URL+"/test.v1.Tenant/Bidi", clientOpts...)
	f.bidiGreeter = connect.NewClient[tenantMsg, tenantMsg](srv.Client(), srv.URL+"/test.v1.Tenant/BidiGreeter", clientOpts...)
	return f
}

var (
	streamOwnTenant   = uuid.MustParse("11111111-1111-1111-1111-111111111111")
	streamOtherTenant = uuid.MustParse("22222222-2222-2222-2222-222222222222")
)

type adminHeader func(http.Header)

func asTenantAdmin(tenant uuid.UUID) adminHeader {
	return func(h http.Header) { h.Set("X-Test-Admin-Tenant", tenant.String()) }
}

func asSuperAdmin() adminHeader { return func(h http.Header) { h.Set("X-Test-Super-Admin", "1") } }

func noAdmin() adminHeader { return func(http.Header) {} }

// callServerStream returns the notes received and the terminal error.
func callServerStream(t *testing.T, f *streamFixture, who adminHeader, target uuid.UUID) ([]string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req := connect.NewRequest(&tenantMsg{TenantID: target.String()})
	who(req.Header())
	stream, err := f.server.CallServerStream(ctx, req)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	var notes []string
	for stream.Receive() {
		notes = append(notes, stream.Msg().Note)
	}
	return notes, stream.Err()
}

// callBidi sends each target in turn, reading one reply per send. It stops
// at the first error and returns the replies seen so far plus that error.
func callBidi(t *testing.T, client *connect.Client[tenantMsg, tenantMsg], who adminHeader, targets ...uuid.UUID) ([]string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream := client.CallBidiStream(ctx)
	who(stream.RequestHeader())
	defer stream.CloseResponse()
	var notes []string
	if len(targets) == 0 {
		if err := stream.CloseRequest(); err != nil {
			return notes, err
		}
		m, err := stream.Receive()
		if err != nil {
			return notes, err
		}
		return append(notes, m.Note), nil
	}
	for _, target := range targets {
		if err := stream.Send(&tenantMsg{TenantID: target.String()}); err != nil && !errors.Is(err, io.EOF) {
			return notes, err
		}
		m, err := stream.Receive()
		if err != nil {
			return notes, err
		}
		notes = append(notes, m.Note)
	}
	_ = stream.CloseRequest()
	if _, err := stream.Receive(); err != nil && !errors.Is(err, io.EOF) {
		return notes, err
	}
	return notes, nil
}

func requireConnectCode(t *testing.T, err error, want connect.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("err = nil, want %v", want)
	}
	if got := connect.CodeOf(err); got != want {
		t.Fatalf("code = %v (%v), want %v", got, err, want)
	}
}

func TestTenantScope_ServerStream_WrongTenantAdminIsPermissionDenied(t *testing.T) {
	f := newStreamFixture(t)
	notes, err := callServerStream(t, f, asTenantAdmin(streamOwnTenant), streamOtherTenant)
	requireConnectCode(t, err, connect.CodePermissionDenied)
	if !errors.Is(err, ErrCrossTenantAccess) && !strings.Contains(err.Error(), "cross-tenant") {
		t.Fatalf("error %q should name the cross-tenant denial", err)
	}
	if len(notes) != 0 || len(f.received()) != 0 {
		t.Fatalf("wrong-tenant server stream reached the handler: notes=%v handler saw=%v", notes, f.received())
	}
}

func TestTenantScope_Bidi_WrongTenantFirstMessageIsPermissionDenied(t *testing.T) {
	f := newStreamFixture(t)
	notes, err := callBidi(t, f.bidi, asTenantAdmin(streamOwnTenant), streamOtherTenant)
	requireConnectCode(t, err, connect.CodePermissionDenied)
	if len(notes) != 0 || len(f.received()) != 0 {
		t.Fatalf("wrong-tenant bidi reached the handler: notes=%v handler saw=%v", notes, f.received())
	}
}

// Every message is checked, not just the first: an own-tenant opener must
// not unlock a cross-tenant follow-up on the same stream.
func TestTenantScope_Bidi_OwnThenWrongTenantIsPermissionDenied(t *testing.T) {
	f := newStreamFixture(t)
	notes, err := callBidi(t, f.bidi, asTenantAdmin(streamOwnTenant), streamOwnTenant, streamOtherTenant)
	requireConnectCode(t, err, connect.CodePermissionDenied)
	if got := f.received(); len(got) != 1 || got[0] != streamOwnTenant.String() {
		t.Fatalf("handler saw %v, want only the own-tenant message", got)
	}
	if len(notes) != 1 {
		t.Fatalf("client got %v, want exactly the own-tenant reply", notes)
	}
}

func TestTenantScope_Bidi_SendBeforeVerifiedMessageFailsClosed(t *testing.T) {
	f := newStreamFixture(t)
	notes, err := callBidi(t, f.bidiGreeter, asTenantAdmin(streamOwnTenant))
	if err == nil {
		t.Fatalf("handler sent %v before any tenant was verified", notes)
	}
	requireConnectCode(t, err, connect.CodePermissionDenied)
	if len(notes) != 0 {
		t.Fatalf("client received %v from an unverified stream", notes)
	}
}

func TestTenantScope_Streams_SameTenantAndSuperAdminPass(t *testing.T) {
	f := newStreamFixture(t)
	if notes, err := callServerStream(t, f, asTenantAdmin(streamOwnTenant), streamOwnTenant); err != nil || len(notes) != 1 {
		t.Fatalf("same-tenant server stream = %v, %v", notes, err)
	}
	if notes, err := callServerStream(t, f, asSuperAdmin(), streamOtherTenant); err != nil || len(notes) != 1 {
		t.Fatalf("super-admin server stream = %v, %v", notes, err)
	}
	if notes, err := callBidi(t, f.bidi, asTenantAdmin(streamOwnTenant), streamOwnTenant, streamOwnTenant); err != nil || len(notes) != 2 {
		t.Fatalf("same-tenant bidi = %v, %v", notes, err)
	}
	if notes, err := callBidi(t, f.bidi, asSuperAdmin(), streamOwnTenant, streamOtherTenant); err != nil || len(notes) != 2 {
		t.Fatalf("super-admin bidi = %v, %v", notes, err)
	}
}

func TestTenantScope_Streams_MissingIdentityIsUnauthenticated(t *testing.T) {
	f := newStreamFixture(t)
	_, err := callServerStream(t, f, noAdmin(), streamOwnTenant)
	requireConnectCode(t, err, connect.CodeUnauthenticated)
	_, err = callBidi(t, f.bidi, noAdmin(), streamOwnTenant)
	requireConnectCode(t, err, connect.CodeUnauthenticated)
	if got := f.received(); len(got) != 0 {
		t.Fatalf("unauthenticated streams reached the handler: %v", got)
	}
}

func TestTenantScope_Streams_DedicatedModeRefusesOtherTenantEvenForSuperAdmin(t *testing.T) {
	f := newStreamFixture(t, WithDedicatedTenant(streamOwnTenant))
	_, err := callServerStream(t, f, asSuperAdmin(), streamOtherTenant)
	requireConnectCode(t, err, connect.CodePermissionDenied)
	_, err = callBidi(t, f.bidi, asSuperAdmin(), streamOtherTenant)
	requireConnectCode(t, err, connect.CodePermissionDenied)
	if notes, err := callServerStream(t, f, asSuperAdmin(), streamOwnTenant); err != nil || len(notes) != 1 {
		t.Fatalf("dedicated tenant server stream = %v, %v", notes, err)
	}
}
