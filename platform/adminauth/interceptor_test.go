package adminauth_test

// Test list:
// - TestNewAdminContextInterceptor/nil_resolver_panics
// - TestInterceptor/missing_tls_state_returns_internal
// - TestInterceptor/no_verified_chain_returns_unauthenticated
// - TestInterceptor/empty_cn_returns_unauthenticated
// - TestInterceptor/unknown_admin_returns_permission_denied
// - TestInterceptor/resolver_infra_error_returns_internal
// - TestInterceptor/happy_path_populates_admin_identity_in_ctx
// - TestInterceptor/super_admin_has_tenant_access_for_any_target

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"go.aocyber.ai/eden-platform-go/platform/adminauth"
)

// fakeResolver — inline test double, hand-built, no LLM-generated data.
type fakeResolver struct {
	knownCN  string
	identity adminauth.AdminIdentity
	infraErr error
}

func (f *fakeResolver) ResolveFromCN(_ context.Context, cn string) (adminauth.AdminIdentity, error) {
	if f.infraErr != nil {
		return adminauth.AdminIdentity{}, f.infraErr
	}
	if cn != f.knownCN {
		return adminauth.AdminIdentity{}, adminauth.ErrUnknownAdmin
	}
	return f.identity, nil
}

// stubRequest is a minimal connect.AnyRequest stub for unary interceptor tests.
// Embedding connect.AnyRequest (an interface) gives nil method tables; the
// interceptor under test never invokes any method on the request, so this is
// safe for the cases we cover.
type stubRequest struct{ connect.AnyRequest }

// makeTLSStateWithCN builds a *tls.ConnectionState with a verified chain
// containing a single cert whose Subject.CommonName == cn.
func makeTLSStateWithCN(cn string) *tls.ConnectionState {
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: cn}}
	return &tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{{cert}},
	}
}

// ctxWithTLSState routes through the public WithTLSConnectionState
// http.Handler so tests use the same context-key plumbing as production.
func ctxWithTLSState(t *testing.T, state *tls.ConnectionState) context.Context {
	t.Helper()
	var captured context.Context
	handler := adminauth.WithTLSConnectionState(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		captured = r.Context()
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = state
	handler.ServeHTTP(httptest.NewRecorder(), req)
	require.NotNil(t, captured, "WithTLSConnectionState should pass through to handler")
	return captured
}

func TestNewAdminContextInterceptor_NilResolverPanics(t *testing.T) {
	require.Panics(t, func() { adminauth.NewAdminContextInterceptor(nil) })
}

func TestInterceptor_MissingTLSStateReturnsInternal(t *testing.T) {
	resolver := &fakeResolver{}
	icpt := adminauth.NewAdminContextInterceptor(resolver)
	wrapped := icpt.WrapUnary(func(_ context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		return nil, nil
	})
	_, err := wrapped(context.Background(), stubRequest{})
	require.Error(t, err)
	var ce *connect.Error
	require.True(t, errors.As(err, &ce))
	require.Equal(t, connect.CodeInternal, ce.Code())
}

func TestInterceptor_NoVerifiedChainReturnsUnauthenticated(t *testing.T) {
	// TLS state present but no verified chains → mtls.ExtractPeerCommonName returns ErrNoVerifiedChain.
	state := &tls.ConnectionState{ServerName: "test.local"}
	ctx := ctxWithTLSState(t, state)

	resolver := &fakeResolver{}
	icpt := adminauth.NewAdminContextInterceptor(resolver)
	wrapped := icpt.WrapUnary(func(_ context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		return nil, nil
	})
	_, err := wrapped(ctx, stubRequest{})
	require.Error(t, err)
	var ce *connect.Error
	require.True(t, errors.As(err, &ce))
	require.Equal(t, connect.CodeUnauthenticated, ce.Code())
}

func TestInterceptor_EmptyCNReturnsUnauthenticated(t *testing.T) {
	// Verified chain present, but leaf Subject.CommonName is empty.
	state := makeTLSStateWithCN("")
	ctx := ctxWithTLSState(t, state)

	resolver := &fakeResolver{knownCN: "aoid-admin-acme"}
	icpt := adminauth.NewAdminContextInterceptor(resolver)
	wrapped := icpt.WrapUnary(func(_ context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		return nil, nil
	})
	_, err := wrapped(ctx, stubRequest{})
	require.Error(t, err)
	var ce *connect.Error
	require.True(t, errors.As(err, &ce))
	require.Equal(t, connect.CodeUnauthenticated, ce.Code())
	require.ErrorIs(t, err, adminauth.ErrMissingCN)
}

func TestInterceptor_UnknownAdminReturnsPermissionDenied(t *testing.T) {
	state := makeTLSStateWithCN("nobody")
	ctx := ctxWithTLSState(t, state)

	resolver := &fakeResolver{knownCN: "aoid-admin-acme"}
	icpt := adminauth.NewAdminContextInterceptor(resolver)
	wrapped := icpt.WrapUnary(func(_ context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		return nil, nil
	})
	_, err := wrapped(ctx, stubRequest{})
	require.Error(t, err)
	var ce *connect.Error
	require.True(t, errors.As(err, &ce))
	require.Equal(t, connect.CodePermissionDenied, ce.Code())
	require.ErrorIs(t, err, adminauth.ErrUnknownAdmin)
}

func TestInterceptor_ResolverInfraErrorReturnsInternal(t *testing.T) {
	state := makeTLSStateWithCN("aoid-admin-acme")
	ctx := ctxWithTLSState(t, state)

	resolver := &fakeResolver{infraErr: errors.New("db down")}
	icpt := adminauth.NewAdminContextInterceptor(resolver)
	wrapped := icpt.WrapUnary(func(_ context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		return nil, nil
	})
	_, err := wrapped(ctx, stubRequest{})
	require.Error(t, err)
	var ce *connect.Error
	require.True(t, errors.As(err, &ce))
	require.Equal(t, connect.CodeInternal, ce.Code())
}

func TestInterceptor_HappyPathPopulatesAdminIdentityInCtx(t *testing.T) {
	tenantID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	want := adminauth.AdminIdentity{
		SubjectCN:    "aoid-admin-acme",
		TenantID:     tenantID,
		IsSuperAdmin: false,
		Roles:        []string{"tenant_admin"},
	}
	state := makeTLSStateWithCN("aoid-admin-acme")
	ctx := ctxWithTLSState(t, state)

	resolver := &fakeResolver{knownCN: "aoid-admin-acme", identity: want}
	icpt := adminauth.NewAdminContextInterceptor(resolver)

	var got *adminauth.AdminIdentity
	wrapped := icpt.WrapUnary(func(innerCtx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		got = adminauth.AdminIdentityFromContext(innerCtx)
		return nil, nil
	})

	_, err := wrapped(ctx, stubRequest{})
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, want.SubjectCN, got.SubjectCN)
	require.Equal(t, want.TenantID, got.TenantID)
	require.Equal(t, want.IsSuperAdmin, got.IsSuperAdmin)
	require.Equal(t, want.Roles, got.Roles)
}

func TestInterceptor_SuperAdminHasTenantAccessForAnyTarget(t *testing.T) {
	want := adminauth.AdminIdentity{
		SubjectCN:    "aoid-superadmin",
		TenantID:     uuid.Nil,
		IsSuperAdmin: true,
		Roles:        []string{"super_admin"},
	}
	state := makeTLSStateWithCN("aoid-superadmin")
	ctx := ctxWithTLSState(t, state)

	resolver := &fakeResolver{knownCN: "aoid-superadmin", identity: want}
	icpt := adminauth.NewAdminContextInterceptor(resolver)

	var got *adminauth.AdminIdentity
	wrapped := icpt.WrapUnary(func(innerCtx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		got = adminauth.AdminIdentityFromContext(innerCtx)
		return nil, nil
	})
	_, err := wrapped(ctx, stubRequest{})
	require.NoError(t, err)
	require.NotNil(t, got)
	require.True(t, got.IsSuperAdmin)
	require.True(t, got.HasTenantAccess(uuid.Nil))
	require.True(t, got.HasTenantAccess(uuid.MustParse("22222222-2222-2222-2222-222222222222")))
}

// fakeStreamConn is a minimal connect.StreamingHandlerConn; the interceptor
// under test only reads the context, never the conn.
type fakeStreamConn struct{ connect.StreamingHandlerConn }

func runStreaming(t *testing.T, ctx context.Context, r adminauth.AdminIdentityResolver) (called bool, seen *adminauth.AdminIdentity, err error) {
	t.Helper()
	icpt := adminauth.NewAdminContextInterceptor(r)
	handler := icpt.WrapStreamingHandler(func(ctx context.Context, _ connect.StreamingHandlerConn) error {
		called = true
		seen = adminauth.AdminIdentityFromContext(ctx)
		return nil
	})
	err = handler(ctx, fakeStreamConn{})
	return called, seen, err
}

// Streaming companion to #78: without this, every admin stream reaches the
// tenant-scope check with no identity (now: Unauthenticated), and before
// #78 reached the handler with no admin check at all.
func TestInterceptor_Streaming_HappyPathPopulatesAdminIdentity(t *testing.T) {
	tenant := uuid.New()
	r := &fakeResolver{knownCN: "aoid-admin-acme", identity: adminauth.AdminIdentity{SubjectCN: "aoid-admin-acme", TenantID: tenant}}
	called, seen, err := runStreaming(t, ctxWithTLSState(t, makeTLSStateWithCN("aoid-admin-acme")), r)
	require.NoError(t, err)
	require.True(t, called)
	require.NotNil(t, seen, "streaming handler must see the AdminIdentity")
	require.Equal(t, tenant, seen.TenantID)
}

func TestInterceptor_Streaming_UnknownAdminIsPermissionDenied(t *testing.T) {
	r := &fakeResolver{knownCN: "aoid-admin-acme"}
	called, _, err := runStreaming(t, ctxWithTLSState(t, makeTLSStateWithCN("aoid-admin-evil")), r)
	require.False(t, called)
	var ce *connect.Error
	require.True(t, errors.As(err, &ce))
	require.Equal(t, connect.CodePermissionDenied, ce.Code())
}

func TestInterceptor_Streaming_MissingTLSStateIsInternal(t *testing.T) {
	called, _, err := runStreaming(t, context.Background(), &fakeResolver{knownCN: "x"})
	require.False(t, called)
	var ce *connect.Error
	require.True(t, errors.As(err, &ce))
	require.Equal(t, connect.CodeInternal, ce.Code())
}
