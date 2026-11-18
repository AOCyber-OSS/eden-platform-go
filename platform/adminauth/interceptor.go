package adminauth

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"

	"go.aocyber.ai/eden-platform-go/platform/mtls"
)

// NewAdminContextInterceptor returns a Connect interceptor (unary and
// streaming handlers) that:
//  1. Reads *tls.ConnectionState from context (set by WithTLSConnectionState).
//  2. Extracts the peer's CommonName via platform/mtls.ExtractPeerCommonName.
//  3. Calls resolver.ResolveFromCN to map CN → AdminIdentity.
//  4. Stores the AdminIdentity in the request context for downstream code.
//
// Error mapping:
//
//	TLS state missing        → CodeInternal         (operator misconfig)
//	no verified chain        → CodeUnauthenticated  (mTLS not enforced / cert invalid)
//	empty CN                 → CodeUnauthenticated
//	resolver ErrUnknownAdmin → CodePermissionDenied
//	resolver other err       → CodeInternal         (infra failure)
//
// Panics if resolver is nil — callers MUST provide a resolver.
func NewAdminContextInterceptor(resolver AdminIdentityResolver) connect.Interceptor {
	if resolver == nil {
		panic("adminauth: NewAdminContextInterceptor requires a non-nil resolver")
	}
	return &adminContextInterceptor{resolver: resolver}
}

type adminContextInterceptor struct {
	resolver AdminIdentityResolver
}

var _ connect.Interceptor = (*adminContextInterceptor)(nil)

// resolve maps the verified mTLS peer to an AdminIdentity in ctx.
func (i *adminContextInterceptor) resolve(ctx context.Context) (context.Context, error) {
	state := TLSConnectionStateFromContext(ctx)
	if state == nil {
		return nil, connect.NewError(connect.CodeInternal,
			errors.New("adminauth: TLS state missing — wire WithTLSConnectionState before Connect mux"))
	}
	cn, err := mtls.ExtractPeerCommonName(state)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated,
			fmt.Errorf("adminauth: cn extract: %w", err))
	}
	if cn == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated, ErrMissingCN)
	}
	identity, err := i.resolver.ResolveFromCN(ctx, cn)
	switch {
	case errors.Is(err, ErrUnknownAdmin):
		return nil, connect.NewError(connect.CodePermissionDenied, err)
	case err != nil:
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("adminauth: resolver: %w", err))
	}
	return WithAdminIdentity(ctx, identity), nil
}

func (i *adminContextInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		ctx, err := i.resolve(ctx)
		if err != nil {
			return nil, err
		}
		return next(ctx, req)
	}
}

func (i *adminContextInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		ctx, err := i.resolve(ctx)
		if err != nil {
			return err
		}
		return next(ctx, conn)
	}
}

// WrapStreamingClient is a pass-through: this is a server-side interceptor.
func (i *adminContextInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}
