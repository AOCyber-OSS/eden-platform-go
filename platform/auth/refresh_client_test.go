package auth_test

// Issue #80: client-bound refresh tokens at the auth.Service layer.

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.aocyber.ai/eden-platform-go/platform/auth"
	"go.aocyber.ai/eden-platform-go/platform/devstore"
)

// setupWindowService is setupAuthService with an explicit, open legacy window
// so the tests do not depend on DefaultLegacyUntypedCutoff or today's date.
func setupWindowService(t *testing.T, cutoff time.Time) (*auth.Service, *auth.JWTManager) {
	t.Helper()
	backend := devstore.NewMemoryBackend()
	jm, err := auth.NewJWTManager(auth.JWTConfig{
		Issuer:              "test",
		AccessTokenExpiry:   time.Minute,
		RefreshTokenExpiry:  time.Hour,
		LegacyUntypedCutoff: cutoff,
	})
	if err != nil {
		t.Fatalf("NewJWTManager: %v", err)
	}
	return auth.NewService(backend.AuthStore(), jm, auth.NewPasswordHasher()), jm
}

// legacyRefreshFor signs a pre-#80 refresh token (no token_use, no aud,
// 7-day lifetime) for userID and remembers it, as the old AO ID did.
func legacyRefreshFor(t *testing.T, svc *auth.Service, jm *auth.JWTManager, user auth.User) string {
	t.Helper()
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.GetSigningMethod("ML-DSA-65"), jwt.MapClaims{
		"sub": user.ID.String(), "iss": "test", "jti": "legacy",
		"exp": now.Add(7 * 24 * time.Hour).Unix(), "iat": now.Unix(),
	})
	tok.Header["kid"] = jm.ActiveKID()
	s, err := tok.SignedString(jm.ActivePrivateKey())
	if err != nil {
		t.Fatalf("sign legacy refresh: %v", err)
	}
	if err := svc.RememberRefreshToken(context.Background(), user.ID, s, now.Add(7*24*time.Hour)); err != nil {
		t.Fatalf("remember legacy refresh: %v", err)
	}
	return s
}

// clientBoundRefreshFor mints and remembers a refresh token bound to clientID.
func clientBoundRefreshFor(t *testing.T, svc *auth.Service, jm *auth.JWTManager, user auth.User, clientID string) string {
	t.Helper()
	rt, err := jm.CreateClientRefreshToken(user.ID.String(), clientID)
	if err != nil {
		t.Fatalf("CreateClientRefreshToken: %v", err)
	}
	if err := svc.RememberRefreshToken(context.Background(), user.ID, rt, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("remember: %v", err)
	}
	return rt
}

func audOf(t *testing.T, jm *auth.JWTManager, rt string) []string {
	t.Helper()
	c, err := jm.ValidateRefreshTokenClaims(rt)
	if err != nil {
		t.Fatalf("ValidateRefreshTokenClaims: %v", err)
	}
	return c.Audience
}

// TestService_RefreshToken_RejectsClientBoundToken: the generic refresh path
// must not redeem a client-bound token, or the binding is bypassed.
func TestService_RefreshToken_RejectsClientBoundToken(t *testing.T) {
	svc, jm := setupWindowService(t, time.Now().Add(time.Hour))
	ctx := context.Background()
	resp, err := svc.SignUp(ctx, "bound@example.com", "password123", "Bound")
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	rt := clientBoundRefreshFor(t, svc, jm, resp.User, "client-a")
	if _, err := svc.RefreshToken(ctx, rt); err == nil {
		t.Fatal("RefreshToken redeemed a client-bound refresh token")
	}
	// And it was not burned: the owning client can still redeem it.
	if _, err := svc.RefreshTokenForClient(ctx, rt, "client-a"); err != nil {
		t.Fatalf("owner redeem after rejected generic attempt: %v", err)
	}
}

// TestService_RefreshTokenForClient_RejectsUnboundTypedToken: a typed refresh
// token from a password login carries no client and is not an OAuth grant.
func TestService_RefreshTokenForClient_RejectsUnboundTypedToken(t *testing.T) {
	svc, _ := setupWindowService(t, time.Now().Add(time.Hour))
	ctx := context.Background()
	resp, err := svc.SignUp(ctx, "unbound@example.com", "password123", "Unbound")
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if _, err := svc.RefreshTokenForClient(ctx, resp.RefreshToken, "client-a"); err == nil {
		t.Fatal("RefreshTokenForClient redeemed an unbound typed refresh token")
	}
}

// TestService_RefreshTokenForClient_RotationStaysBound: the rotated token is
// bound to the same client, so a second hop by another client still fails.
func TestService_RefreshTokenForClient_RotationStaysBound(t *testing.T) {
	svc, jm := setupWindowService(t, time.Now().Add(time.Hour))
	ctx := context.Background()
	resp, err := svc.SignUp(ctx, "rot@example.com", "password123", "Rot")
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	rt := clientBoundRefreshFor(t, svc, jm, resp.User, "client-a")
	next, err := svc.RefreshTokenForClient(ctx, rt, "client-a")
	if err != nil {
		t.Fatalf("RefreshTokenForClient: %v", err)
	}
	if aud := audOf(t, jm, next.RefreshToken); len(aud) != 1 || aud[0] != "client-a" {
		t.Errorf("rotated refresh aud = %v, want [client-a]", aud)
	}
	if _, err := svc.RefreshTokenForClient(ctx, next.RefreshToken, "client-b"); err == nil {
		t.Error("rotated token redeemed by another client")
	}
}

// TestService_RefreshTokenForClient_LegacyWindow: a pre-#80 refresh token
// (unbound) is redeemable in the window and re-issued bound to the client;
// after the cutoff it is rejected.
func TestService_RefreshTokenForClient_LegacyWindow(t *testing.T) {
	svc, jm := setupWindowService(t, time.Now().Add(time.Hour))
	ctx := context.Background()
	resp, err := svc.SignUp(ctx, "legacy@example.com", "password123", "Legacy")
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	next, err := svc.RefreshTokenForClient(ctx, legacyRefreshFor(t, svc, jm, resp.User), "client-a")
	if err != nil {
		t.Fatalf("legacy refresh rejected in window: %v", err)
	}
	if aud := audOf(t, jm, next.RefreshToken); len(aud) != 1 || aud[0] != "client-a" {
		t.Errorf("re-issued refresh aud = %v, want [client-a]", aud)
	}

	closed, cjm := setupWindowService(t, time.Now().Add(-time.Second))
	resp2, err := closed.SignUp(ctx, "legacy2@example.com", "password123", "Legacy")
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if _, err := closed.RefreshTokenForClient(ctx, legacyRefreshFor(t, closed, cjm, resp2.User), "client-a"); err == nil {
		t.Error("legacy refresh accepted after the cutoff")
	}
}

// TestService_RefreshTokenForClient_FederationNeedsCompany: the federation
// audience is honoured only on a company-bound token.
func TestService_RefreshTokenForClient_FederationNeedsCompany(t *testing.T) {
	svc, jm := setupWindowService(t, time.Now().Add(time.Hour))
	ctx := context.Background()
	resp, err := svc.SignUp(ctx, "fedc@example.com", "password123", "Fed")
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	rt := clientBoundRefreshFor(t, svc, jm, resp.User, auth.FederationRefreshAudience)
	if _, err := svc.RefreshTokenForClient(ctx, rt, "client-a"); err == nil {
		t.Fatal("company-less federation-audience token redeemed")
	}
}
