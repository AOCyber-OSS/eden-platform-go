package devstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.aocyber.ai/eden-platform-go/platform/auth"
)

// TestAuthStore_ConsumeRefreshToken: the auth.RefreshTokenConsumer contract.
// Consuming an active token succeeds once; a second consume, or one of a
// token never issued, is auth.ErrRefreshTokenNotActive.
func TestAuthStore_ConsumeRefreshToken(t *testing.T) {
	store := NewMemoryBackend().AuthStore()
	var c auth.RefreshTokenConsumer = store
	ctx := context.Background()
	if err := store.CreateRefreshToken(ctx, uuid.New(), "h1", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := c.ConsumeRefreshToken(ctx, "h1"); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if err := c.ConsumeRefreshToken(ctx, "h1"); !errors.Is(err, auth.ErrRefreshTokenNotActive) {
		t.Fatalf("second consume err = %v, want ErrRefreshTokenNotActive", err)
	}
	if err := c.ConsumeRefreshToken(ctx, "never"); !errors.Is(err, auth.ErrRefreshTokenNotActive) {
		t.Fatalf("unknown consume err = %v, want ErrRefreshTokenNotActive", err)
	}
}
