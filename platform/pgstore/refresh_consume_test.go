package pgstore_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"go.aocyber.ai/eden-platform-go/platform/auth"
)

// TestAuthStore_ConsumeRefreshToken: the auth.RefreshTokenConsumer contract
// against Postgres, including concurrent consumers of one token (exactly one
// wins: the UPDATE is conditional on revoked = false).
func TestAuthStore_ConsumeRefreshToken(t *testing.T) {
	backend := setupTestBackend(t)
	store := backend.AuthStore()
	var c auth.RefreshTokenConsumer = store
	ctx := context.Background()
	user, err := store.CreateUser(ctx, "consume@example.com", "hash", "Consume")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := store.CreateRefreshToken(ctx, user.ID, "h1", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := c.ConsumeRefreshToken(ctx, "h1"); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if err := c.ConsumeRefreshToken(ctx, "h1"); !errors.Is(err, auth.ErrRefreshTokenNotActive) {
		t.Fatalf("second consume err = %v, want ErrRefreshTokenNotActive", err)
	}

	if err := store.CreateRefreshToken(ctx, user.ID, "h2", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("create h2: %v", err)
	}
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		wins int
	)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if c.ConsumeRefreshToken(ctx, "h2") == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d concurrent consumes succeeded, want 1", wins)
	}
}
