package auth_test

// Refresh rotation must be single-use under concurrency: two redeems of the
// same refresh token racing each other yield exactly one new token pair.

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestRefresh_ConcurrentRedeemSingleUse(t *testing.T) {
	svc, jm := setupWindowService(t, time.Now().Add(time.Hour))
	ctx := context.Background()
	up, err := svc.SignUp(ctx, "race@example.com", "password123", "Race")
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	upc, _ := jm.ValidateAccessToken(up.AccessToken)

	const rounds, racers = 30, 8
	for r := 0; r < rounds; r++ {
		rt, err := jm.CreateCompanyRefreshToken(up.User.ID.String(), upc.CompanyID)
		if err != nil {
			t.Fatalf("mint: %v", err)
		}
		if err := svc.RememberRefreshToken(ctx, up.User.ID, rt, time.Now().Add(time.Hour)); err != nil {
			t.Fatalf("remember: %v", err)
		}
		var (
			wg   sync.WaitGroup
			mu   sync.Mutex
			wins int
		)
		start := make(chan struct{})
		for i := 0; i < racers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if _, err := svc.RefreshToken(ctx, rt); err == nil {
					mu.Lock()
					wins++
					mu.Unlock()
				}
			}()
		}
		close(start)
		wg.Wait()
		if wins != 1 {
			t.Fatalf("round %d: %d concurrent redeems succeeded, want exactly 1", r, wins)
		}
	}
}
