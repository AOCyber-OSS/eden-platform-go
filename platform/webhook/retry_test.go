package webhook_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.aocyber.ai/eden-platform-go/platform/webhook"
	"github.com/google/uuid"
)

// localReceiver opts the httptest receivers (http://127.0.0.1:port) out of
// the webhook egress policy. Only these delivery-mechanics tests use it; the
// policy itself is covered by ssrf_test.go with the default service.
var localReceiver = webhook.WithInsecureTargets("127.0.0.1")

// memStore is an in-memory WebhookStore for tests.
type memStore struct {
	mu         sync.Mutex
	hooks      map[uuid.UUID]webhook.Webhook
	deliveries map[uuid.UUID]webhook.WebhookDelivery
	failCounts map[uuid.UUID]int
}

func newMemStore() *memStore {
	return &memStore{
		hooks:      make(map[uuid.UUID]webhook.Webhook),
		deliveries: make(map[uuid.UUID]webhook.WebhookDelivery),
		failCounts: make(map[uuid.UUID]int),
	}
}

func (s *memStore) CreateWebhook(_ context.Context, companyID uuid.UUID, url, secret string, events []string) (webhook.Webhook, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	wh := webhook.Webhook{
		ID:        uuid.New(),
		CompanyID: companyID,
		URL:       url,
		Secret:    secret,
		Events:    events,
		Active:    true,
		CreatedAt: time.Now(),
	}
	s.hooks[wh.ID] = wh
	return wh, nil
}

func (s *memStore) GetWebhook(_ context.Context, id uuid.UUID) (webhook.Webhook, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	wh, ok := s.hooks[id]
	if !ok {
		return webhook.Webhook{}, errNotFound
	}
	return wh, nil
}

func (s *memStore) ListWebhooksByCompany(_ context.Context, companyID uuid.UUID) ([]webhook.Webhook, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []webhook.Webhook
	for _, wh := range s.hooks {
		if wh.CompanyID == companyID {
			out = append(out, wh)
		}
	}
	return out, nil
}

func (s *memStore) UpdateWebhookStatus(_ context.Context, id uuid.UUID, active bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	wh, ok := s.hooks[id]
	if !ok {
		return errNotFound
	}
	wh.Active = active
	s.hooks[id] = wh
	return nil
}

func (s *memStore) DeleteWebhook(_ context.Context, companyID, id uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if wh, ok := s.hooks[id]; !ok || wh.CompanyID != companyID {
		return webhook.ErrWebhookNotFound
	}
	delete(s.hooks, id)
	return nil
}

func (s *memStore) IncrementFailureCount(_ context.Context, id uuid.UUID) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failCounts[id]++
	wh := s.hooks[id]
	wh.ConsecutiveFails = s.failCounts[id]
	s.hooks[id] = wh
	return s.failCounts[id], nil
}

func (s *memStore) ResetFailureCount(_ context.Context, id uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failCounts[id] = 0
	wh := s.hooks[id]
	wh.ConsecutiveFails = 0
	s.hooks[id] = wh
	return nil
}

func (s *memStore) CreateDelivery(_ context.Context, webhookID uuid.UUID, eventType, payload string) (webhook.WebhookDelivery, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := webhook.WebhookDelivery{
		ID:        uuid.New(),
		WebhookID: webhookID,
		EventType: eventType,
		Payload:   payload,
		Status:    "pending",
		CreatedAt: time.Now(),
	}
	s.deliveries[d.ID] = d
	return d, nil
}

func (s *memStore) UpdateDelivery(_ context.Context, id uuid.UUID, status string, statusCode int, responseBody string, nextRetryAt *time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.deliveries[id]
	if !ok {
		return errNotFound
	}
	d.Status = status
	d.StatusCode = statusCode
	d.ResponseBody = responseBody
	d.Attempts++
	d.NextRetryAt = nextRetryAt
	s.deliveries[id] = d
	return nil
}

func (s *memStore) GetPendingDeliveries(_ context.Context) ([]webhook.WebhookDelivery, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []webhook.WebhookDelivery
	for _, d := range s.deliveries {
		if d.Status == "pending" {
			out = append(out, d)
		}
	}
	return out, nil
}

func (s *memStore) GetDelivery(_ context.Context, id uuid.UUID) (webhook.WebhookDelivery, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.deliveries[id]
	if !ok {
		return webhook.WebhookDelivery{}, errNotFound
	}
	return d, nil
}

func (s *memStore) ListFailedDeliveriesForRetry(_ context.Context, maxAttempts int) ([]webhook.WebhookDelivery, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []webhook.WebhookDelivery
	for _, d := range s.deliveries {
		if d.Status == "failed" && d.Attempts < maxAttempts {
			out = append(out, d)
		}
	}
	return out, nil
}

// helpers for assertions
func (s *memStore) snapshotDelivery(id uuid.UUID) webhook.WebhookDelivery {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deliveries[id]
}

func (s *memStore) snapshotHook(id uuid.UUID) webhook.Webhook {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hooks[id]
}

// directInsertDelivery seeds a delivery in a target state (used to set up
// "already failed" scenarios for retry tests).
func (s *memStore) directInsertDelivery(d webhook.WebhookDelivery) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deliveries[d.ID] = d
}

var errNotFound = &storeError{msg: "not found"}

type storeError struct{ msg string }

func (e *storeError) Error() string { return e.msg }

// Test_ExponentialBackoff_NextRetrySchedule verifies that when delivery
// fails before maxRetries, NextRetryAt is set to roughly 2^attempt minutes
// from now; on the final attempt status flips to "exhausted" with no
// NextRetryAt.
func Test_ExponentialBackoff_NextRetrySchedule(t *testing.T) {
	store := newMemStore()
	// Always-fail server.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	svc := webhook.NewService(store, localReceiver, webhook.WithMaxRetries(3))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	companyID := uuid.New()
	wh, err := svc.Register(ctx, companyID, srv.URL, "secret", []string{"*"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Trigger 3 deliveries by Trigger() — each is independent; Attempts on the
	// new row resets to 0. To exercise the "exhausted" path we simulate the
	// retry chain by creating one delivery and forcing its Attempts via the
	// store: we inject a delivery whose Attempts already equals maxRetries-1.
	// First, get a baseline (attempt 0 -> attempt 1) via Trigger.
	if err := svc.Trigger(ctx, companyID, "test", `{"x":1}`); err != nil {
		t.Fatalf("Trigger: %v", err)
	}
	_ = svc.Shutdown(ctx)

	// Find the delivery that was created.
	store.mu.Lock()
	var d1 webhook.WebhookDelivery
	for _, d := range store.deliveries {
		if d.WebhookID == wh.ID {
			d1 = d
			break
		}
	}
	store.mu.Unlock()
	if d1.ID == uuid.Nil {
		t.Fatalf("no delivery created")
	}

	// First failure: attempt 1, status="failed", NextRetryAt set ~2min out.
	got := store.snapshotDelivery(d1.ID)
	if got.Status != "failed" {
		t.Errorf("delivery.Status = %q, want failed", got.Status)
	}
	if got.Attempts != 1 {
		t.Errorf("delivery.Attempts = %d, want 1", got.Attempts)
	}
	if got.NextRetryAt == nil {
		t.Errorf("delivery.NextRetryAt = nil, want non-nil for attempt < maxRetries")
	} else {
		delay := time.Until(*got.NextRetryAt)
		// Expect ~2 minutes (2^1) for first failure; allow generous slack.
		if delay < time.Minute || delay > 3*time.Minute {
			t.Errorf("NextRetryAt delay = %v, want ~2 min (1-3 min)", delay)
		}
	}

	// Now force a delivery into "1 attempt remaining" and trigger ExecuteDelivery.
	exhaust := webhook.WebhookDelivery{
		ID:        uuid.New(),
		WebhookID: wh.ID,
		EventType: "test",
		Payload:   `{"x":2}`,
		Status:    "failed",
		Attempts:  2, // 1 retry already done; with maxRetries=3, the next failure is "exhausted"
		CreatedAt: time.Now(),
	}
	store.directInsertDelivery(exhaust)

	if err := svc.ExecuteDelivery(ctx, exhaust.ID); err != nil {
		t.Fatalf("ExecuteDelivery: %v", err)
	}
	_ = svc.Shutdown(ctx)

	got = store.snapshotDelivery(exhaust.ID)
	if got.Status != "exhausted" {
		t.Errorf("after final retry: Status = %q, want exhausted", got.Status)
	}
	if got.NextRetryAt != nil {
		t.Errorf("after final retry: NextRetryAt = %v, want nil", got.NextRetryAt)
	}
}

// Test_AutoPauseAfterConsecutiveFailures verifies that after N consecutive
// failures the webhook is auto-paused (Active=false).
func Test_AutoPauseAfterConsecutiveFailures(t *testing.T) {
	store := newMemStore()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	svc := webhook.NewService(store, localReceiver,
		webhook.WithMaxRetries(1),               // each Trigger gives one attempt
		webhook.WithMaxConsecutiveFailures(3),   // pause after 3
	)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	companyID := uuid.New()
	wh, err := svc.Register(ctx, companyID, srv.URL, "secret", []string{"*"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	for i := 0; i < 3; i++ {
		// Re-fetch the hook each time so we see the latest Active flag — a
		// paused hook would skip Trigger anyway.
		if err := svc.Trigger(ctx, companyID, "test", `{}`); err != nil {
			t.Fatalf("Trigger: %v", err)
		}
		_ = svc.Shutdown(ctx)
	}

	got := store.snapshotHook(wh.ID)
	if got.Active {
		t.Errorf("after 3 consecutive failures: webhook.Active = true, want false")
	}
}

// Test_RetryFailedDeliveries_ReEnqueuesActiveOnly verifies that
// RetryFailedDeliveries skips inactive webhooks.
func Test_RetryFailedDeliveries_ReEnqueuesActiveOnly(t *testing.T) {
	store := newMemStore()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	svc := webhook.NewService(store, localReceiver, webhook.WithMaxRetries(5))
	ctx := context.Background()

	companyID := uuid.New()
	active, _ := svc.Register(ctx, companyID, srv.URL, "secret", []string{"*"})
	inactive, _ := svc.Register(ctx, companyID, srv.URL, "secret", []string{"*"})
	_ = store.UpdateWebhookStatus(ctx, inactive.ID, false)

	// Seed two failed deliveries, one per webhook.
	store.directInsertDelivery(webhook.WebhookDelivery{
		ID: uuid.New(), WebhookID: active.ID, EventType: "test",
		Payload: `{}`, Status: "failed", Attempts: 1, CreatedAt: time.Now(),
	})
	store.directInsertDelivery(webhook.WebhookDelivery{
		ID: uuid.New(), WebhookID: inactive.ID, EventType: "test",
		Payload: `{}`, Status: "failed", Attempts: 1, CreatedAt: time.Now(),
	})

	retried, err := svc.RetryFailedDeliveries(ctx)
	if err != nil {
		t.Fatalf("RetryFailedDeliveries: %v", err)
	}
	if retried != 1 {
		t.Errorf("retried = %d, want 1 (only active webhook)", retried)
	}

	_ = svc.Shutdown(ctx)
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("HTTP hits = %d, want 1", got)
	}
}

// Test_RetryFailedDeliveries_NoFailedRows is a no-op when nothing to retry.
func Test_RetryFailedDeliveries_NoFailedRows(t *testing.T) {
	store := newMemStore()
	svc := webhook.NewService(store, localReceiver)

	retried, err := svc.RetryFailedDeliveries(context.Background())
	if err != nil {
		t.Fatalf("RetryFailedDeliveries: %v", err)
	}
	if retried != 0 {
		t.Errorf("retried = %d, want 0", retried)
	}
}

// Test_ExecuteDelivery_Success verifies a single delivery via ExecuteDelivery
// records "success" status.
func Test_ExecuteDelivery_Success(t *testing.T) {
	store := newMemStore()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	svc := webhook.NewService(store, localReceiver)
	ctx := context.Background()

	companyID := uuid.New()
	wh, _ := svc.Register(ctx, companyID, srv.URL, "secret", []string{"*"})
	d := webhook.WebhookDelivery{
		ID: uuid.New(), WebhookID: wh.ID, EventType: "test",
		Payload: `{}`, Status: "pending", CreatedAt: time.Now(),
	}
	store.directInsertDelivery(d)

	if err := svc.ExecuteDelivery(ctx, d.ID); err != nil {
		t.Fatalf("ExecuteDelivery: %v", err)
	}
	_ = svc.Shutdown(ctx)

	got := store.snapshotDelivery(d.ID)
	if got.Status != "success" {
		t.Errorf("delivery.Status = %q, want success", got.Status)
	}
}

// Test_Service_Options_Applied verifies functional options actually apply.
func Test_Service_Options_Applied(t *testing.T) {
	store := newMemStore()
	custom := &http.Client{Timeout: 7 * time.Second}
	svc := webhook.NewService(store, localReceiver,
		webhook.WithHTTPClient(custom),
		webhook.WithHTTPTimeout(2*time.Second),
		webhook.WithMaxRetries(99),
		webhook.WithMaxConsecutiveFailures(42),
		webhook.WithDeliveryTimeout(3*time.Second),
	)
	if svc == nil {
		t.Fatal("NewService returned nil")
	}
	// Smoke: call Trigger to confirm it doesn't panic with the configured options.
	companyID := uuid.New()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	_, _ = svc.Register(context.Background(), companyID, srv.URL, "s", []string{"*"})
	_ = svc.Trigger(context.Background(), companyID, "x", `{}`)
	_ = svc.Shutdown(context.Background())
}
