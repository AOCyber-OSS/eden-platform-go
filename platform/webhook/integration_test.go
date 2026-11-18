package webhook_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.aocyber.ai/eden-platform-go/platform/devstore"
	"go.aocyber.ai/eden-platform-go/platform/rbac"
	"go.aocyber.ai/eden-platform-go/platform/webhook"
)

// TestRBACAuditWebhook_Integration drives the canonical chain end-to-end:
//
//  1. RBAC: an owner has admin-level permission (HasMinimumRole returns true).
//  2. Audit: an "rbac.permission.granted" event is appended.
//  3. Webhook: the service triggers a webhook subscribed to "rbac.*".
//  4. Verification: the captured POST has a valid HMAC signature, matches the
//     payload, and the delivery row is recorded as "success".
//
// All in-memory — no PG dependency.
func TestRBACAuditWebhook_Integration(t *testing.T) {
	ctx := context.Background()

	// --- 1. RBAC ---
	backend := devstore.NewMemoryBackend()
	backend.SeedRBACRole(rbac.Role{ID: rbac.OwnerRoleID, Name: "owner", Level: rbac.RoleLevelOwner, IsSystem: true})
	backend.SeedRBACRole(rbac.Role{ID: rbac.AdminRoleID, Name: "admin", Level: rbac.RoleLevelAdmin, IsSystem: true})
	backend.SeedRBACRole(rbac.Role{ID: rbac.MemberRoleID, Name: "member", Level: rbac.RoleLevelMember, IsSystem: true})
	rbacStore := backend.RBACStore()

	companyID := uuid.New()
	ownerID := uuid.New()
	if err := rbacStore.CreateMembership(ctx, companyID, ownerID, rbac.OwnerRoleID); err != nil {
		t.Fatalf("CreateMembership(owner): %v", err)
	}

	enforcer := rbac.NewEnforcer(rbacStore, nil)
	allowed, err := enforcer.HasMinimumRole(ctx, ownerID, companyID, rbac.RoleLevelAdmin)
	if err != nil {
		t.Fatalf("HasMinimumRole: %v", err)
	}
	if !allowed {
		t.Fatalf("owner should satisfy HasMinimumRole(admin) but got false")
	}

	// --- 2. Audit ---
	auditStore := backend.AuditStore()
	if err := auditStore.CreateAuditLog(
		ctx,
		companyID,
		ownerID,
		"rbac.permission.granted",
		"membership",
		ownerID.String(),
		"127.0.0.1",
		[]byte(`{"role":"owner"}`),
	); err != nil {
		t.Fatalf("CreateAuditLog: %v", err)
	}

	// --- 3. Webhook + httptest receiver ---
	var (
		mu           sync.Mutex
		receivedSig  string
		receivedBody string
		receivedEv   string
		receivedDel  string
		hits         int32
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		mu.Lock()
		defer mu.Unlock()
		b, _ := io.ReadAll(r.Body)
		receivedBody = string(b)
		receivedSig = r.Header.Get("X-Eden-Signature")
		receivedEv = r.Header.Get("X-Eden-Event")
		receivedDel = r.Header.Get("X-Eden-Delivery")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	store := newMemStore()
	svc := webhook.NewService(store, localReceiver)

	wh, err := svc.Register(ctx, companyID, srv.URL, "shared-secret", []string{"rbac.*"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	payload := fmt.Sprintf(`{"company_id":%q,"actor":%q,"action":"rbac.permission.granted"}`, companyID, ownerID)
	if err := svc.Trigger(ctx, companyID, "rbac.permission.granted", payload); err != nil {
		t.Fatalf("Trigger: %v", err)
	}

	// Wait for the in-flight delivery to finish.
	shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := svc.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	// --- 4. Assertions ---
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("HTTP hits = %d, want 1", got)
	}

	mu.Lock()
	gotSig, gotBody, gotEv, gotDel := receivedSig, receivedBody, receivedEv, receivedDel
	mu.Unlock()

	if gotSig == "" {
		t.Fatal("no X-Eden-Signature header received")
	}
	if !webhook.VerifySignature(wh.Secret, gotSig, gotBody) {
		t.Errorf("VerifySignature() = false for received body")
	}
	if gotBody != payload {
		t.Errorf("body mismatch: got %q want %q", gotBody, payload)
	}
	if gotEv != "rbac.permission.granted" {
		t.Errorf("X-Eden-Event = %q, want %q", gotEv, "rbac.permission.granted")
	}
	if gotDel == "" {
		t.Error("X-Eden-Delivery header empty")
	}

	// Find the delivery for this webhook and confirm it's recorded as success.
	var found bool
	store.mu.Lock()
	for _, d := range store.deliveries {
		if d.WebhookID == wh.ID {
			found = true
			if d.Status != "success" {
				t.Errorf("delivery.Status = %q, want success", d.Status)
			}
			if d.StatusCode != http.StatusOK {
				t.Errorf("delivery.StatusCode = %d, want %d", d.StatusCode, http.StatusOK)
			}
		}
	}
	store.mu.Unlock()
	if !found {
		t.Errorf("no delivery row recorded for webhook %s", wh.ID)
	}

	// Sanity: the audit row exists. devstore.AuditStore exposes
	// QueryAuditLogs with company filter, but the proto-typed return is heavy
	// for this test. We only need to know append succeeded above (no error).
	// The returning lookup is exercised by platform/audit's own tests.
}

// TestRBACAuditWebhook_Integration_NonMatchingEvent confirms a webhook subscribed
// to a different prefix is NOT delivered to.
func TestRBACAuditWebhook_Integration_NonMatchingEvent(t *testing.T) {
	ctx := context.Background()

	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	store := newMemStore()
	svc := webhook.NewService(store, localReceiver)
	companyID := uuid.New()
	if _, err := svc.Register(ctx, companyID, srv.URL, "secret", []string{"spend.*"}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if err := svc.Trigger(ctx, companyID, "rbac.permission.granted", `{}`); err != nil {
		t.Fatalf("Trigger: %v", err)
	}
	_ = svc.Shutdown(ctx)

	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Errorf("HTTP hits = %d, want 0 (event prefix should not match)", got)
	}
}
