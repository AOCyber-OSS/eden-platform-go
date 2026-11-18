package pgstore_test

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	edenplatform "go.aocyber.ai/eden-platform-go"
	"go.aocyber.ai/eden-platform-go/platform/company"
	"go.aocyber.ai/eden-platform-go/platform/pgstore"
	"go.aocyber.ai/eden-platform-go/platform/rbac"
	"go.aocyber.ai/eden-platform-go/platform/webhook"
)

func setupTestBackend(t *testing.T) *pgstore.Backend {
	t.Helper()
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set, skipping integration tests")
	}
	migrationsFS, err := fs.Sub(edenplatform.MigrationsFS, "migrations/platform")
	if err != nil {
		t.Fatalf("sub migrations fs: %v", err)
	}
	backend, err := pgstore.NewBackend(context.Background(), dbURL, migrationsFS)
	if err != nil {
		t.Fatalf("create backend: %v", err)
	}
	t.Cleanup(func() {
		truncateAll(t, backend)
		backend.Close()
	})
	truncateAll(t, backend)
	return backend
}

func truncateAll(t *testing.T, backend *pgstore.Backend) {
	t.Helper()
	ctx := context.Background()
	// Truncate in reverse dependency order to avoid FK violations.
	// consent_ledger is append-only via row triggers; use TRUNCATE which
	// bypasses BEFORE DELETE row-level triggers.
	if _, err := backend.Pool().Exec(ctx, "TRUNCATE consent_ledger CASCADE"); err != nil {
		t.Fatalf("truncate consent_ledger: %v", err)
	}
	tables := []string{
		"webhook_deliveries", "webhooks",
		"audit_logs",
		"platform_parent_of_record", "platform_household_members", "platform_households",
		"company_memberships", "role_permissions", "permissions",
		"company_hierarchies",
		"refresh_tokens", "sso_configs",
		"encrypted_credentials", "device_tokens",
		// roles has seeded system roles -- don't truncate, just delete non-system
		// companies before roles due to FK
	}
	for _, table := range tables {
		if _, err := backend.Pool().Exec(ctx, "DELETE FROM "+table); err != nil {
			t.Fatalf("truncate %s: %v", table, err)
		}
	}
	// Delete non-system roles first (they FK-reference companies).
	if _, err := backend.Pool().Exec(ctx, "DELETE FROM roles WHERE is_system = false"); err != nil {
		t.Fatalf("truncate non-system roles: %v", err)
	}
	// Delete non-system companies (system roles reference them indirectly)
	if _, err := backend.Pool().Exec(ctx, "DELETE FROM companies"); err != nil {
		t.Fatalf("truncate companies: %v", err)
	}
	// Delete test users
	if _, err := backend.Pool().Exec(ctx, "DELETE FROM users"); err != nil {
		t.Fatalf("truncate users: %v", err)
	}
}

// --- AuthStore Tests ---

func TestAuthStore_UserCRUD(t *testing.T) {
	backend := setupTestBackend(t)
	store := backend.AuthStore()
	ctx := context.Background()

	// Create user
	user, err := store.CreateUser(ctx, "test@example.com", "hash123", "Test User")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if user.Email != "test@example.com" {
		t.Errorf("email = %q, want %q", user.Email, "test@example.com")
	}
	if user.ID == uuid.Nil {
		t.Error("user ID is nil")
	}

	// Get by email
	found, err := store.GetUserByEmail(ctx, "test@example.com")
	if err != nil {
		t.Fatalf("get by email: %v", err)
	}
	if found.ID != user.ID {
		t.Errorf("found.ID = %s, want %s", found.ID, user.ID)
	}

	// Get by ID
	found2, err := store.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("get by id: %v", err)
	}
	if found2.Email != "test@example.com" {
		t.Errorf("found2.Email = %q, want %q", found2.Email, "test@example.com")
	}

	// Duplicate email
	_, err = store.CreateUser(ctx, "test@example.com", "hash456", "Duplicate")
	if err == nil {
		t.Error("expected error for duplicate email, got nil")
	}
}

func TestAuthStore_RefreshTokens(t *testing.T) {
	backend := setupTestBackend(t)
	store := backend.AuthStore()
	ctx := context.Background()

	user, _ := store.CreateUser(ctx, "token@example.com", "hash", "Token User")

	// Create refresh token
	expires := time.Now().Add(24 * time.Hour)
	err := store.CreateRefreshToken(ctx, user.ID, "tokenhash123", expires)
	if err != nil {
		t.Fatalf("create refresh token: %v", err)
	}

	// Get refresh token
	record, err := store.GetRefreshToken(ctx, "tokenhash123")
	if err != nil {
		t.Fatalf("get refresh token: %v", err)
	}
	if record.UserID != user.ID {
		t.Errorf("token user id = %s, want %s", record.UserID, user.ID)
	}

	// Revoke
	err = store.RevokeRefreshToken(ctx, "tokenhash123")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// Should not find revoked token
	_, err = store.GetRefreshToken(ctx, "tokenhash123")
	if err == nil {
		t.Error("expected error for revoked token")
	}
}

func TestAuthStore_Transactions(t *testing.T) {
	backend := setupTestBackend(t)
	store := backend.AuthStore()
	ctx := context.Background()

	// BeginTx + Create + Commit
	txStore, err := store.BeginTx(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	user, err := txStore.CreateUser(ctx, "committed@example.com", "hash", "Committed")
	if err != nil {
		t.Fatalf("create in tx: %v", err)
	}
	if err := txStore.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// Should find committed user
	found, err := store.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("find committed user: %v", err)
	}
	if found.Email != "committed@example.com" {
		t.Errorf("email = %q, want %q", found.Email, "committed@example.com")
	}

	// BeginTx + Create + Rollback
	txStore2, err := store.BeginTx(ctx)
	if err != nil {
		t.Fatalf("begin tx2: %v", err)
	}
	user2, err := txStore2.CreateUser(ctx, "rolledback@example.com", "hash", "Rolled Back")
	if err != nil {
		t.Fatalf("create in tx2: %v", err)
	}
	if err := txStore2.Rollback(ctx); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	// Should NOT find rolled back user
	_, err = store.GetUserByID(ctx, user2.ID)
	if err == nil {
		t.Error("expected error for rolled back user, got nil")
	}
}

// --- CompanyStore Tests ---

func TestCompanyStore_CRUD(t *testing.T) {
	backend := setupTestBackend(t)
	store := backend.CompanyStore()
	ctx := context.Background()

	// Create
	c, err := store.CreateCompany(ctx, company.Company{
		Name:        "Test Corp",
		Slug:        "test-corp",
		CompanyType: company.CompanyTypeStandalone,
		Settings:    json.RawMessage(`{"enabled_features":["home"]}`),
	})
	if err != nil {
		t.Fatalf("create company: %v", err)
	}
	if c.Name != "Test Corp" {
		t.Errorf("name = %q, want %q", c.Name, "Test Corp")
	}

	// Get
	found, err := store.GetCompany(ctx, c.ID)
	if err != nil {
		t.Fatalf("get company: %v", err)
	}
	if found.Slug != "test-corp" {
		t.Errorf("slug = %q, want %q", found.Slug, "test-corp")
	}

	// Update
	c.Name = "Updated Corp"
	c.CompanyType = company.CompanyTypeHolding
	updated, err := store.UpdateCompany(ctx, c)
	if err != nil {
		t.Fatalf("update company: %v", err)
	}
	if updated.Name != "Updated Corp" {
		t.Errorf("updated name = %q, want %q", updated.Name, "Updated Corp")
	}

	// List
	companies, err := store.ListCompanies(ctx)
	if err != nil {
		t.Fatalf("list companies: %v", err)
	}
	if len(companies) != 1 {
		t.Errorf("company count = %d, want 1", len(companies))
	}
}

func TestCompanyStore_Hierarchy(t *testing.T) {
	backend := setupTestBackend(t)
	store := backend.CompanyStore()
	ctx := context.Background()

	parent, _ := store.CreateCompany(ctx, company.Company{Name: "Parent", Slug: "parent", CompanyType: company.CompanyTypeHolding})
	child, _ := store.CreateCompany(ctx, company.Company{Name: "Child", Slug: "child", CompanyType: company.CompanyTypeSubsidiary, ParentCompanyID: &parent.ID})

	// Insert hierarchy entries
	err := store.InsertHierarchyEntries(ctx, []company.CompanyHierarchy{
		{AncestorID: parent.ID, DescendantID: parent.ID, Generations: 0},
		{AncestorID: child.ID, DescendantID: child.ID, Generations: 0},
		{AncestorID: parent.ID, DescendantID: child.ID, Generations: 1},
	})
	if err != nil {
		t.Fatalf("insert hierarchy: %v", err)
	}

	// GetAncestors
	ancestors, err := store.GetAncestors(ctx, child.ID)
	if err != nil {
		t.Fatalf("get ancestors: %v", err)
	}
	if len(ancestors) < 1 {
		t.Errorf("ancestor count = %d, want >= 1", len(ancestors))
	}

	// GetDescendants
	descendants, err := store.GetDescendants(ctx, parent.ID)
	if err != nil {
		t.Fatalf("get descendants: %v", err)
	}
	if len(descendants) < 1 {
		t.Errorf("descendant count = %d, want >= 1", len(descendants))
	}

	// GetSelfAndDescendantIDs
	ids, err := store.GetSelfAndDescendantIDs(ctx, parent.ID)
	if err != nil {
		t.Fatalf("get descendant ids: %v", err)
	}
	if len(ids) < 2 {
		t.Errorf("descendant id count = %d, want >= 2", len(ids))
	}
}

func TestCompanyStore_ListCompaniesForUser(t *testing.T) {
	backend := setupTestBackend(t)
	authStore := backend.AuthStore()
	companyStore := backend.CompanyStore()
	ctx := context.Background()

	user, _ := authStore.CreateUser(ctx, "member@example.com", "hash", "Member")
	c, _ := companyStore.CreateCompany(ctx, company.Company{Name: "Member Co", Slug: "member-co"})

	// Create membership via auth store
	// Need a role ID -- use system owner role
	ownerRoleID := uuid.MustParse("10000000-0000-0000-0000-000000000001")
	_ = authStore.CreateCompanyMembership(ctx, c.ID, user.ID, ownerRoleID)

	// List companies for user
	companies, err := companyStore.ListCompaniesForUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("list for user: %v", err)
	}
	if len(companies) != 1 {
		t.Errorf("company count = %d, want 1", len(companies))
	}
	if len(companies) > 0 && companies[0].Name != "Member Co" {
		t.Errorf("company name = %q, want %q", companies[0].Name, "Member Co")
	}
}

// --- RBACStore Tests ---

func TestRBACStore_RolesAndPermissions(t *testing.T) {
	backend := setupTestBackend(t)
	store := backend.RBACStore()
	ctx := context.Background()

	// Get system role
	ownerRoleID := uuid.MustParse("10000000-0000-0000-0000-000000000001")
	role, err := store.GetRoleByID(ctx, ownerRoleID)
	if err != nil {
		t.Fatalf("get system role: %v", err)
	}
	if role.Name != "owner" {
		t.Errorf("role name = %q, want %q", role.Name, "owner")
	}

	// Create custom role
	companyStore := backend.CompanyStore()
	c, _ := companyStore.CreateCompany(ctx, company.Company{Name: "RBAC Co", Slug: "rbac-co"})

	customRole, err := store.CreateRole(ctx, c.ID, "custom", "Custom role", rbac.RoleLevelManager)
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	if customRole.Level != rbac.RoleLevelManager {
		t.Errorf("level = %d, want %d", customRole.Level, rbac.RoleLevelManager)
	}

	// List roles by company (should include system + custom)
	roles, err := store.ListRolesByCompany(ctx, c.ID)
	if err != nil {
		t.Fatalf("list roles: %v", err)
	}
	if len(roles) < 2 {
		t.Errorf("role count = %d, want >= 2", len(roles))
	}
}

func TestRBACStore_Membership(t *testing.T) {
	backend := setupTestBackend(t)
	rbacStore := backend.RBACStore()
	authStore := backend.AuthStore()
	companyStore := backend.CompanyStore()
	ctx := context.Background()

	user, _ := authStore.CreateUser(ctx, "rbac-user@example.com", "hash", "RBAC User")
	c, _ := companyStore.CreateCompany(ctx, company.Company{Name: "Membership Co", Slug: "membership-co"})
	ownerRoleID := uuid.MustParse("10000000-0000-0000-0000-000000000001")

	// Create membership
	err := rbacStore.CreateMembership(ctx, c.ID, user.ID, ownerRoleID)
	if err != nil {
		t.Fatalf("create membership: %v", err)
	}

	// Get membership
	membership, err := rbacStore.GetMembership(ctx, c.ID, user.ID)
	if err != nil {
		t.Fatalf("get membership: %v", err)
	}
	if membership.RoleName != "owner" {
		t.Errorf("role name = %q, want %q", membership.RoleName, "owner")
	}

	// Get membership in company (pointer return)
	membershipPtr, err := rbacStore.GetMembershipInCompany(ctx, c.ID, user.ID)
	if err != nil {
		t.Fatalf("get membership in company: %v", err)
	}
	if membershipPtr == nil {
		t.Error("expected non-nil membership")
	}

	// Nonexistent membership returns nil, nil
	nonexistentPtr, err := rbacStore.GetMembershipInCompany(ctx, uuid.New(), uuid.New())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if nonexistentPtr != nil {
		t.Error("expected nil for nonexistent membership")
	}

	// Get user role
	userRole, err := rbacStore.GetUserRole(ctx, c.ID, user.ID)
	if err != nil {
		t.Fatalf("get user role: %v", err)
	}
	if userRole.Name != "owner" {
		t.Errorf("user role = %q, want %q", userRole.Name, "owner")
	}
}

// --- AuditStore Tests ---

func TestAuditStore_CreateAndQuery(t *testing.T) {
	backend := setupTestBackend(t)
	auditStore := backend.AuditStore()
	authStore := backend.AuthStore()
	companyStore := backend.CompanyStore()
	ctx := context.Background()

	user, _ := authStore.CreateUser(ctx, "auditor@example.com", "hash", "Auditor")
	c, _ := companyStore.CreateCompany(ctx, company.Company{Name: "Audit Co", Slug: "audit-co"})

	// Create audit logs
	for _, action := range []string{"user.login", "user.login", "settings.updated"} {
		err := auditStore.CreateAuditLog(ctx, c.ID, user.ID, action, "user", user.ID.String(), "127.0.0.1", []byte(`{}`))
		if err != nil {
			t.Fatalf("create audit log: %v", err)
		}
	}

	// Query all
	entries, total, err := auditStore.QueryAuditLogs(ctx, c.ID, 10, 0, nil, nil, nil)
	if err != nil {
		t.Fatalf("query all: %v", err)
	}
	if total != 3 {
		t.Errorf("total = %d, want 3", total)
	}
	if len(entries) != 3 {
		t.Errorf("entries = %d, want 3", len(entries))
	}

	// Query with action filter
	action := "user.login"
	filtered, filteredTotal, err := auditStore.QueryAuditLogs(ctx, c.ID, 10, 0, nil, &action, nil)
	if err != nil {
		t.Fatalf("query filtered: %v", err)
	}
	if filteredTotal != 2 {
		t.Errorf("filtered total = %d, want 2", filteredTotal)
	}
	if len(filtered) != 2 {
		t.Errorf("filtered entries = %d, want 2", len(filtered))
	}

	// Query with pagination
	paginated, _, err := auditStore.QueryAuditLogs(ctx, c.ID, 1, 1, nil, nil, nil)
	if err != nil {
		t.Fatalf("query paginated: %v", err)
	}
	if len(paginated) != 1 {
		t.Errorf("paginated = %d, want 1", len(paginated))
	}
}

// --- WebhookStore Tests ---

func TestWebhookStore_CRUD(t *testing.T) {
	backend := setupTestBackend(t)
	store := backend.WebhookStore()
	companyStore := backend.CompanyStore()
	ctx := context.Background()

	c, _ := companyStore.CreateCompany(ctx, company.Company{Name: "Webhook Co", Slug: "webhook-co"})

	// Create
	wh, err := store.CreateWebhook(ctx, c.ID, "https://example.com/hook", "secret", []string{"user.created"})
	if err != nil {
		t.Fatalf("create webhook: %v", err)
	}
	if wh.URL != "https://example.com/hook" {
		t.Errorf("url = %q, want %q", wh.URL, "https://example.com/hook")
	}

	// Get
	found, err := store.GetWebhook(ctx, wh.ID)
	if err != nil {
		t.Fatalf("get webhook: %v", err)
	}
	if found.Secret != "secret" {
		t.Errorf("secret = %q, want %q", found.Secret, "secret")
	}

	// List
	webhooks, err := store.ListWebhooksByCompany(ctx, c.ID)
	if err != nil {
		t.Fatalf("list webhooks: %v", err)
	}
	if len(webhooks) != 1 {
		t.Errorf("webhook count = %d, want 1", len(webhooks))
	}

	// Increment failure
	count, err := store.IncrementFailureCount(ctx, wh.ID)
	if err != nil {
		t.Fatalf("increment failure: %v", err)
	}
	if count != 1 {
		t.Errorf("failure count = %d, want 1", count)
	}

	// Reset failure
	err = store.ResetFailureCount(ctx, wh.ID)
	if err != nil {
		t.Fatalf("reset failure: %v", err)
	}

	// Delete
	err = store.DeleteWebhook(ctx, c.ID, wh.ID)
	if err != nil {
		t.Fatalf("delete webhook: %v", err)
	}
	_, err = store.GetWebhook(ctx, wh.ID)
	if err == nil {
		t.Error("expected error for deleted webhook")
	}
}

func TestWebhookStore_Deliveries(t *testing.T) {
	backend := setupTestBackend(t)
	store := backend.WebhookStore()
	companyStore := backend.CompanyStore()
	ctx := context.Background()

	c, _ := companyStore.CreateCompany(ctx, company.Company{Name: "Delivery Co", Slug: "delivery-co"})
	wh, _ := store.CreateWebhook(ctx, c.ID, "https://example.com/hook", "secret", []string{"*"})

	// Create delivery
	delivery, err := store.CreateDelivery(ctx, wh.ID, "user.created", `{"user":"test"}`)
	if err != nil {
		t.Fatalf("create delivery: %v", err)
	}
	if delivery.Status != "pending" {
		t.Errorf("status = %q, want %q", delivery.Status, "pending")
	}

	// Update delivery
	nextRetry := time.Now().Add(time.Hour)
	err = store.UpdateDelivery(ctx, delivery.ID, "failed", 500, "server error", &nextRetry)
	if err != nil {
		t.Fatalf("update delivery: %v", err)
	}

	// Get pending deliveries (should include failed with future retry)
	// Note: the delivery was set to "failed" with next_retry_at in the future,
	// so it won't appear in GetPendingDeliveries (which checks next_retry_at <= now())

	// List deliveries by webhook
	deliveries, err := store.ListDeliveriesByWebhook(ctx, c.ID, wh.ID, 10, 0)
	if err != nil {
		t.Fatalf("list deliveries: %v", err)
	}
	if len(deliveries) != 1 {
		t.Errorf("delivery count = %d, want 1", len(deliveries))
	}
}

// TestWebhookStore_TenantScoped pins #77 at the SQL layer: another
// company's id deletes nothing (ErrWebhookNotFound) and lists nothing.
func TestWebhookStore_TenantScoped(t *testing.T) {
	backend := setupTestBackend(t)
	store := backend.WebhookStore()
	companyStore := backend.CompanyStore()
	ctx := context.Background()

	a, err := companyStore.CreateCompany(ctx, company.Company{Name: "Tenant A", Slug: "tenant-a"})
	if err != nil {
		t.Fatalf("create company a: %v", err)
	}
	b, err := companyStore.CreateCompany(ctx, company.Company{Name: "Tenant B", Slug: "tenant-b"})
	if err != nil {
		t.Fatalf("create company b: %v", err)
	}
	wh, err := store.CreateWebhook(ctx, a.ID, "https://a.example.com/hook", "secret-a", []string{"*"})
	if err != nil {
		t.Fatalf("create webhook: %v", err)
	}
	if _, err := store.CreateDelivery(ctx, wh.ID, "user.created", `{"pii":"a"}`); err != nil {
		t.Fatalf("create delivery: %v", err)
	}

	// Wrong tenant: list returns nothing, delete is a no-op + not found.
	got, err := store.ListDeliveriesByWebhook(ctx, b.ID, wh.ID, 10, 0)
	if err != nil {
		t.Fatalf("wrong-tenant list: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("wrong-tenant list returned %d deliveries, want 0", len(got))
	}
	if err := store.DeleteWebhook(ctx, b.ID, wh.ID); !errors.Is(err, webhook.ErrWebhookNotFound) {
		t.Fatalf("wrong-tenant delete = %v, want ErrWebhookNotFound", err)
	}
	if _, err := store.GetWebhook(ctx, wh.ID); err != nil {
		t.Fatalf("wrong-tenant delete removed the webhook: %v", err)
	}

	// Right tenant: list sees the delivery, delete removes it once.
	got, err = store.ListDeliveriesByWebhook(ctx, a.ID, wh.ID, 10, 0)
	if err != nil || len(got) != 1 {
		t.Fatalf("same-tenant list = %d rows, %v; want 1", len(got), err)
	}
	if err := store.DeleteWebhook(ctx, a.ID, wh.ID); err != nil {
		t.Fatalf("same-tenant delete: %v", err)
	}
	if err := store.DeleteWebhook(ctx, a.ID, wh.ID); !errors.Is(err, webhook.ErrWebhookNotFound) {
		t.Fatalf("second delete = %v, want ErrWebhookNotFound", err)
	}
}

// TestAuthStore_GetCompanyMembershipByUser_OldestFirst pins the fix in #38:
// a multi-company user must resolve to the OLDEST membership (the "home"
// company), stable across calls. The fixture is arranged so that EVERY other
// plausible order gives the wrong answer: the home membership is inserted
// SECOND (so physical/no-ORDER-BY order returns the other one) and home is the
// company with the LARGER id (so a company_id tiebreak alone returns the other
// one). Only created_at ASC picks home — which is the fix.
func TestAuthStore_GetCompanyMembershipByUser_OldestFirst(t *testing.T) {
	backend := setupTestBackend(t)
	authStore := backend.AuthStore()
	companyStore := backend.CompanyStore()
	ctx := context.Background()

	user, err := authStore.CreateUser(ctx, "multi@example.com", "hash", "Multi")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	c1, _ := companyStore.CreateCompany(ctx, company.Company{Name: "Co 1", Slug: "co-1"})
	c2, _ := companyStore.CreateCompany(ctx, company.Company{Name: "Co 2", Slug: "co-2"})
	home, later := c1, c2
	if c2.ID.String() > c1.ID.String() {
		home, later = c2, c1 // home = larger id, so company_id ASC would NOT pick it
	}
	ownerRoleID := uuid.MustParse("10000000-0000-0000-0000-000000000001")

	// Physically insert the NON-home membership first.
	if err := authStore.CreateCompanyMembership(ctx, later.ID, user.ID, ownerRoleID); err != nil {
		t.Fatalf("later membership: %v", err)
	}
	if err := authStore.CreateCompanyMembership(ctx, home.ID, user.ID, ownerRoleID); err != nil {
		t.Fatalf("home membership: %v", err)
	}
	// ...but make home the OLDER membership.
	if _, err := backend.Pool().Exec(ctx,
		`UPDATE company_memberships SET created_at = created_at - interval '1 day' WHERE user_id = $1 AND company_id = $2`,
		user.ID, home.ID); err != nil {
		t.Fatalf("backdate home membership: %v", err)
	}

	for i := 0; i < 5; i++ {
		m, err := authStore.GetCompanyMembershipByUser(ctx, user.ID)
		if err != nil {
			t.Fatalf("get membership: %v", err)
		}
		if m.CompanyID != home.ID {
			t.Fatalf("call %d: resolved company = %s, want oldest/home %s (other = %s)", i, m.CompanyID, home.ID, later.ID)
		}
	}
}
