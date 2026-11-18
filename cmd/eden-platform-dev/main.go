package main

import (
	"context"
	"flag"
	"io/fs"
	"log"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"

	connect "connectrpc.com/connect"
	edenplatform "go.aocyber.ai/eden-platform-go"
	"go.aocyber.ai/eden-platform-go/platform/auth"
	"go.aocyber.ai/eden-platform-go/platform/bridge"
	"go.aocyber.ai/eden-platform-go/platform/company"
	"go.aocyber.ai/eden-platform-go/platform/config"
	"go.aocyber.ai/eden-platform-go/platform/connectapi"
	"go.aocyber.ai/eden-platform-go/platform/devstore"
	"go.aocyber.ai/eden-platform-go/platform/observability"
	"go.aocyber.ai/eden-platform-go/platform/pgstore"
	"go.aocyber.ai/eden-platform-go/platform/rbac"
	platformregistry "go.aocyber.ai/eden-platform-go/platform/registry"
	"go.aocyber.ai/eden-platform-go/platform/server"
	"go.aocyber.ai/eden-platform-go/platform/webhook"
	platformv1connect "go.aocyber.ai/eden-platform-go/gen/go/platform/v1/platformv1connect"
	"github.com/google/uuid"
)

func main() {
	observability.InitLogging("", "")

	useDB := flag.Bool("db", false, "Use PostgreSQL instead of in-memory devstore")
	flag.Parse()

	cfg := config.Load()

	if cfg.JWTKeySeedPath == "" {
		cfg.JWTKeySeedPath = filepath.Join("dev", "jwt", "jwt_mldsa65.seed")
	}

	if *useDB {
		slog.Info("using PostgreSQL backend", "database_url", maskDatabaseURL(cfg.DatabaseURL))
		migrationsFS, err := fs.Sub(edenplatform.MigrationsFS, "migrations/platform")
		if err != nil {
			log.Fatalf("sub migrations fs: %v", err)
		}
		pgBackend, err := pgstore.NewBackend(context.Background(), cfg.DatabaseURL, migrationsFS)
		if err != nil {
			log.Fatalf("pgstore backend: %v", err)
		}
		defer pgBackend.Close()

		as := pgBackend.AuthStore()
		cs := pgBackend.CompanyStore()
		rs := pgBackend.RBACStore()
		aus := pgBackend.AuditStore()
		ws := pgBackend.WebhookStore()

		runServer(cfg, as, cs, rs, ws, cs, aus, ws)
	} else {
		slog.Info("using in-memory devstore backend")
		backend := devstore.NewMemoryBackend()
		seedSSOForDev(backend)
		seedRBACData(backend)
		seedWebhookData(backend)
		seedAuditData(backend)

		as := backend.AuthStore()
		cs := backend.CompanyStore()
		rs := backend.RBACStore()
		aus := backend.AuditStore()
		ws := backend.WebhookStore()

		runServer(cfg, as, cs, rs, ws, cs, aus, ws)
	}
}

// runServer starts the HTTP server with the given store implementations.
// The companyLister, auditQuerier, and deliveryQ parameters accept the
// concrete store types that satisfy the connectapi-specific interfaces
// (userCompanyLister, AuditLogQuerier, deliveryQuerier) beyond the base
// store interfaces.
func runServer(
	cfg *config.PlatformConfig,
	authStore auth.TxAuthStore,
	companyStore company.CompanyStore,
	rbacStore rbac.RBACStore,
	webhookStore webhook.WebhookStore,
	companyLister interface {
		ListCompaniesForUser(context.Context, uuid.UUID) ([]company.Company, error)
	},
	auditQuerier connectapi.AuditLogQuerier,
	deliveryQ interface {
		ListDeliveriesByWebhook(ctx context.Context, companyID, webhookID uuid.UUID, limit, offset int) ([]webhook.WebhookDelivery, error)
	},
) {
	jwtManager, err := auth.NewJWTManager(auth.JWTConfig{
		KeySeedPath:        cfg.JWTKeySeedPath,
		Issuer:             "eden-platform-dev",
		AccessTokenExpiry:  auth.DefaultJWTConfig().AccessTokenExpiry,
		RefreshTokenExpiry: auth.DefaultJWTConfig().RefreshTokenExpiry,
	})
	if err != nil {
		log.Fatalf("create jwt manager: %v", err)
	}

	authService := auth.NewService(authStore, jwtManager, auth.NewPasswordHasher())
	companyService := company.NewService(companyStore)
	ssoService := auth.NewSSOService(authStore, jwtManager, "http://localhost"+cfg.ServerAddr)

	enforcer := rbac.NewEnforcer(rbacStore, nil)
	rbacResolver := rbac.NewHierarchyResolver(rbacStore)
	rbacService := rbac.NewService(rbacStore, enforcer, rbacResolver)
	webhookService := webhook.NewService(webhookStore)

	adapterRegistry := bridge.NewAdapterRegistry()
	seedBridgeAdapters(adapterRegistry)

	reg := seedRegistry()

	metrics := observability.NewMetrics()
	obsInterceptor := observability.NewObservabilityInterceptor(metrics)

	mux := http.NewServeMux()
	ssoService.RegisterHTTPHandlers(mux)

	authInterceptor := server.NewAuthInterceptor(jwtManager, server.DefaultPublicProcedures())
	rbacConfig := server.InterceptorConfig{
		PublicProcedures:     server.DefaultPublicProcedures(),
		ProcedurePermissions: defaultProcedurePermissions(),
	}
	rbacInterceptor := server.NewRBACInterceptor(enforcer, rbacConfig)
	slog.Info("RBAC interceptor enabled", "mapped_procedures", len(defaultProcedurePermissions()))

	server.RegisterPlatformHandlers(
		mux,
		server.PlatformHandlers{
			Auth:     connectapi.NewAuthHandler(authService, ssoService),
			Company:  connectapi.NewCompanyHandler(companyService, companyLister),
			Registry: connectapi.NewRegistryHandler(reg, companyStore),
			RBAC:     connectapi.NewRBACHandler(rbacService, enforcer, rbacResolver),
			Audit:    connectapi.NewAuditHandler(auditQuerier),
			Webhook:  connectapi.NewWebhookHandler(webhookService, webhookStore, deliveryQ),
			Bridge:   connectapi.NewBridgeHandler(adapterRegistry),
		},
		connect.WithInterceptors(obsInterceptor, authInterceptor, rbacInterceptor),
	)
	mux.Handle("/up", (&server.HealthChecker{}).Handler())
	mux.Handle("/metrics", metrics.MetricsHandler())

	handler := server.CORSMiddleware(server.LoggingMiddleware(mux))
	log.Printf("eden platform dev server listening on %s", cfg.ServerAddr)
	if err := http.ListenAndServe(cfg.ServerAddr, handler); err != nil {
		log.Fatal(err)
	}
}

func maskDatabaseURL(url string) string {
	if idx := strings.Index(url, "@"); idx > 0 {
		prefix := url[:strings.Index(url, "://")+3]
		return prefix + "***@" + url[idx+1:]
	}
	return url
}

func defaultProcedurePermissions() map[string]server.Permission {
	return map[string]server.Permission{
		platformv1connect.CompanyServiceCreateCompanyProcedure:         {Feature: "settings", Action: "admin"},
		platformv1connect.CompanyServiceUpdateCompanyProcedure:         {Feature: "settings", Action: "edit"},
		platformv1connect.RBACServiceCreateRoleProcedure:               {Feature: "settings", Action: "admin"},
		platformv1connect.RBACServiceAssignRoleProcedure:               {Feature: "settings", Action: "admin"},
		platformv1connect.RBACServiceRemoveRoleProcedure:               {Feature: "settings", Action: "admin"},
		platformv1connect.WebhookServiceRegisterWebhookProcedure:       {Feature: "settings", Action: "admin"},
		platformv1connect.WebhookServiceDeleteWebhookProcedure:         {Feature: "settings", Action: "admin"},
	}
}

func seedRBACData(backend *devstore.Backend) {
	rbacStore := backend.RBACStore()
	ctx := context.Background()

	systemRoles := []rbac.Role{
		{ID: rbac.OwnerRoleID, Name: "owner", Level: rbac.RoleLevelOwner, IsSystem: true},
		{ID: rbac.AdminRoleID, Name: "admin", Level: rbac.RoleLevelAdmin, IsSystem: true},
		{ID: rbac.MemberRoleID, Name: "member", Level: rbac.RoleLevelMember, IsSystem: true},
		{ID: rbac.ViewerRoleID, Name: "viewer", Level: rbac.RoleLevelViewer, IsSystem: true},
	}
	for _, role := range systemRoles {
		backend.SeedRBACRole(role)
	}

	type permDef struct {
		feature string
		action  string
	}
	basePerms := []permDef{
		{"settings", "view"}, {"settings", "edit"}, {"settings", "admin"},
		{"projects", "view"}, {"projects", "create"}, {"projects", "edit"}, {"projects", "delete"},
	}

	permIDs := make(map[string]uuid.UUID)
	for _, p := range basePerms {
		id := uuid.New()
		permIDs[p.feature+":"+p.action] = id
		backend.SeedRBACPermission(rbac.Permission{ID: id, Feature: p.feature, Action: p.action})
	}

	for _, pid := range permIDs {
		_ = rbacStore.AddRolePermission(ctx, rbac.OwnerRoleID, pid)
	}
	for key, pid := range permIDs {
		if key != "settings:admin" {
			_ = rbacStore.AddRolePermission(ctx, rbac.AdminRoleID, pid)
		}
	}
	for key, pid := range permIDs {
		if key == "settings:admin" || key == "projects:delete" {
			continue
		}
		_ = rbacStore.AddRolePermission(ctx, rbac.MemberRoleID, pid)
	}
	for key, pid := range permIDs {
		if strings.HasSuffix(key, ":view") {
			_ = rbacStore.AddRolePermission(ctx, rbac.ViewerRoleID, pid)
		}
	}

	slog.Info("seeded RBAC data", "roles", len(systemRoles), "permissions", len(basePerms))
}

func seedSSOForDev(backend *devstore.Backend) {
	testCompanyID := uuid.MustParse("20000000-0000-0000-0000-000000000001")
	backend.SetSSOConfig(testCompanyID, "oidc", auth.SSOConfig{
		CompanyID: testCompanyID, Provider: "oidc",
		IssuerURL: "https://accounts.google.com", ClientID: "dev-oidc-client-id", ClientSecret: "dev-oidc-client-secret",
	})
	backend.SetSSOConfig(testCompanyID, "saml", auth.SSOConfig{
		CompanyID: testCompanyID, Provider: "saml",
		MetadataURL: "https://login.microsoftonline.com/dev-tenant/federationmetadata/2007-06/federationmetadata.xml",
	})
	slog.Info("seeded SSO config for dev", "company_id", testCompanyID)
}

func seedBridgeAdapters(registry *bridge.AdapterRegistry) {
	registry.Register("eden.platform.", &devAdapter{})
	slog.Info("seeded bridge adapters", "count", 1)
}

type devAdapter struct{}

func (a *devAdapter) EventTypes() []string {
	return []string{"eden.platform.user.created", "eden.platform.company.created", "eden.platform.role.assigned"}
}
func (a *devAdapter) Transform(subject string, envelope bridge.EventEnvelope) (*bridge.TransformedEvent, error) {
	return &bridge.TransformedEvent{EventType: envelope.EventType, SourceID: envelope.EventID, CompanyID: envelope.CompanyID, Data: envelope.Data}, nil
}
func (a *devAdapter) ActionTypes() []bridge.ActionSchema {
	return []bridge.ActionSchema{
		{Type: "eden.notify", Label: "Send Notification", RequiresInput: true, InputHint: "Notification message", Destructive: false},
		{Type: "eden.export", Label: "Export Data", RequiresInput: false, Destructive: false},
	}
}
func (a *devAdapter) SupportsAction(actionType string) bool {
	return actionType == "eden.notify" || actionType == "eden.export"
}

func seedWebhookData(backend *devstore.Backend) {
	ctx := context.Background()
	testCompanyID := uuid.MustParse("20000000-0000-0000-0000-000000000001")
	_, _ = backend.WebhookStore().CreateWebhook(ctx, testCompanyID, "https://example.com/webhook", "test-secret-key", []string{"eden.platform.*"})
	slog.Info("seeded webhook data", "company_id", testCompanyID)
}

func seedAuditData(backend *devstore.Backend) {
	auditStore := backend.AuditStore()
	ctx := context.Background()
	testCompanyID := uuid.MustParse("20000000-0000-0000-0000-000000000001")
	testUserID := uuid.MustParse("30000000-0000-0000-0000-000000000001")
	for _, a := range []struct{ action, resource, resourceID string }{
		{"user.login", "user", testUserID.String()},
		{"company.settings.updated", "company", testCompanyID.String()},
		{"role.assigned", "membership", uuid.New().String()},
	} {
		_ = auditStore.CreateAuditLog(ctx, testCompanyID, testUserID, a.action, a.resource, a.resourceID, "127.0.0.1", []byte(`{}`))
	}
	slog.Info("seeded audit data", "entries", 3)
}

func seedRegistry() *platformregistry.Registry {
	reg := platformregistry.New()
	reg.Register(&platformregistry.ModuleRegistration{
		Name:          "home",
		NavItems:      []platformregistry.NavItem{{ID: "home", Label: "Home", Icon: "home", Path: "/home", Feature: "home", Priority: 0}},
		Widgets:       []platformregistry.Widget{{ID: "welcome", Label: "Welcome", Type: "summary", Feature: "home", Priority: 0}},
		BadgeProvider: func(companyID, userID string) int { return 1 },
	})
	reg.Register(&platformregistry.ModuleRegistration{
		Name:          "projects",
		NavItems:      []platformregistry.NavItem{{ID: "projects", Label: "Projects", Icon: "folder", Path: "/projects", Feature: "projects", Priority: 10}},
		SearchScopes:  []platformregistry.SearchScope{{ID: "projects", Label: "Projects", Feature: "projects"}},
		BadgeProvider: func(companyID, userID string) int { return 4 },
	})
	reg.Register(&platformregistry.ModuleRegistration{
		Name:          "activity",
		NavItems:      []platformregistry.NavItem{{ID: "activity", Label: "Activity", Icon: "analytics", Path: "/activity", Feature: "activity", Priority: 20}},
		BadgeProvider: func(companyID, userID string) int { return 2 },
	})
	reg.Register(&platformregistry.ModuleRegistration{
		Name:     "settings",
		NavItems: []platformregistry.NavItem{{ID: "settings", Label: "Settings", Icon: "settings", Path: "/settings", Feature: "settings", Priority: 30}},
	})
	return reg
}
