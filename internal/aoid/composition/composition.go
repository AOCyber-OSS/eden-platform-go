// Package composition wires the AO ID service together: it builds the
// platform/auth, platform/household and platform/consent services on top
// of a chosen storage backend (in-memory devstore for `aoid` running
// locally, pgstore-backed Postgres for staging / production).
//
// Callers invoke either BuildInMemory or BuildPostgres at boot, and pass
// the resulting *Services to internal/aoid/server.New. Lifetime cleanup
// runs through Services.Close.
package composition

import (
	"context"
	"fmt"
	"io/fs"

	edenplatform "go.aocyber.ai/eden-platform-go"
	"go.aocyber.ai/eden-platform-go/internal/aoid/clients"
	"go.aocyber.ai/eden-platform-go/internal/aoid/config"
	"go.aocyber.ai/eden-platform-go/internal/aoid/federation"
	"go.aocyber.ai/eden-platform-go/platform/audit"
	"go.aocyber.ai/eden-platform-go/platform/auth"
	"go.aocyber.ai/eden-platform-go/platform/consent"
	"go.aocyber.ai/eden-platform-go/platform/devstore"
	"go.aocyber.ai/eden-platform-go/platform/household"
	"go.aocyber.ai/eden-platform-go/platform/pgstore"
)

// Services is the assembled set of platform services aoid exposes.
//
// JWTManager is held alongside Auth because the JWKS endpoint needs
// direct access to the manager's key map; routing JWKS through Auth would
// force a transitive dependency that platform/auth doesn't currently
// expose.
//
// Close is the backend-agnostic teardown hook: pgstore-backed builds
// close the connection pool, in-memory builds are a no-op. Either way it
// is safe to call multiple times — the second call is a no-op.
type Services struct {
	Auth        *auth.Service
	JWTManager  *auth.JWTManager
	Household   *household.Service
	Consent     *consent.Service
	AuditLogger *audit.Logger
	Clients     clients.Registry
	Federation  *federation.Stack
	Close       func() error
}

// BuildInMemory returns a Services backed by devstore (for auth/audit)
// and aoid-local in-memory stores (for household/consent — the platform
// memstore implementations are unexported test types). Suitable for
// local dev, smoke tests, and CI runs that don't require Postgres.
func BuildInMemory(cfg *config.Config) (*Services, error) {
	jm, err := buildJWTManager(cfg)
	if err != nil {
		return nil, fmt.Errorf("composition: jwt manager: %w", err)
	}

	backend := devstore.NewMemoryBackend()
	authStore := backend.AuthStore()
	auditStore := backend.AuditStore()
	auditLogger := audit.NewLogger(auditStore)
	auditLogger.Start()

	hhStore := newInMemoryHouseholdStore()
	consentStore := newInMemoryConsentStore()

	hasher := auth.NewPasswordHasher()
	authSvc := auth.NewService(authStore, jm, hasher)

	hhSvc := household.NewService(hhStore, auditLogger)
	consentSvc := consent.NewService(consentStore, auditLogger)

	clientReg := clients.NewMemoryRegistry()
	if err := seedClientsIfConfigured(clientReg, cfg); err != nil {
		auditLogger.Stop()
		return nil, fmt.Errorf("composition: seed clients: %w", err)
	}

	out := &Services{
		Auth:        authSvc,
		JWTManager:  jm,
		Household:   hhSvc,
		Consent:     consentSvc,
		AuditLogger: auditLogger,
		Clients:     clientReg,
		Close: func() error {
			auditLogger.Stop()
			return nil
		},
	}
	fed, err := BuildFederation(cfg, out)
	if err != nil {
		auditLogger.Stop()
		return nil, fmt.Errorf("composition: federation: %w", err)
	}
	out.Federation = fed
	return out, nil
}

// BuildPostgres builds a Services on top of pgstore. Migrations run
// before the stores are constructed (pgstore.NewBackend handles that
// using the embedded migrations FS).
//
// Note: pgstore migrations live alongside platform migrations in the
// shared migrations/platform tree. AO ID currently has zero schema of
// its own — every table it reads/writes is owned by a platform package.
// When AO ID grows AO-specific schema (objective 30+), introduce a
// migrations/aoid namespace and run them in addition to platform.
func BuildPostgres(ctx context.Context, cfg *config.Config) (*Services, error) {
	jm, err := buildJWTManager(cfg)
	if err != nil {
		return nil, fmt.Errorf("composition: jwt manager: %w", err)
	}

	migrationsFS, err := fs.Sub(edenplatform.MigrationsFS, "migrations/platform")
	if err != nil {
		return nil, fmt.Errorf("composition: migrations fs: %w", err)
	}

	backend, err := pgstore.NewBackend(ctx, cfg.DatabaseURL, migrationsFS)
	if err != nil {
		return nil, fmt.Errorf("composition: pgstore backend: %w", err)
	}

	authStore := backend.AuthStore()
	auditStore := backend.AuditStore()
	auditLogger := audit.NewLogger(auditStore)
	auditLogger.Start()
	hhStore := backend.HouseholdStore()
	consentStore := backend.ConsentStore()

	hasher := auth.NewPasswordHasher()
	authSvc := auth.NewService(authStore, jm, hasher)
	hhSvc := household.NewService(hhStore, auditLogger)
	consentSvc := consent.NewService(consentStore, auditLogger)

	clientReg := clients.NewMemoryRegistry()
	if err := seedClientsIfConfigured(clientReg, cfg); err != nil {
		auditLogger.Stop()
		backend.Close()
		return nil, fmt.Errorf("composition: seed clients: %w", err)
	}

	out := &Services{
		Auth:        authSvc,
		JWTManager:  jm,
		Household:   hhSvc,
		Consent:     consentSvc,
		AuditLogger: auditLogger,
		Clients:     clientReg,
		Close: func() error {
			auditLogger.Stop()
			backend.Close()
			return nil
		},
	}
	fed, err := BuildFederation(cfg, out)
	if err != nil {
		auditLogger.Stop()
		backend.Close()
		return nil, fmt.Errorf("composition: federation: %w", err)
	}
	out.Federation = fed
	return out, nil
}

// seedClientsIfConfigured registers the AODex pilot client into reg
// when both AODexClientSecret and AODexRedirectURIs are populated.
// Logs at info if AODex is registered; logs at warn if config is partial
// (helps catch typos in env vars without taking the service down).
func seedClientsIfConfigured(reg clients.Registry, cfg *config.Config) error {
	if cfg.AODexClientSecret == "" && len(cfg.AODexRedirectURIs) == 0 {
		return nil
	}
	if cfg.AODexClientSecret == "" || len(cfg.AODexRedirectURIs) == 0 {
		return fmt.Errorf("AODex client config partial: secret=%t, redirects=%d", cfg.AODexClientSecret != "", len(cfg.AODexRedirectURIs))
	}
	return clients.SeedAODex(context.Background(), reg, cfg.AODexClientSecret, cfg.AODexRedirectURIs)
}

// buildJWTManager applies aoid configuration to the platform/auth JWT
// manager. Multi-key rotation when JWTKeySeedPaths is set; single-key
// when only JWTKeySeedPath is set; ephemeral (dev) when neither is set.
func buildJWTManager(cfg *config.Config) (*auth.JWTManager, error) {
	jwtCfg := auth.DefaultJWTConfig()
	jwtCfg.Issuer = cfg.Issuer
	jwtCfg.AccessTokenExpiry = cfg.AccessTokenExpiry
	jwtCfg.RefreshTokenExpiry = cfg.RefreshTokenExpiry
	jwtCfg.KeySeedPath = cfg.JWTKeySeedPath
	jwtCfg.KeySeedPaths = cfg.JWTKeySeedPaths
	jwtCfg.ActiveKID = cfg.JWTActiveKID
	jwtCfg.RejectLegacyUntyped = cfg.JWTRejectLegacyUntyped
	return auth.NewJWTManager(jwtCfg)
}
