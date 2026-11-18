// Package config loads aoid runtime configuration from environment
// variables. The convention mirrors platform/config but is scoped to
// aoid-specific knobs so the service can be tuned without dragging in
// every platform setting.
package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the resolved aoid runtime configuration. Fields are populated
// by Load() from AOID_* environment variables; unset variables fall back
// to the documented defaults.
type Config struct {
	// ListenAddr is the bind address for the HTTP server.
	// Env: AOID_LISTEN_ADDR. Default: ":8090".
	ListenAddr string

	// Issuer is the canonical AO ID issuer URL emitted by the discovery
	// document and stamped into JWT iss claims when the issuer activates
	// (objective 30). Env: AOID_ISSUER. Default: "http://localhost:8090".
	Issuer string

	// Environment is the deployment tier: "production", "staging", "dev".
	// Env: AOID_ENV. Default: "dev".
	Environment string

	// LogLevel is the slog level: "debug", "info", "warn", "error".
	// Env: AOID_LOG_LEVEL. Default: "info".
	LogLevel string

	// LogFormat is the slog handler format: "json" or "text".
	// Env: AOID_LOG_FORMAT. Default: "text".
	LogFormat string

	// SentryDSN, when non-empty, ships error-level slog records to Sentry
	// via platform/errortrack. Empty DSN = no-op transport (CI-safe).
	// Env: AOID_SENTRY_DSN. Default: "".
	SentryDSN string

	// Release is the git SHA / build identifier surfaced in errortrack
	// events and the /healthz response. Env: AOID_RELEASE. Default: "dev".
	Release string

	// DatabaseURL is the Postgres DSN used by the pgstore backend.
	// Env: AOID_DATABASE_URL or DATABASE_URL. Default: empty (devstore mode).
	DatabaseURL string

	// JWTKeySeedPath is the single-key fallback path to a 32-byte ML-DSA-65
	// seed file. Used when JWTKeySeedPaths is empty.
	// Env: AOID_JWT_KEY_SEED_PATH. Default: empty (ephemeral key, dev only).
	JWTKeySeedPath string

	// JWTKeySeedPaths enables multi-key rotation. Format is a comma-
	// separated list of `kid=path` pairs:
	//
	//   AOID_JWT_KEY_SEED_PATHS="2026-Q2=/etc/aoid/keys/q2.seed,2026-Q3=/etc/aoid/keys/q3.seed"
	//
	// When non-empty, the kid named by JWTActiveKID signs new tokens; all
	// listed kids are exposed via JWKS for verification.
	JWTKeySeedPaths map[string]string

	// JWTActiveKID is the kid (matching a JWTKeySeedPaths entry) whose key
	// signs newly-issued tokens. Required when JWTKeySeedPaths is set.
	// Env: AOID_JWT_ACTIVE_KID.
	JWTActiveKID string

	// JWTRejectLegacyUntyped closes the issue-#80 migration window now:
	// tokens minted before the token_use claim existed are refused even
	// before auth.DefaultLegacyUntypedCutoff. Env:
	// AOID_JWT_REJECT_LEGACY_UNTYPED ("true"/"1"). Default: false.
	JWTRejectLegacyUntyped bool

	// AccessTokenExpiry is the lifetime of issued access tokens. Used by
	// the issuer (objective 30); included here so config is immutable once
	// the issuer activates. Env: AOID_ACCESS_TOKEN_EXPIRY (Go duration).
	// Default: 15m.
	AccessTokenExpiry time.Duration

	// RefreshTokenExpiry is the lifetime of issued refresh tokens.
	// Env: AOID_REFRESH_TOKEN_EXPIRY (Go duration). Default: 168h (7d).
	RefreshTokenExpiry time.Duration

	// ShutdownTimeout caps the graceful shutdown window between SIGTERM and
	// hard kill. Env: AOID_SHUTDOWN_TIMEOUT (Go duration). Default: 5s.
	ShutdownTimeout time.Duration

	// AODexClientSecret is the shared secret used to authenticate the
	// AODex pilot OIDC client at /oauth2/token. Set via env
	// AOID_AODEX_CLIENT_SECRET. When empty AND Environment != production
	// a deterministic dev secret is used so local boots Just Work; in
	// production an empty secret means AODex is not seeded.
	AODexClientSecret string

	// AODexRedirectURIs is the comma-separated allow-list of redirect
	// URIs accepted at /oauth2/authorize for the AODex client. Set via
	// AOID_AODEX_REDIRECT_URIS. Default in non-prod includes
	// http://localhost:8080/auth/aoid/callback.
	AODexRedirectURIs []string
}

// Load reads AOID_* (and a few common fallbacks) from the environment and
// returns a populated Config with defaults applied. Never returns an error;
// invalid values use their default rather than failing boot, so a typo in
// AOID_LOG_LEVEL doesn't take the service down.
func Load() *Config {
	c := &Config{
		ListenAddr:             envOr("AOID_LISTEN_ADDR", ":8090"),
		Issuer:                 envOr("AOID_ISSUER", "http://localhost:8090"),
		Environment:            envOr("AOID_ENV", "dev"),
		LogLevel:               envOr("AOID_LOG_LEVEL", "info"),
		LogFormat:              envOr("AOID_LOG_FORMAT", "text"),
		SentryDSN:              os.Getenv("AOID_SENTRY_DSN"),
		Release:                envOr("AOID_RELEASE", "dev"),
		DatabaseURL:            firstNonEmpty(os.Getenv("AOID_DATABASE_URL"), os.Getenv("DATABASE_URL")),
		JWTKeySeedPath:         os.Getenv("AOID_JWT_KEY_SEED_PATH"),
		JWTKeySeedPaths:        parseSeedPaths(os.Getenv("AOID_JWT_KEY_SEED_PATHS")),
		JWTActiveKID:           os.Getenv("AOID_JWT_ACTIVE_KID"),
		JWTRejectLegacyUntyped: parseBool(os.Getenv("AOID_JWT_REJECT_LEGACY_UNTYPED")),
		AccessTokenExpiry:      parseDuration(os.Getenv("AOID_ACCESS_TOKEN_EXPIRY"), 15*time.Minute),
		RefreshTokenExpiry:     parseDuration(os.Getenv("AOID_REFRESH_TOKEN_EXPIRY"), 7*24*time.Hour),
		ShutdownTimeout:        parseDuration(os.Getenv("AOID_SHUTDOWN_TIMEOUT"), 5*time.Second),
		AODexClientSecret:      os.Getenv("AOID_AODEX_CLIENT_SECRET"),
		AODexRedirectURIs:      parseCSV(os.Getenv("AOID_AODEX_REDIRECT_URIS")),
	}
	if c.AODexClientSecret == "" && c.Environment != "production" {
		c.AODexClientSecret = "dev-aodex-client-secret-do-not-use-in-prod"
	}
	if len(c.AODexRedirectURIs) == 0 && c.Environment != "production" {
		c.AODexRedirectURIs = []string{
			"http://localhost:8080/auth/aoid/callback",
		}
	}
	return c
}

// parseBool reports whether raw is a true value ("true", "1", ...). Anything
// unparseable is false.
func parseBool(raw string) bool {
	v, err := strconv.ParseBool(strings.TrimSpace(raw))
	return err == nil && v
}

// parseCSV splits a comma-separated string into a trimmed, non-empty
// slice. Returns nil for the empty string.
func parseCSV(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func parseDuration(raw string, def time.Duration) time.Duration {
	if raw == "" {
		return def
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return def
	}
	return d
}

// parseSeedPaths parses "kid1=/path1,kid2=/path2" into a map. Malformed
// entries are dropped silently — a missing seed path will surface as a
// boot error from auth.NewJWTManager, which is the right place to fail.
func parseSeedPaths(raw string) map[string]string {
	if raw == "" {
		return nil
	}
	out := make(map[string]string)
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		eq := strings.IndexByte(pair, '=')
		if eq <= 0 || eq == len(pair)-1 {
			continue
		}
		kid := strings.TrimSpace(pair[:eq])
		path := strings.TrimSpace(pair[eq+1:])
		if kid == "" || path == "" {
			continue
		}
		out[kid] = path
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
