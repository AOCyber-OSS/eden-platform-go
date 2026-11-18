package config

import (
	"testing"
	"time"
)

func TestLoad_Defaults(t *testing.T) {
	t.Setenv("AOID_LISTEN_ADDR", "")
	t.Setenv("AOID_ISSUER", "")
	t.Setenv("AOID_ENV", "")
	t.Setenv("AOID_LOG_LEVEL", "")
	t.Setenv("AOID_LOG_FORMAT", "")
	t.Setenv("AOID_RELEASE", "")
	t.Setenv("AOID_ACCESS_TOKEN_EXPIRY", "")
	t.Setenv("AOID_REFRESH_TOKEN_EXPIRY", "")
	t.Setenv("AOID_SHUTDOWN_TIMEOUT", "")
	t.Setenv("AOID_JWT_KEY_SEED_PATHS", "")

	c := Load()
	if c.ListenAddr != ":8090" {
		t.Errorf("ListenAddr = %q want :8090", c.ListenAddr)
	}
	if c.Issuer != "http://localhost:8090" {
		t.Errorf("Issuer = %q want default localhost", c.Issuer)
	}
	if c.Environment != "dev" {
		t.Errorf("Environment = %q want dev", c.Environment)
	}
	if c.LogLevel != "info" {
		t.Errorf("LogLevel = %q want info", c.LogLevel)
	}
	if c.AccessTokenExpiry != 15*time.Minute {
		t.Errorf("AccessTokenExpiry = %v want 15m", c.AccessTokenExpiry)
	}
	if c.RefreshTokenExpiry != 7*24*time.Hour {
		t.Errorf("RefreshTokenExpiry = %v want 168h", c.RefreshTokenExpiry)
	}
	if c.ShutdownTimeout != 5*time.Second {
		t.Errorf("ShutdownTimeout = %v want 5s", c.ShutdownTimeout)
	}
	if c.JWTKeySeedPaths != nil {
		t.Errorf("JWTKeySeedPaths = %v want nil", c.JWTKeySeedPaths)
	}
}

func TestLoad_Overrides(t *testing.T) {
	t.Setenv("AOID_LISTEN_ADDR", "127.0.0.1:9000")
	t.Setenv("AOID_ISSUER", "https://id.example.com")
	t.Setenv("AOID_ENV", "production")
	t.Setenv("AOID_LOG_LEVEL", "debug")
	t.Setenv("AOID_LOG_FORMAT", "json")
	t.Setenv("AOID_RELEASE", "abc123")
	t.Setenv("AOID_DATABASE_URL", "postgres://x@y/z")
	t.Setenv("AOID_ACCESS_TOKEN_EXPIRY", "30m")
	t.Setenv("AOID_REFRESH_TOKEN_EXPIRY", "30d")
	t.Setenv("AOID_SHUTDOWN_TIMEOUT", "10s")

	c := Load()
	if c.ListenAddr != "127.0.0.1:9000" {
		t.Errorf("ListenAddr override failed: %q", c.ListenAddr)
	}
	if c.Issuer != "https://id.example.com" {
		t.Errorf("Issuer override failed: %q", c.Issuer)
	}
	if c.Environment != "production" {
		t.Errorf("Environment override failed: %q", c.Environment)
	}
	if c.LogLevel != "debug" {
		t.Errorf("LogLevel override failed: %q", c.LogLevel)
	}
	if c.LogFormat != "json" {
		t.Errorf("LogFormat override failed: %q", c.LogFormat)
	}
	if c.Release != "abc123" {
		t.Errorf("Release override failed: %q", c.Release)
	}
	if c.DatabaseURL != "postgres://x@y/z" {
		t.Errorf("DatabaseURL override failed: %q", c.DatabaseURL)
	}
	if c.AccessTokenExpiry != 30*time.Minute {
		t.Errorf("AccessTokenExpiry override failed: %v", c.AccessTokenExpiry)
	}
	// "30d" is not a valid Go duration; expect default fallback.
	if c.RefreshTokenExpiry != 7*24*time.Hour {
		t.Errorf("RefreshTokenExpiry should fall back to default for invalid input, got %v", c.RefreshTokenExpiry)
	}
	if c.ShutdownTimeout != 10*time.Second {
		t.Errorf("ShutdownTimeout override failed: %v", c.ShutdownTimeout)
	}
}

func TestParseSeedPaths(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want map[string]string
	}{
		{"empty", "", nil},
		{"single", "k1=/p1", map[string]string{"k1": "/p1"}},
		{"multiple", "a=/x,b=/y", map[string]string{"a": "/x", "b": "/y"}},
		{"trim space", "  a = /x , b=/y  ", map[string]string{"a": "/x", "b": "/y"}},
		{"malformed dropped", "ok=/p,bad,empty=", map[string]string{"ok": "/p"}},
		{"all malformed", "bad,=,=path", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseSeedPaths(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("len mismatch: got %v want %v", got, tc.want)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("got[%q] = %q want %q", k, got[k], v)
				}
			}
		})
	}
}

// TestLoad_JWTRejectLegacyUntyped (issue #80): the env flag that closes the
// untyped-token migration window early. Unset = window follows its cutoff.
func TestLoad_JWTRejectLegacyUntyped(t *testing.T) {
	t.Setenv("AOID_JWT_REJECT_LEGACY_UNTYPED", "")
	if Load().JWTRejectLegacyUntyped {
		t.Error("unset: JWTRejectLegacyUntyped = true, want false")
	}
	t.Setenv("AOID_JWT_REJECT_LEGACY_UNTYPED", "true")
	if !Load().JWTRejectLegacyUntyped {
		t.Error("true: JWTRejectLegacyUntyped = false, want true")
	}
}
