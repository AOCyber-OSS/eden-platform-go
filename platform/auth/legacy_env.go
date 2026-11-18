package auth

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Env var names a consumer can use to drive the issue-#80 legacy window
// through ApplyLegacyUntypedEnv (eden-biz: set them on the biz-api service).
const (
	// EnvRejectLegacyUntyped ("true"/"1") closes the window now.
	EnvRejectLegacyUntyped = "EDEN_JWT_REJECT_LEGACY_UNTYPED"
	// EnvLegacyUntypedCutoff (RFC 3339) overrides DefaultLegacyUntypedCutoff.
	EnvLegacyUntypedCutoff = "EDEN_JWT_LEGACY_UNTYPED_CUTOFF"
)

// ApplyLegacyUntypedEnv sets cfg.RejectLegacyUntyped and
// cfg.LegacyUntypedCutoff from EnvRejectLegacyUntyped and
// EnvLegacyUntypedCutoff, read through getenv (normally os.Getenv). Unset
// variables leave cfg unchanged; an unparseable value is an error, so a typo
// fails boot rather than silently keeping the window open.
func ApplyLegacyUntypedEnv(cfg *JWTConfig, getenv func(string) string) error {
	if raw := strings.TrimSpace(getenv(EnvRejectLegacyUntyped)); raw != "" {
		v, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("%s: %w", EnvRejectLegacyUntyped, err)
		}
		cfg.RejectLegacyUntyped = v
	}
	if raw := strings.TrimSpace(getenv(EnvLegacyUntypedCutoff)); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return fmt.Errorf("%s: %w", EnvLegacyUntypedCutoff, err)
		}
		cfg.LegacyUntypedCutoff = t
	}
	return nil
}
