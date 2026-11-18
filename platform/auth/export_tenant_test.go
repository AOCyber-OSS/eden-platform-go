package auth

import (
	"context"

	"github.com/google/uuid"
)

// JITProvisionForTest exposes SSO JIT provisioning (the path that signs a
// user in to one specific company) to the external auth_test package.
func (s *SSOService) JITProvisionForTest(ctx context.Context, email, name string, companyID uuid.UUID) (*AuthResponse, error) {
	return s.jitProvision(ctx, email, name, companyID, "oidc")
}
