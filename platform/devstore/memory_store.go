package devstore

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.aocyber.ai/eden-platform-go/platform/auth"
	"go.aocyber.ai/eden-platform-go/platform/company"
	"go.aocyber.ai/eden-platform-go/platform/rbac"
	"go.aocyber.ai/eden-platform-go/platform/webhook"
)

type memoryState struct {
	usersByID       map[uuid.UUID]auth.User
	usersByEmail    map[string]uuid.UUID
	companies       map[uuid.UUID]company.Company
	hierarchy       []company.CompanyHierarchy
	memberships     map[uuid.UUID][]auth.Membership
	roles           map[uuid.UUID]auth.Role
	refreshTokens   map[string]auth.RefreshTokenRecord
	ssoConfigs      map[string]auth.SSOConfig
	defaultSettings json.RawMessage

	// RBAC state
	rbacRoles       map[uuid.UUID]rbac.Role
	rbacPermissions map[uuid.UUID]rbac.Permission
	rolePermissions map[uuid.UUID][]uuid.UUID  // roleID -> []permissionID
	rbacMemberships map[string]rbac.Membership // "companyID:userID" -> Membership

	// Audit state
	auditLogs []auditLogEntry

	// Webhook state
	webhooks   map[uuid.UUID]webhook.Webhook
	deliveries map[uuid.UUID]webhook.WebhookDelivery
}

type Backend struct {
	mu    sync.RWMutex
	state *memoryState
}

func NewMemoryBackend() *Backend {
	defaultSettings := json.RawMessage(`{"enabled_features":["home","projects","activity","settings"]}`)
	return &Backend{
		state: &memoryState{
			usersByID:       map[uuid.UUID]auth.User{},
			usersByEmail:    map[string]uuid.UUID{},
			companies:       map[uuid.UUID]company.Company{},
			hierarchy:       []company.CompanyHierarchy{},
			memberships:     map[uuid.UUID][]auth.Membership{},
			roles:           authRoles(),
			refreshTokens:   map[string]auth.RefreshTokenRecord{},
			ssoConfigs:      map[string]auth.SSOConfig{},
			defaultSettings: defaultSettings,
			rbacRoles:       map[uuid.UUID]rbac.Role{},
			rbacPermissions: map[uuid.UUID]rbac.Permission{},
			rolePermissions: map[uuid.UUID][]uuid.UUID{},
			rbacMemberships: map[string]rbac.Membership{},
			auditLogs:       []auditLogEntry{},
			webhooks:        map[uuid.UUID]webhook.Webhook{},
			deliveries:      map[uuid.UUID]webhook.WebhookDelivery{},
		},
	}
}

func (b *Backend) AuthStore() *AuthStore {
	return &AuthStore{backend: b}
}

func (b *Backend) CompanyStore() *CompanyStore {
	return &CompanyStore{backend: b}
}

func (b *Backend) RBACStore() *RBACStore {
	return &RBACStore{backend: b}
}

func (b *Backend) AuditStore() *AuditStore {
	return &AuditStore{backend: b}
}

func (b *Backend) WebhookStore() *WebhookStore {
	return &WebhookStore{backend: b}
}

// SeedRBACRole seeds a system role into the RBAC store.
func (b *Backend) SeedRBACRole(role rbac.Role) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.state.rbacRoles[role.ID] = role
}

// SeedRBACPermission seeds a permission into the RBAC store.
func (b *Backend) SeedRBACPermission(perm rbac.Permission) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.state.rbacPermissions[perm.ID] = perm
}

// SetRBACMembershipOverrides sets permission overrides on an existing RBAC membership.
func (b *Backend) SetRBACMembershipOverrides(key string, overrides json.RawMessage) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if m, ok := b.state.rbacMemberships[key]; ok {
		m.PermissionOverrides = overrides
		b.state.rbacMemberships[key] = m
	}
}

// SetSSOConfig seeds an SSO configuration into the devstore.
func (b *Backend) SetSSOConfig(companyID uuid.UUID, provider string, config auth.SSOConfig) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.state.ssoConfigs[companyID.String()+":"+provider] = config
}

type AuthStore struct {
	backend *Backend
	state   *memoryState
}

type CompanyStore struct {
	backend *Backend
}

func authRoles() map[uuid.UUID]auth.Role {
	return map[uuid.UUID]auth.Role{
		rbac.OwnerRoleID:  {ID: rbac.OwnerRoleID, Name: "owner", RoleLevel: 90},
		rbac.AdminRoleID:  {ID: rbac.AdminRoleID, Name: "admin", RoleLevel: 80},
		rbac.MemberRoleID: {ID: rbac.MemberRoleID, Name: "member", RoleLevel: 40},
		rbac.ViewerRoleID: {ID: rbac.ViewerRoleID, Name: "viewer", RoleLevel: 20},
	}
}

func (s *AuthStore) BeginTx(ctx context.Context) (auth.TxAuthStore, error) {
	s.backend.mu.RLock()
	defer s.backend.mu.RUnlock()
	return &AuthStore{backend: s.backend, state: s.backend.state.clone()}, nil
}

func (s *AuthStore) Commit(ctx context.Context) error {
	if s.state == nil {
		return nil
	}
	s.backend.mu.Lock()
	defer s.backend.mu.Unlock()
	s.backend.state = s.state
	return nil
}

func (s *AuthStore) Rollback(ctx context.Context) error {
	return nil
}

func (s *AuthStore) stateRef() *memoryState {
	if s.state != nil {
		return s.state
	}
	return s.backend.state
}

func (s *AuthStore) GetUserByEmail(ctx context.Context, email string) (auth.User, error) {
	s.backend.mu.RLock()
	defer s.backend.mu.RUnlock()
	state := s.stateRef()
	id, ok := state.usersByEmail[strings.ToLower(strings.TrimSpace(email))]
	if !ok {
		return auth.User{}, fmt.Errorf("user not found")
	}
	return state.usersByID[id], nil
}

func (s *AuthStore) GetUserByID(ctx context.Context, id uuid.UUID) (auth.User, error) {
	s.backend.mu.RLock()
	defer s.backend.mu.RUnlock()
	state := s.stateRef()
	user, ok := state.usersByID[id]
	if !ok {
		return auth.User{}, fmt.Errorf("user not found")
	}
	return user, nil
}

func (s *AuthStore) CreateUser(ctx context.Context, email, passwordHash, displayName string) (auth.User, error) {
	s.backend.mu.Lock()
	defer s.backend.mu.Unlock()
	state := s.stateRef()

	normalized := strings.ToLower(strings.TrimSpace(email))
	if _, exists := state.usersByEmail[normalized]; exists {
		return auth.User{}, fmt.Errorf("duplicate key")
	}

	user := auth.User{
		ID:           uuid.New(),
		Email:        normalized,
		PasswordHash: passwordHash,
		DisplayName:  strings.TrimSpace(displayName),
		IsActive:     true,
		CreatedAt:    time.Now().UTC(),
	}
	state.usersByID[user.ID] = user
	state.usersByEmail[normalized] = user.ID
	return user, nil
}

func (s *AuthStore) UpdateUser(ctx context.Context, id uuid.UUID, displayName, avatarURL string) (auth.User, error) {
	s.backend.mu.Lock()
	defer s.backend.mu.Unlock()
	state := s.stateRef()

	user, exists := state.usersByID[id]
	if !exists {
		return auth.User{}, fmt.Errorf("user not found")
	}
	user.DisplayName = displayName
	user.AvatarURL = avatarURL
	state.usersByID[id] = user
	return user, nil
}

func (s *AuthStore) CreateCompany(ctx context.Context, name, slug, companyType string) (uuid.UUID, error) {
	s.backend.mu.Lock()
	defer s.backend.mu.Unlock()
	state := s.stateRef()

	ct := company.CompanyType(companyType)
	if ct == "" {
		ct = company.CompanyTypeStandalone
	}
	id := uuid.New()
	now := time.Now().UTC()
	state.companies[id] = company.Company{
		ID:          id,
		Name:        name,
		Slug:        slug,
		CompanyType: ct,
		Settings:    append(json.RawMessage(nil), state.defaultSettings...),
		IsActive:    true,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	insertHierarchy(state, company.CompanyHierarchy{AncestorID: id, DescendantID: id, Generations: 0})
	return id, nil
}

func (s *AuthStore) CreateCompanyMembership(ctx context.Context, companyID, userID, roleID uuid.UUID) error {
	s.backend.mu.Lock()
	defer s.backend.mu.Unlock()
	state := s.stateRef()

	role, ok := state.roles[roleID]
	if !ok {
		return fmt.Errorf("role not found")
	}
	current := state.memberships[userID]
	for _, membership := range current {
		if membership.CompanyID == companyID {
			return nil
		}
	}
	state.memberships[userID] = append(current, auth.Membership{
		CompanyID: companyID,
		UserID:    userID,
		RoleID:    roleID,
		RoleName:  role.Name,
	})
	return nil
}

func (s *AuthStore) GetCompanyMembershipByUser(ctx context.Context, userID uuid.UUID) (auth.Membership, error) {
	s.backend.mu.RLock()
	defer s.backend.mu.RUnlock()
	state := s.stateRef()
	memberships := state.memberships[userID]
	if len(memberships) == 0 {
		return auth.Membership{}, fmt.Errorf("membership not found")
	}
	// Oldest membership ("home" company) first, matching pgstore's
	// ListUserCompanyIDs ORDER BY created_at ASC. CreateCompanyMembership only
	// ever appends, so slice order IS creation order.
	return memberships[0], nil
}

// ListUserCompanyIDs implements auth.MembershipLister: the user's company
// ids, oldest membership first.
func (s *AuthStore) ListUserCompanyIDs(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, error) {
	s.backend.mu.RLock()
	defer s.backend.mu.RUnlock()
	state := s.stateRef()
	ids := make([]uuid.UUID, 0, len(state.memberships[userID]))
	for _, m := range state.memberships[userID] {
		ids = append(ids, m.CompanyID)
	}
	return ids, nil
}

func (s *AuthStore) GetRoleByID(ctx context.Context, roleID uuid.UUID) (auth.Role, error) {
	s.backend.mu.RLock()
	defer s.backend.mu.RUnlock()
	state := s.stateRef()
	role, ok := state.roles[roleID]
	if !ok {
		return auth.Role{}, fmt.Errorf("role not found")
	}
	return role, nil
}

func (s *AuthStore) GetUserRole(ctx context.Context, companyID, userID uuid.UUID) (auth.Role, error) {
	s.backend.mu.RLock()
	defer s.backend.mu.RUnlock()
	state := s.stateRef()
	for _, membership := range state.memberships[userID] {
		if membership.CompanyID == companyID {
			role, ok := state.roles[membership.RoleID]
			if !ok {
				return auth.Role{}, fmt.Errorf("role not found")
			}
			return role, nil
		}
	}
	return auth.Role{}, fmt.Errorf("role not found")
}

func (s *AuthStore) CreateRefreshToken(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) error {
	s.backend.mu.Lock()
	defer s.backend.mu.Unlock()
	state := s.stateRef()
	state.refreshTokens[tokenHash] = auth.RefreshTokenRecord{UserID: userID, TokenHash: tokenHash, ExpiresAt: expiresAt}
	return nil
}

func (s *AuthStore) GetRefreshToken(ctx context.Context, tokenHash string) (auth.RefreshTokenRecord, error) {
	s.backend.mu.RLock()
	defer s.backend.mu.RUnlock()
	state := s.stateRef()
	record, ok := state.refreshTokens[tokenHash]
	if !ok || time.Now().UTC().After(record.ExpiresAt) {
		return auth.RefreshTokenRecord{}, fmt.Errorf("refresh token not found")
	}
	return record, nil
}

// ConsumeRefreshToken implements auth.RefreshTokenConsumer: it removes an
// active refresh token under the write lock, or reports
// auth.ErrRefreshTokenNotActive.
func (s *AuthStore) ConsumeRefreshToken(ctx context.Context, tokenHash string) error {
	s.backend.mu.Lock()
	defer s.backend.mu.Unlock()
	state := s.stateRef()
	record, ok := state.refreshTokens[tokenHash]
	if !ok || time.Now().UTC().After(record.ExpiresAt) {
		return auth.ErrRefreshTokenNotActive
	}
	delete(state.refreshTokens, tokenHash)
	return nil
}

func (s *AuthStore) RevokeRefreshToken(ctx context.Context, tokenHash string) error {
	s.backend.mu.Lock()
	defer s.backend.mu.Unlock()
	state := s.stateRef()
	delete(state.refreshTokens, tokenHash)
	return nil
}

func (s *AuthStore) GetSSOConfig(ctx context.Context, companyID uuid.UUID, provider string) (auth.SSOConfig, error) {
	s.backend.mu.RLock()
	defer s.backend.mu.RUnlock()
	state := s.stateRef()
	config, ok := state.ssoConfigs[companyID.String()+":"+provider]
	if !ok {
		return auth.SSOConfig{}, fmt.Errorf("sso config not found")
	}
	return config, nil
}

func (s *AuthStore) ListSSOConfigs(ctx context.Context, companyID uuid.UUID) ([]auth.SSOConfig, error) {
	s.backend.mu.RLock()
	defer s.backend.mu.RUnlock()
	state := s.stateRef()
	var configs []auth.SSOConfig
	for key, cfg := range state.ssoConfigs {
		if len(key) > 36 && key[:36] == companyID.String() {
			configs = append(configs, cfg)
		}
	}
	return configs, nil
}

func (s *AuthStore) UpsertSSOConfig(ctx context.Context, cfg auth.SSOConfig) error {
	s.backend.mu.Lock()
	defer s.backend.mu.Unlock()
	state := s.stateRef()
	state.ssoConfigs[cfg.CompanyID.String()+":"+cfg.Provider] = cfg
	return nil
}

func (s *AuthStore) DeleteSSOConfig(ctx context.Context, companyID uuid.UUID, provider string) error {
	s.backend.mu.Lock()
	defer s.backend.mu.Unlock()
	state := s.stateRef()
	delete(state.ssoConfigs, companyID.String()+":"+provider)
	return nil
}

func (s *AuthStore) HasEnforcedSSO(ctx context.Context, companyID uuid.UUID) (bool, error) {
	s.backend.mu.RLock()
	defer s.backend.mu.RUnlock()
	state := s.stateRef()
	for key, cfg := range state.ssoConfigs {
		if len(key) > 36 && key[:36] == companyID.String() && cfg.EnforceSSO && cfg.IsActive {
			return true, nil
		}
	}
	return false, nil
}

// ResolveJITCompanyByIssuerDomain scans the in-memory SSOConfigs for the single
// active, jit_enabled config whose issuer + email-domain allowlist match
// (COMPANION-AV05-AOID-JIT TRD-06). Zero ⇒ ErrNoJITMatch; >1 ⇒ ErrAmbiguousJITMatch.
func (s *AuthStore) ResolveJITCompanyByIssuerDomain(ctx context.Context, issuer, emailDomain string) (uuid.UUID, string, error) {
	s.backend.mu.RLock()
	defer s.backend.mu.RUnlock()
	state := s.stateRef()
	var matches []auth.SSOConfig
	for _, cfg := range state.ssoConfigs {
		if cfg.IssuerURL != issuer || !cfg.IsActive || !cfg.JITEnabled {
			continue
		}
		for _, d := range cfg.EmailDomainAllowlist {
			if d == emailDomain {
				matches = append(matches, cfg)
				break
			}
		}
	}
	switch len(matches) {
	case 0:
		return uuid.Nil, "", auth.ErrNoJITMatch
	case 1:
		return matches[0].CompanyID, matches[0].JITDefaultRole, nil
	default:
		return uuid.Nil, "", auth.ErrAmbiguousJITMatch
	}
}

func (s *AuthStore) UpsertOAuthCredential(ctx context.Context, cred auth.OAuthCredential) error {
	return nil // noop for dev store
}

func (s *AuthStore) GetOAuthCredential(ctx context.Context, userID uuid.UUID, provider string) (auth.OAuthCredential, error) {
	return auth.OAuthCredential{}, fmt.Errorf("oauth credential not found")
}

func (s *AuthStore) CreateAuditLog(ctx context.Context, companyID, actorID uuid.UUID, action, resource, resourceID, ipAddress string, details []byte) error {
	return nil
}

func (s *CompanyStore) ListCompaniesForUser(ctx context.Context, userID uuid.UUID) ([]company.Company, error) {
	s.backend.mu.RLock()
	defer s.backend.mu.RUnlock()

	memberships := s.backend.state.memberships[userID]
	companies := make([]company.Company, 0, len(memberships))
	for _, membership := range memberships {
		if companyRecord, ok := s.backend.state.companies[membership.CompanyID]; ok {
			companies = append(companies, companyRecord)
		}
	}
	sort.Slice(companies, func(i, j int) bool { return companies[i].Name < companies[j].Name })
	return companies, nil
}

func (s *CompanyStore) CreateCompany(ctx context.Context, c company.Company) (company.Company, error) {
	s.backend.mu.Lock()
	defer s.backend.mu.Unlock()

	now := time.Now().UTC()
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	if c.Settings == nil {
		c.Settings = append(json.RawMessage(nil), s.backend.state.defaultSettings...)
	}
	if c.CompanyType == "" {
		c.CompanyType = company.CompanyTypeStandalone
	}
	c.IsActive = true
	if c.CreatedAt.IsZero() {
		c.CreatedAt = now
	}
	c.UpdatedAt = now
	s.backend.state.companies[c.ID] = c
	insertHierarchy(s.backend.state, company.CompanyHierarchy{AncestorID: c.ID, DescendantID: c.ID, Generations: 0})
	if c.ParentCompanyID != nil {
		for _, ancestor := range getAncestors(s.backend.state, *c.ParentCompanyID) {
			insertHierarchy(s.backend.state, company.CompanyHierarchy{
				AncestorID:   ancestor.AncestorID,
				DescendantID: c.ID,
				Generations:  ancestor.Generations + 1,
			})
		}
	}
	return c, nil
}

func (s *CompanyStore) GetCompany(ctx context.Context, id uuid.UUID) (company.Company, error) {
	s.backend.mu.RLock()
	defer s.backend.mu.RUnlock()

	companyRecord, ok := s.backend.state.companies[id]
	if !ok {
		return company.Company{}, fmt.Errorf("company not found")
	}
	return companyRecord, nil
}

func (s *CompanyStore) UpdateCompany(ctx context.Context, c company.Company) (company.Company, error) {
	s.backend.mu.Lock()
	defer s.backend.mu.Unlock()

	current, ok := s.backend.state.companies[c.ID]
	if !ok {
		return company.Company{}, fmt.Errorf("company not found")
	}
	if c.Name != "" {
		current.Name = c.Name
	}
	if c.Slug != "" {
		current.Slug = c.Slug
	}
	if c.CompanyType != "" {
		current.CompanyType = c.CompanyType
	}
	current.InheritedRoleCap = c.InheritedRoleCap
	current.InheritedAccessLvl = c.InheritedAccessLvl
	if c.Settings != nil {
		current.Settings = c.Settings
	}
	current.UpdatedAt = time.Now().UTC()
	s.backend.state.companies[c.ID] = current
	return current, nil
}

func (s *CompanyStore) ListCompanies(ctx context.Context) ([]company.Company, error) {
	s.backend.mu.RLock()
	defer s.backend.mu.RUnlock()

	companies := make([]company.Company, 0, len(s.backend.state.companies))
	for _, companyRecord := range s.backend.state.companies {
		companies = append(companies, companyRecord)
	}
	sort.Slice(companies, func(i, j int) bool { return companies[i].Name < companies[j].Name })
	return companies, nil
}

func (s *CompanyStore) InsertHierarchyEntries(ctx context.Context, entries []company.CompanyHierarchy) error {
	s.backend.mu.Lock()
	defer s.backend.mu.Unlock()
	for _, entry := range entries {
		insertHierarchy(s.backend.state, entry)
	}
	return nil
}

func (s *CompanyStore) GetAncestors(ctx context.Context, companyID uuid.UUID) ([]company.CompanyHierarchy, error) {
	s.backend.mu.RLock()
	defer s.backend.mu.RUnlock()
	return getAncestors(s.backend.state, companyID), nil
}

func (s *CompanyStore) GetDescendants(ctx context.Context, companyID uuid.UUID) ([]company.CompanyHierarchy, error) {
	s.backend.mu.RLock()
	defer s.backend.mu.RUnlock()

	entries := make([]company.CompanyHierarchy, 0)
	for _, entry := range s.backend.state.hierarchy {
		if entry.AncestorID == companyID {
			entries = append(entries, entry)
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Generations < entries[j].Generations })
	return entries, nil
}

func (s *CompanyStore) GetSelfAndDescendantIDs(ctx context.Context, companyID uuid.UUID) ([]uuid.UUID, error) {
	descendants, err := s.GetDescendants(ctx, companyID)
	if err != nil {
		return nil, err
	}
	ids := make([]uuid.UUID, 0, len(descendants))
	for _, entry := range descendants {
		ids = append(ids, entry.DescendantID)
	}
	return ids, nil
}

func (s *CompanyStore) DeleteHierarchyEntries(ctx context.Context, descendantID uuid.UUID) error {
	s.backend.mu.Lock()
	defer s.backend.mu.Unlock()

	filtered := s.backend.state.hierarchy[:0]
	for _, entry := range s.backend.state.hierarchy {
		if entry.DescendantID != descendantID {
			filtered = append(filtered, entry)
		}
	}
	s.backend.state.hierarchy = filtered
	return nil
}

func getAncestors(state *memoryState, companyID uuid.UUID) []company.CompanyHierarchy {
	entries := make([]company.CompanyHierarchy, 0)
	for _, entry := range state.hierarchy {
		if entry.DescendantID == companyID {
			entries = append(entries, entry)
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Generations < entries[j].Generations })
	return entries
}

func insertHierarchy(state *memoryState, entry company.CompanyHierarchy) {
	for _, existing := range state.hierarchy {
		if existing.AncestorID == entry.AncestorID &&
			existing.DescendantID == entry.DescendantID &&
			existing.Generations == entry.Generations {
			return
		}
	}
	state.hierarchy = append(state.hierarchy, entry)
}

func (s *memoryState) clone() *memoryState {
	cloned := &memoryState{
		usersByID:       map[uuid.UUID]auth.User{},
		usersByEmail:    map[string]uuid.UUID{},
		companies:       map[uuid.UUID]company.Company{},
		hierarchy:       append([]company.CompanyHierarchy(nil), s.hierarchy...),
		memberships:     map[uuid.UUID][]auth.Membership{},
		roles:           map[uuid.UUID]auth.Role{},
		refreshTokens:   map[string]auth.RefreshTokenRecord{},
		ssoConfigs:      map[string]auth.SSOConfig{},
		defaultSettings: append(json.RawMessage(nil), s.defaultSettings...),
		rbacRoles:       map[uuid.UUID]rbac.Role{},
		rbacPermissions: map[uuid.UUID]rbac.Permission{},
		rolePermissions: map[uuid.UUID][]uuid.UUID{},
		rbacMemberships: map[string]rbac.Membership{},
		auditLogs:       append([]auditLogEntry(nil), s.auditLogs...),
		webhooks:        map[uuid.UUID]webhook.Webhook{},
		deliveries:      map[uuid.UUID]webhook.WebhookDelivery{},
	}

	for id, wh := range s.webhooks {
		cloned.webhooks[id] = wh
	}
	for id, d := range s.deliveries {
		cloned.deliveries[id] = d
	}

	for id, user := range s.usersByID {
		cloned.usersByID[id] = user
	}
	for email, id := range s.usersByEmail {
		cloned.usersByEmail[email] = id
	}
	for id, companyRecord := range s.companies {
		if companyRecord.Settings != nil {
			companyRecord.Settings = append(json.RawMessage(nil), companyRecord.Settings...)
		}
		cloned.companies[id] = companyRecord
	}
	for userID, memberships := range s.memberships {
		cloned.memberships[userID] = append([]auth.Membership(nil), memberships...)
	}
	for id, role := range s.roles {
		cloned.roles[id] = role
	}
	for hash, token := range s.refreshTokens {
		cloned.refreshTokens[hash] = token
	}
	for key, config := range s.ssoConfigs {
		cloned.ssoConfigs[key] = config
	}
	for id, role := range s.rbacRoles {
		cloned.rbacRoles[id] = role
	}
	for id, perm := range s.rbacPermissions {
		cloned.rbacPermissions[id] = perm
	}
	for roleID, permIDs := range s.rolePermissions {
		cloned.rolePermissions[roleID] = append([]uuid.UUID(nil), permIDs...)
	}
	for key, membership := range s.rbacMemberships {
		cloned.rbacMemberships[key] = membership
	}
	return cloned
}
