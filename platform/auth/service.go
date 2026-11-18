package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.aocyber.ai/eden-platform-go/platform/rbac"
)

// AuthResponse contains the tokens and user info returned after successful authentication.
type AuthResponse struct {
	AccessToken  string
	RefreshToken string
	User         User
}

// Service contains the business logic for authentication operations.
type Service struct {
	store          TxAuthStore
	jwtManager     *JWTManager
	passwordHasher *PasswordHasher
	b2cMode        bool
}

// NewService creates a new auth Service.
// When b2cMode is true, signup creates a personal workspace instead of a named company.
func NewService(store TxAuthStore, jwtManager *JWTManager, passwordHasher *PasswordHasher, b2cMode ...bool) *Service {
	mode := false
	if len(b2cMode) > 0 {
		mode = b2cMode[0]
	}
	return &Service{
		store:          store,
		jwtManager:     jwtManager,
		passwordHasher: passwordHasher,
		b2cMode:        mode,
	}
}

// SignUp creates a new user account, a default company, and assigns the user as owner.
func (s *Service) SignUp(ctx context.Context, email, password, displayName string) (*AuthResponse, error) {
	if err := validateEmail(email); err != nil {
		return nil, fmt.Errorf("invalid email: %w", err)
	}
	if len(password) < 8 {
		return nil, fmt.Errorf("password must be at least 8 characters")
	}
	if strings.TrimSpace(displayName) == "" {
		return nil, fmt.Errorf("display name is required")
	}

	hashedPassword, err := s.passwordHasher.Hash(password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	tx, err := s.store.BeginTx(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	email = strings.ToLower(strings.TrimSpace(email))
	user, err := tx.CreateUser(ctx, email, hashedPassword, strings.TrimSpace(displayName))
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "unique constraint") {
			return nil, fmt.Errorf("an account with this email already exists")
		}
		return nil, fmt.Errorf("create user: %w", err)
	}

	var companyName, companySlug, companyType string
	if s.b2cMode {
		companyName = strings.TrimSpace(displayName)
		companySlug = fmt.Sprintf("personal-%s", user.ID.String()[:8])
		companyType = "personal"
	} else {
		companyName = fmt.Sprintf("%s's Company", strings.TrimSpace(displayName))
		companySlug = generateSlug(displayName)
		companyType = "standalone"
	}
	companyID, err := tx.CreateCompany(ctx, companyName, companySlug, companyType)
	if err != nil {
		return nil, fmt.Errorf("create company: %w", err)
	}

	if err := tx.CreateCompanyMembership(ctx, companyID, user.ID, rbac.OwnerRoleID); err != nil {
		return nil, fmt.Errorf("create company membership: %w", err)
	}

	companyIDStr := companyID.String()
	accessToken, err := s.jwtManager.CreateAccessToken(user.ID.String(), companyIDStr, "owner", 90, []string{companyIDStr})
	if err != nil {
		return nil, fmt.Errorf("create access token: %w", err)
	}

	refreshToken, err := s.jwtManager.CreateCompanyRefreshToken(user.ID.String(), companyIDStr)
	if err != nil {
		return nil, fmt.Errorf("create refresh token: %w", err)
	}

	tokenHash := HashToken(refreshToken)
	if err := tx.CreateRefreshToken(ctx, user.ID, tokenHash, time.Now().Add(s.jwtManager.config.RefreshTokenExpiry)); err != nil {
		return nil, fmt.Errorf("store refresh token: %w", err)
	}

	_ = tx.CreateAuditLog(ctx, companyID, user.ID, "user.signup", "user", user.ID.String(), "", []byte("{}"))

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}

	return &AuthResponse{AccessToken: accessToken, RefreshToken: refreshToken, User: user}, nil
}

// Login authenticates a user with email and password.
func (s *Service) Login(ctx context.Context, email, password string) (*AuthResponse, error) {
	genericErr := fmt.Errorf("invalid credentials")

	user, err := s.store.GetUserByEmail(ctx, strings.ToLower(strings.TrimSpace(email)))
	if err != nil {
		slog.Debug("login: user not found", "email", email)
		return nil, genericErr
	}
	if !user.IsActive {
		return nil, genericErr
	}

	match, err := s.passwordHasher.Verify(password, user.PasswordHash)
	if err != nil || !match {
		return nil, genericErr
	}

	membership, err := s.store.GetCompanyMembershipByUser(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("get company membership: %w", err)
	}

	role, err := s.store.GetRoleByID(ctx, membership.RoleID)
	if err != nil {
		return nil, fmt.Errorf("get role: %w", err)
	}

	companyIDStr := membership.CompanyID.String()
	accessToken, err := s.jwtManager.CreateAccessToken(user.ID.String(), companyIDStr, role.Name, role.RoleLevel, []string{companyIDStr})
	if err != nil {
		return nil, fmt.Errorf("create access token: %w", err)
	}

	refreshToken, err := s.jwtManager.CreateCompanyRefreshToken(user.ID.String(), companyIDStr)
	if err != nil {
		return nil, fmt.Errorf("create refresh token: %w", err)
	}

	tokenHash := HashToken(refreshToken)
	if err := s.store.CreateRefreshToken(ctx, user.ID, tokenHash, time.Now().Add(s.jwtManager.config.RefreshTokenExpiry)); err != nil {
		return nil, fmt.Errorf("store refresh token: %w", err)
	}

	_ = s.store.CreateAuditLog(ctx, membership.CompanyID, user.ID, "user.login", "user", user.ID.String(), "", []byte("{}"))

	return &AuthResponse{AccessToken: accessToken, RefreshToken: refreshToken, User: user}, nil
}

// SignInNavigators authenticates a user the same way Login does, but issues
// an access token carrying Scopes=["volunteer:field"] and an EMPTY staff
// Role (RoleLevel=0). Used by the Navigators OAuth client at AO ID to mint
// tokens explicitly bounded to /v1/me/* on the politihub API (per ADR-0003).
//
// The refresh token is unchanged in shape — refresh-shape changes are NOT
// in scope for politihub ADR-0003 v1. When a Navigators access token
// expires the client re-issues via SignInNavigators rather than using the
// AO ID refresh endpoint (which would call CreateAccessToken — not
// CreateAccessTokenWithScopes — and lose the volunteer:field scope). This
// is documented behavior, not a bug.
//
// Audit log entry: "user.login_navigators" with a {"client":"navigators"}
// metadata blob to distinguish from the staff "user.login" path.
func (s *Service) SignInNavigators(ctx context.Context, email, password string) (*AuthResponse, error) {
	genericErr := fmt.Errorf("invalid credentials")

	user, err := s.store.GetUserByEmail(ctx, strings.ToLower(strings.TrimSpace(email)))
	if err != nil {
		slog.Debug("signin-navigators: user not found", "email", email)
		return nil, genericErr
	}
	if !user.IsActive {
		return nil, genericErr
	}

	match, err := s.passwordHasher.Verify(password, user.PasswordHash)
	if err != nil || !match {
		return nil, genericErr
	}

	membership, err := s.store.GetCompanyMembershipByUser(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("get company membership: %w", err)
	}

	companyIDStr := membership.CompanyID.String()
	accessToken, err := s.jwtManager.CreateAccessTokenWithScopes(
		user.ID.String(),
		companyIDStr,
		"", // explicit: no staff role on Navigators tokens
		0,  // explicit: no role level
		[]string{companyIDStr},
		[]string{"volunteer:field"}, // the politihub volunteer scope per ADR-0003
	)
	if err != nil {
		return nil, fmt.Errorf("create navigators access token: %w", err)
	}

	refreshToken, err := s.jwtManager.CreateRefreshToken(user.ID.String())
	if err != nil {
		return nil, fmt.Errorf("create refresh token: %w", err)
	}

	tokenHash := HashToken(refreshToken)
	if err := s.store.CreateRefreshToken(ctx, user.ID, tokenHash, time.Now().Add(s.jwtManager.config.RefreshTokenExpiry)); err != nil {
		return nil, fmt.Errorf("store refresh token: %w", err)
	}

	_ = s.store.CreateAuditLog(ctx, membership.CompanyID, user.ID, "user.login_navigators", "user", user.ID.String(), "", []byte(`{"client":"navigators"}`))

	return &AuthResponse{AccessToken: accessToken, RefreshToken: refreshToken, User: user}, nil
}

// JWTManagerForTest exposes the internal JWTManager for in-package and
// _test.go callers that need to validate tokens issued by the service
// against the same ephemeral key the service used. NOT for production use
// — the naming makes that explicit. (Exported because external _test.go
// files cannot reach unexported fields.)
func (s *Service) JWTManagerForTest() *JWTManager {
	return s.jwtManager
}

// MembershipLister is an optional AuthStore capability: the ids of every
// company the user belongs to. Service.RefreshToken uses it only to redeem a
// pre-#80 refresh token, which names no company: such a token is redeemed
// only when the user belongs to exactly one company. A store without it
// cannot redeem those tokens (fail closed).
type MembershipLister interface {
	ListUserCompanyIDs(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, error)
}

// RefreshToken validates, revokes old, and issues new token pair.
//
// The new access token is scoped exactly as the refresh token says, never by
// a guess from the user's memberships:
//   - company-bound (cid claim, from CreateCompanyRefreshToken): re-minted
//     for that company only, with the role the user holds there now; refused
//     if the user is no longer a member.
//   - typed but company-less (CreateRefreshToken): re-minted company-less.
//   - pre-#80 (no token_use, legacy window only): redeemed only when the user
//     belongs to exactly one company, which is then the company; refused
//     otherwise, because the issuing company cannot be known.
//
// It redeems only refresh tokens that are not bound to an OAuth client: a
// token issued to a client by AO ID (aud = client id) must be redeemed through
// RefreshTokenForClient by that client, or the binding could be bypassed here.
func (s *Service) RefreshToken(ctx context.Context, refreshTokenStr string) (*AuthResponse, error) {
	claims, err := s.jwtManager.ValidateRefreshTokenClaims(refreshTokenStr)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token")
	}
	if len(claims.Audience) > 0 {
		return nil, fmt.Errorf("invalid refresh token: bound to a client")
	}
	return s.rotateRefresh(ctx, refreshTokenStr, claims, refreshScope{legacyGuess: claims.TokenUse == ""},
		func(userID, companyID string) (string, error) {
			if companyID == "" {
				return s.jwtManager.CreateRefreshToken(userID)
			}
			return s.jwtManager.CreateCompanyRefreshToken(userID, companyID)
		})
}

// RefreshTokenForClient is RefreshToken for an OAuth refresh_token grant
// (issue #80). The refresh token must be bound to clientID (its aud, set by
// JWTManager.CreateClientRefreshToken), and the rotated refresh token is bound
// to clientID again. The binding is checked before the old token is revoked,
// so a wrong-client attempt does not burn the owner's token.
//
// Company scope follows the token as in RefreshToken, except that a
// company-less token (every AO ID token today, and pre-#80 ones) re-mints the
// company-less "user" access token AO ID issues at the code grant — never a
// company picked from the user's memberships.
//
// Migration: a pre-#80 refresh token (no token_use, so no binding) is
// accepted while the JWTManager's legacy window is open and is re-issued bound
// to the presenting client. A typed refresh token without a binding (minted by
// a password/SSO login, not by an OAuth client) is rejected.
func (s *Service) RefreshTokenForClient(ctx context.Context, refreshTokenStr, clientID string) (*AuthResponse, error) {
	if clientID == "" {
		return nil, fmt.Errorf("invalid refresh token: empty client id")
	}
	claims, err := s.jwtManager.ValidateRefreshTokenClaims(refreshTokenStr)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token")
	}
	legacyUnbound := claims.TokenUse == "" && len(claims.Audience) == 0
	// A federation-bridge token is issued before any OAuth client is known
	// (the federation flow carries none). It is company-bound, and the first
	// client to redeem it gets a token bound to that client from then on.
	federation := len(claims.Audience) == 1 && claims.Audience[0] == FederationRefreshAudience && claims.CompanyID != ""
	if !legacyUnbound && !federation && !(len(claims.Audience) == 1 && claims.Audience[0] == clientID) {
		return nil, fmt.Errorf("invalid refresh token: not issued to this client")
	}
	return s.rotateRefresh(ctx, refreshTokenStr, claims, refreshScope{companyLessRole: "user"},
		func(userID, companyID string) (string, error) {
			return s.jwtManager.CreateClientCompanyRefreshToken(userID, clientID, companyID)
		})
}

// FederationRefreshAudience is the aud of a refresh token minted by the AO ID
// federation bridge, which has no OAuth client to bind to. Such a token must
// also be company-bound; see RefreshTokenForClient.
const FederationRefreshAudience = "aoid:federation"

// refreshScope tunes how rotateRefresh scopes a company-less refresh token.
type refreshScope struct {
	// legacyGuess: the token predates #80 and names no company; resolve the
	// company only when the user has exactly one membership.
	legacyGuess bool
	// companyLessRole is the role stamped on a company-less access token.
	companyLessRole string
}

// rotateRefresh looks up, revokes and replaces a validated refresh token. The
// company scope is resolved and checked before the old token is revoked, so a
// refused refresh never burns the token. mintRefresh mints the replacement for
// (userID, companyID), companyID empty for a company-less session.
func (s *Service) rotateRefresh(ctx context.Context, refreshTokenStr string, claims *RefreshClaims, scope refreshScope, mintRefresh func(userID, companyID string) (string, error)) (*AuthResponse, error) {
	tokenHash := HashToken(refreshTokenStr)
	storedToken, err := s.store.GetRefreshToken(ctx, tokenHash)
	if err != nil {
		return nil, fmt.Errorf("refresh token not found or expired")
	}

	user, err := s.store.GetUserByID(ctx, storedToken.UserID)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}

	companyID := uuid.Nil
	switch {
	case claims.CompanyID != "":
		companyID, err = uuid.Parse(claims.CompanyID)
		if err != nil {
			return nil, fmt.Errorf("invalid refresh token: bad company")
		}
	case scope.legacyGuess:
		companyID, err = s.soleCompany(ctx, user.ID)
		if err != nil {
			return nil, err
		}
	}

	var role Role
	if companyID != uuid.Nil {
		// Re-read the role in the bound company; fails if no longer a member.
		role, err = s.store.GetUserRole(ctx, companyID, user.ID)
		if err != nil {
			return nil, fmt.Errorf("invalid refresh token: not a member of the session's company")
		}
	}

	if err := s.consumeRefresh(ctx, tokenHash); err != nil {
		return nil, err
	}

	var newAccessToken, companyIDStr string
	if companyID != uuid.Nil {
		companyIDStr = companyID.String()
		newAccessToken, err = s.jwtManager.CreateAccessToken(user.ID.String(), companyIDStr, role.Name, role.RoleLevel, []string{companyIDStr})
	} else {
		newAccessToken, err = s.jwtManager.CreateAccessToken(user.ID.String(), "", scope.companyLessRole, 0, nil)
	}
	if err != nil {
		return nil, fmt.Errorf("create access token: %w", err)
	}

	newRefreshToken, err := mintRefresh(user.ID.String(), companyIDStr)
	if err != nil {
		return nil, fmt.Errorf("create refresh token: %w", err)
	}

	newTokenHash := HashToken(newRefreshToken)
	if err := s.store.CreateRefreshToken(ctx, user.ID, newTokenHash, time.Now().Add(s.jwtManager.config.RefreshTokenExpiry)); err != nil {
		return nil, fmt.Errorf("store new refresh token: %w", err)
	}

	return &AuthResponse{AccessToken: newAccessToken, RefreshToken: newRefreshToken, User: user}, nil
}

// consumeRefresh revokes the old refresh token, single-use: with a
// RefreshTokenConsumer store a token another redeem already consumed is
// refused here, so concurrent redeems yield one new pair.
func (s *Service) consumeRefresh(ctx context.Context, tokenHash string) error {
	if c, ok := s.store.(RefreshTokenConsumer); ok {
		if err := c.ConsumeRefreshToken(ctx, tokenHash); err != nil {
			if errors.Is(err, ErrRefreshTokenNotActive) {
				return fmt.Errorf("refresh token already used or revoked")
			}
			return fmt.Errorf("revoke old refresh token: %w", err)
		}
		return nil
	}
	if err := s.store.RevokeRefreshToken(ctx, tokenHash); err != nil {
		return fmt.Errorf("revoke old refresh token: %w", err)
	}
	return nil
}

// soleCompany returns the user's only company, for a pre-#80 refresh token
// that names none. More than one membership (or a store that cannot list
// them) is refused: the issuing company is unknowable, and picking one is the
// tenant escalation this guards against.
func (s *Service) soleCompany(ctx context.Context, userID uuid.UUID) (uuid.UUID, error) {
	lister, ok := s.store.(MembershipLister)
	if !ok {
		return uuid.Nil, fmt.Errorf("invalid refresh token: legacy token names no company; sign in again")
	}
	ids, err := lister.ListUserCompanyIDs(ctx, userID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("list memberships: %w", err)
	}
	if len(ids) != 1 {
		return uuid.Nil, fmt.Errorf("invalid refresh token: legacy token names no company; sign in again")
	}
	return ids[0], nil
}

// UpdateProfile updates the user's display name and avatar URL.
func (s *Service) UpdateProfile(ctx context.Context, userID uuid.UUID, displayName, avatarURL string) (User, error) {
	if strings.TrimSpace(displayName) == "" {
		return User{}, fmt.Errorf("display name is required")
	}
	return s.store.UpdateUser(ctx, userID, strings.TrimSpace(displayName), strings.TrimSpace(avatarURL))
}

// Logout revokes the provided refresh token.
func (s *Service) Logout(ctx context.Context, refreshTokenStr string) error {
	tokenHash := HashToken(refreshTokenStr)
	return s.store.RevokeRefreshToken(ctx, tokenHash)
}

// RememberRefreshToken records a freshly-minted refresh token in the
// auth store so it can be rotated later via RefreshToken (or, for a
// client-bound token, RefreshTokenForClient).
//
// Used by callers that mint a refresh token outside the SignUp/Login
// pipeline (a company switch, an onboarding redeem) and still need rotation
// to work. The platform's own SignUp + Login paths embed this call inside
// their transactions.
//
// Mint the token for the session it belongs to (issue #80): a refresh
// re-mints exactly what the token names. A company-scoped session must use
// JWTManager.CreateCompanyRefreshToken(userID, companyID); a token from
// CreateRefreshToken names no company, so RefreshToken re-mints a
// company-less access token from it (RequireCompany then fails). Tokens
// handed to an OAuth client use CreateClientRefreshToken and are redeemed
// only through RefreshTokenForClient.
func (s *Service) RememberRefreshToken(ctx context.Context, userID uuid.UUID, refreshTokenStr string, expiresAt time.Time) error {
	tokenHash := HashToken(refreshTokenStr)
	return s.store.CreateRefreshToken(ctx, userID, tokenHash, expiresAt)
}

// GetUserByID resolves a user by ID. The auth.Service does not own a
// public user lookup; this thin pass-through exposes the underlying
// store for issuer code that needs claim values without re-importing
// the store interface.
func (s *Service) GetUserByID(ctx context.Context, id uuid.UUID) (User, error) {
	return s.store.GetUserByID(ctx, id)
}

// GetUserByEmail resolves a user by email. Same shape as
// GetUserByID — exposed so federation flows (aoid Bridge) can JIT-
// provision without re-importing the store interface.
func (s *Service) GetUserByEmail(ctx context.Context, email string) (User, error) {
	return s.store.GetUserByEmail(ctx, strings.ToLower(strings.TrimSpace(email)))
}

// GetUserRole returns userID's role in companyID, or an error when the user
// is not a member of that company. Exposed so federation flows can scope an
// email match to the asserting tenant (#74).
func (s *Service) GetUserRole(ctx context.Context, companyID, userID uuid.UUID) (Role, error) {
	return s.store.GetUserRole(ctx, companyID, userID)
}

// CreateUserWithMembership creates a user and their membership in companyID
// in ONE transaction, so a failed membership never leaves a user row behind.
// Under the SSO/federation refuse-non-members rule (#74) such a user could
// never sign in again. Used by federation JIT.
func (s *Service) CreateUserWithMembership(ctx context.Context, email, passwordHash, displayName string, companyID, roleID uuid.UUID) (User, error) {
	return createUserWithMembership(ctx, s.store, email, passwordHash, displayName, companyID, roleID)
}

// createUserWithMembership runs CreateUser + CreateCompanyMembership in one
// transaction on store.
func createUserWithMembership(ctx context.Context, store TxAuthStore, email, passwordHash, displayName string, companyID, roleID uuid.UUID) (User, error) {
	tx, err := store.BeginTx(ctx)
	if err != nil {
		return User{}, fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	user, err := tx.CreateUser(ctx, strings.ToLower(strings.TrimSpace(email)), passwordHash, strings.TrimSpace(displayName))
	if err != nil {
		return User{}, fmt.Errorf("create user: %w", err)
	}
	if err := tx.CreateCompanyMembership(ctx, companyID, user.ID, roleID); err != nil {
		return User{}, fmt.Errorf("create company membership: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return User{}, fmt.Errorf("commit transaction: %w", err)
	}
	return user, nil
}

// CreateUser inserts a new user. Federation callers supply an unusable
// password hash (e.g. "fed:<random>") to disable password login for
// SSO-only accounts. Companies and memberships are NOT created here —
// that remains the caller's responsibility.
func (s *Service) CreateUser(ctx context.Context, email, passwordHash, displayName string) (User, error) {
	return s.store.CreateUser(ctx, strings.ToLower(strings.TrimSpace(email)), passwordHash, strings.TrimSpace(displayName))
}

// HashToken computes SHA-256 hash of a token for database storage.
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func validateEmail(email string) error {
	_, err := mail.ParseAddress(email)
	return err
}

func generateSlug(name string) string {
	slug := strings.ToLower(strings.TrimSpace(name))
	slug = strings.ReplaceAll(slug, " ", "-")
	var result strings.Builder
	for _, c := range slug {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			result.WriteRune(c)
		}
	}
	s := result.String()
	if s == "" {
		s = "default-company"
	}
	return s + "-" + time.Now().Format("150405")
}
