package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	domain "github.com/companyofcreators/auth-service/internal/domain/auth"
)

type RegisterInput struct {
	Email    string
	Password string
	Name     string
	Phone    string
	Role     string
}

type RegisterOutput struct {
	AccessToken  string
	RefreshToken string
	UserID       string
	Email        string
	Roles        []string
}

type RegisterUseCase struct {
	credentialRepo domain.CredentialRepository
	refreshRepo    domain.RefreshTokenRepository
	verifyRepo     domain.VerifyTokenRepository
	tokenService   domain.TokenService
	hasher         Hasher
	kafka          EventPublisher
	logger         *slog.Logger
	refreshTTL     time.Duration
	verifyTTL      time.Duration
	bcryptCost     int
}

type Hasher interface {
	Hash(password string) (string, error)
	Compare(hash, password string) error
}

type EventPublisher interface {
	PublishUserCreated(userID, email string, roles []string) error
	PublishAuthLogin(userID, email string, roles []string) error
	PublishAuthLogout(userID string) error
	PublishVerificationCreated(userID, email string) error
}

func NewRegisterUseCase(
	credentialRepo domain.CredentialRepository,
	refreshRepo domain.RefreshTokenRepository,
	verifyRepo domain.VerifyTokenRepository,
	tokenService domain.TokenService,
	hasher Hasher,
	kafka EventPublisher,
	logger *slog.Logger,
	refreshTTL time.Duration,
	verifyTTL time.Duration,
	bcryptCost int,
) *RegisterUseCase {
	return &RegisterUseCase{
		credentialRepo: credentialRepo,
		refreshRepo:    refreshRepo,
		verifyRepo:     verifyRepo,
		tokenService:   tokenService,
		hasher:         hasher,
		kafka:          kafka,
		logger:         logger,
		refreshTTL:     refreshTTL,
		verifyTTL:      verifyTTL,
		bcryptCost:     bcryptCost,
	}
}

func (uc *RegisterUseCase) Execute(ctx context.Context, input RegisterInput) (*RegisterOutput, error) {
	if input.Role == "" {
		input.Role = "user"
	}

	validRoles := map[string]bool{"user": true, "master": true, "moderator": true, "admin": true}
	if !validRoles[input.Role] {
		return nil, fmt.Errorf("invalid role: %s", input.Role)
	}

	_, err := uc.credentialRepo.FindByEmail(ctx, input.Email)
	if err == nil {
		return nil, domain.ErrEmailTaken
	}
	if err != domain.ErrUserNotFound {
		return nil, fmt.Errorf("failed to check email: %w", err)
	}

	passwordHash, err := uc.hasher.Hash(input.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	userID := uuid.New()
	now := time.Now()

	cred := &domain.Credential{
		ID:           userID,
		Email:        input.Email,
		PasswordHash: passwordHash,
		Verified:     false,
		CreatedAt:    now,
	}

	if err := uc.credentialRepo.Create(ctx, cred); err != nil {
		return nil, fmt.Errorf("failed to create credential: %w", err)
	}

	if err := uc.credentialRepo.InsertRole(ctx, userID, input.Role); err != nil {
		return nil, fmt.Errorf("failed to insert role: %w", err)
	}

	roles := []string{input.Role}

	accessToken, err := uc.tokenService.GenerateAccessToken(userID.String(), input.Email, roles)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := uc.tokenService.GenerateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	refreshHash := sha256Hash(refreshToken)
	if err := uc.refreshRepo.Save(ctx, userID, refreshHash, uc.refreshTTL); err != nil {
		return nil, fmt.Errorf("failed to save refresh token: %w", err)
	}

	if err := uc.kafka.PublishUserCreated(userID.String(), input.Email, roles); err != nil {
		uc.logger.Warn("failed to publish user.created event", "error", err)
	}

	verifyToken, err := uc.tokenService.GenerateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate verify token: %w", err)
	}

	if err := uc.verifyRepo.Save(ctx, verifyToken, userID, uc.verifyTTL); err != nil {
		return nil, fmt.Errorf("failed to save verify token: %w", err)
	}

	if err := uc.kafka.PublishVerificationCreated(userID.String(), input.Email); err != nil {
		uc.logger.Warn("failed to publish verification.created event", "error", err)
	}

	uc.logger.Info("user registered", "user_id", userID.String(), "email", input.Email, "roles", roles)

	return &RegisterOutput{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		UserID:       userID.String(),
		Email:        input.Email,
		Roles:        roles,
	}, nil
}

func sha256Hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
