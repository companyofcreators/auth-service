package auth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	domain "github.com/companyofcreators/auth-service/internal/domain/auth"
)

type RegisterInput struct {
	Email      string
	Password   string
	Name       string
	FirstName  string
	LastName   string
	MiddleName string
	Birthdate  string
	Phone      string
}

type RegisterOutput struct {
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	UserID       string `json:"user_id"`
	Email        string `json:"email"`
	Roles        []string `json:"roles"`
	Message      string `json:"message,omitempty"`
}

type RegisterUseCase struct {
	db                   *sql.DB
	credentialRepo       domain.CredentialRepository
	refreshRepo          domain.RefreshTokenRepository
	verifyRepo           domain.VerifyTokenRepository
	tokenService         domain.TokenService
	hasher               Hasher
	kafka                EventPublisher
	logger               *slog.Logger
	refreshTTL           time.Duration
	verifyTTL            time.Duration
	bcryptCost           int
	requireEmailVerified bool
}

type Hasher interface {
	Hash(password string) (string, error)
	Compare(hash, password string) error
}

type EventPublisher interface {
	PublishUserCreated(userID, email, firstName, lastName, phone string, roles []string) error
	PublishAuthLogin(userID, email string, roles []string) error
	PublishAuthLogout(userID string) error
	PublishVerificationCreated(userID, email, name, verifyToken string) error
}

func NewRegisterUseCase(
	db *sql.DB,
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
	requireEmailVerified bool,
) *RegisterUseCase {
	return &RegisterUseCase{
		db:                   db,
		credentialRepo:       credentialRepo,
		refreshRepo:          refreshRepo,
		verifyRepo:           verifyRepo,
		tokenService:         tokenService,
		hasher:               hasher,
		kafka:                kafka,
		logger:               logger,
		refreshTTL:           refreshTTL,
		verifyTTL:            verifyTTL,
		bcryptCost:           bcryptCost,
		requireEmailVerified: requireEmailVerified,
	}
}

func (uc *RegisterUseCase) Execute(ctx context.Context, input RegisterInput) (*RegisterOutput, error) {
	// Auto-generate Name from FirstName + LastName if empty (backward-compatible)
	if input.Name == "" {
		input.Name = input.FirstName + " " + input.LastName
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

	tx, err := uc.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("начать транзакцию: %w", err)
	}
	defer tx.Rollback()

	if err := uc.credentialRepo.CreateTx(ctx, tx, cred); err != nil {
		return nil, fmt.Errorf("создать учётные данные: %w", err)
	}

	if err := uc.credentialRepo.InsertRoleTx(ctx, tx, userID, "user"); err != nil {
		return nil, fmt.Errorf("добавить роль: %w", err)
	}

	// Store user profile
	profile := &domain.UserProfile{
		UserID:     userID,
		Name:       input.Name,
		FirstName:  input.FirstName,
		LastName:   input.LastName,
		MiddleName: input.MiddleName,
		Phone:      input.Phone,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if input.Birthdate != "" {
		profile.Birthdate = &input.Birthdate
	}

	if err := uc.credentialRepo.CreateProfileTx(ctx, tx, profile); err != nil {
		return nil, fmt.Errorf("создать профиль: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("зафиксировать транзакцию: %w", err)
	}

	roles := []string{"user"}

	// Generate verification token (always needed)
	verifyToken, err := uc.tokenService.GenerateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate verify token: %w", err)
	}

	if err := uc.verifyRepo.Save(ctx, verifyToken, userID, uc.verifyTTL); err != nil {
		return nil, fmt.Errorf("failed to save verify token: %w", err)
	}

	if err := uc.kafka.PublishVerificationCreated(userID.String(), input.Email, input.Name, verifyToken); err != nil {
		uc.logger.Warn("failed to publish verification.created event", "error", err)
	}

	if err := uc.kafka.PublishUserCreated(userID.String(), input.Email, input.FirstName, input.LastName, input.Phone, roles); err != nil {
		uc.logger.Warn("failed to publish user.created event", "error", err)
	}

	uc.logger.Info("user registered", "user_id", userID.String(), "email", input.Email, "roles", roles)

	if uc.requireEmailVerified {
		return &RegisterOutput{
			UserID:  userID.String(),
			Email:   input.Email,
			Roles:   roles,
			Message: "На указанный email отправлено письмо для подтверждения",
		}, nil
	}

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
