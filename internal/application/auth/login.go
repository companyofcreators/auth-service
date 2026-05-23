package auth

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	domain "github.com/companyofcreators/auth-service/internal/domain/auth"
)

type LoginInput struct {
	Email    string
	Password string
}

type LoginOutput struct {
	AccessToken  string
	RefreshToken string
	UserID       string
	Email        string
	Roles        []string
}

type LoginUseCase struct {
	credentialRepo      domain.CredentialRepository
	refreshRepo         domain.RefreshTokenRepository
	tokenService        domain.TokenService
	hasher              Hasher
	kafka               EventPublisher
	logger              *slog.Logger
	refreshTTL          time.Duration
	requireEmailVerified bool
}

func NewLoginUseCase(
	credentialRepo domain.CredentialRepository,
	refreshRepo domain.RefreshTokenRepository,
	tokenService domain.TokenService,
	hasher Hasher,
	kafka EventPublisher,
	logger *slog.Logger,
	refreshTTL time.Duration,
	requireEmailVerified bool,
) *LoginUseCase {
	return &LoginUseCase{
		credentialRepo:       credentialRepo,
		refreshRepo:          refreshRepo,
		tokenService:         tokenService,
		hasher:               hasher,
		kafka:                kafka,
		logger:               logger,
		refreshTTL:           refreshTTL,
		requireEmailVerified: requireEmailVerified,
	}
}

func (uc *LoginUseCase) Execute(ctx context.Context, input LoginInput) (*LoginOutput, error) {
	cred, err := uc.credentialRepo.FindByEmail(ctx, input.Email)
	if err != nil {
		if err == domain.ErrUserNotFound {
			return nil, domain.ErrInvalidCredentials
		}
		return nil, fmt.Errorf("failed to find credential: %w", err)
	}

	if err := uc.hasher.Compare(cred.PasswordHash, input.Password); err != nil {
		return nil, domain.ErrInvalidCredentials
	}

	if uc.requireEmailVerified && !cred.Verified {
		return nil, domain.ErrEmailNotVerified
	}

	if cred.IsBanned {
		msg := "ваш аккаунт заблокирован"
		if cred.BannedReason != "" {
			msg += ": " + cred.BannedReason
		}
		return nil, fmt.Errorf("%s: %w", msg, domain.ErrUserBanned)
	}

	roles, err := uc.credentialRepo.GetRoles(ctx, cred.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get roles: %w", err)
	}

	accessToken, err := uc.tokenService.GenerateAccessToken(cred.ID.String(), cred.Email, roles)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := uc.tokenService.GenerateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	refreshHash := sha256Hash(refreshToken)
	if err := uc.refreshRepo.Save(ctx, cred.ID, refreshHash, uc.refreshTTL); err != nil {
		return nil, fmt.Errorf("failed to save refresh token: %w", err)
	}

	if err := uc.kafka.PublishAuthLogin(cred.ID.String(), cred.Email, roles); err != nil {
		uc.logger.Warn("failed to publish auth.login event", "error", err)
	}

	uc.logger.Info("user logged in", "user_id", cred.ID.String(), "email", cred.Email)

	return &LoginOutput{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		UserID:       cred.ID.String(),
		Email:        cred.Email,
		Roles:        roles,
	}, nil
}

