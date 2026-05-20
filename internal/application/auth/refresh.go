package auth

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	domain "github.com/companyofcreators/auth-service/internal/domain/auth"
)

type RefreshInput struct {
	RefreshToken string
}

type RefreshOutput struct {
	AccessToken  string
	RefreshToken string
	UserID       string
	Email        string
	Roles        []string
}

type RefreshUseCase struct {
	credentialRepo domain.CredentialRepository
	refreshRepo    domain.RefreshTokenRepository
	tokenService   domain.TokenService
	logger         *slog.Logger
	refreshTTL     time.Duration
}

func NewRefreshUseCase(
	credentialRepo domain.CredentialRepository,
	refreshRepo domain.RefreshTokenRepository,
	tokenService domain.TokenService,
	logger *slog.Logger,
	refreshTTL time.Duration,
) *RefreshUseCase {
	return &RefreshUseCase{
		credentialRepo: credentialRepo,
		refreshRepo:    refreshRepo,
		tokenService:   tokenService,
		logger:         logger,
		refreshTTL:     refreshTTL,
	}
}

func (uc *RefreshUseCase) Execute(ctx context.Context, input RefreshInput) (*RefreshOutput, error) {
	refreshHash := sha256Hash(input.RefreshToken)

	userID, err := uc.refreshRepo.FindUserIDByHash(ctx, refreshHash)
	if err != nil {
		return nil, domain.ErrInvalidRefreshToken
	}

	storedHash, err := uc.refreshRepo.Find(ctx, userID)
	if err != nil {
		return nil, domain.ErrInvalidRefreshToken
	}

	if storedHash != refreshHash {
		uc.logger.Warn("refresh token mismatch - possible token theft", "user_id", userID.String())
		_ = uc.refreshRepo.DeleteAll(ctx, userID)
		return nil, domain.ErrInvalidRefreshToken
	}

	if err := uc.refreshRepo.Delete(ctx, userID); err != nil {
		uc.logger.Warn("failed to delete old refresh token", "error", err)
	}

	cred, err := uc.credentialRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to find credential: %w", err)
	}

	roles, err := uc.credentialRepo.GetRoles(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get roles: %w", err)
	}

	accessToken, err := uc.tokenService.GenerateAccessToken(userID.String(), cred.Email, roles)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	newRefreshToken, err := uc.tokenService.GenerateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	newRefreshHash := sha256Hash(newRefreshToken)
	if err := uc.refreshRepo.Save(ctx, userID, newRefreshHash, uc.refreshTTL); err != nil {
		return nil, fmt.Errorf("failed to save new refresh token: %w", err)
	}

	uc.logger.Info("tokens refreshed", "user_id", userID.String())

	return &RefreshOutput{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		UserID:       userID.String(),
		Email:        cred.Email,
		Roles:        roles,
	}, nil
}

