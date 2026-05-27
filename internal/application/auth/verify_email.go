package auth

import (
	"context"
	"fmt"
	"log/slog"

	domain "github.com/companyofcreators/auth-service/internal/domain/auth"
)

type VerifyEmailInput struct {
	Token string
}

type VerifyEmailUseCase struct {
	credentialRepo domain.CredentialRepository
	verifyRepo     domain.VerifyTokenRepository
	logger         *slog.Logger
}

func NewVerifyEmailUseCase(
	credentialRepo domain.CredentialRepository,
	verifyRepo domain.VerifyTokenRepository,
	logger *slog.Logger,
) *VerifyEmailUseCase {
	return &VerifyEmailUseCase{
		credentialRepo: credentialRepo,
		verifyRepo:     verifyRepo,
		logger:         logger,
	}
}

func (uc *VerifyEmailUseCase) Execute(ctx context.Context, input VerifyEmailInput) error {
	userID, err := uc.verifyRepo.Get(ctx, input.Token)
	if err != nil {
		return domain.ErrInvalidVerifyToken
	}

	if err := uc.credentialRepo.SetVerified(ctx, userID); err != nil {
		return fmt.Errorf("failed to set verified: %w", err)
	}

	if err := uc.verifyRepo.Delete(ctx, input.Token); err != nil {
		uc.logger.Warn("failed to delete verify token after verification", "error", err)
	}

	uc.logger.Info("email verified", "user_id", userID.String())

	return nil
}
