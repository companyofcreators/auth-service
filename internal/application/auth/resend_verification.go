package auth

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	domain "github.com/companyofcreators/auth-service/internal/domain/auth"
)

type ResendVerificationInput struct {
	Email string
}

type ResendVerificationUseCase struct {
	credentialRepo domain.CredentialRepository
	verifyRepo     domain.VerifyTokenRepository
	tokenService   domain.TokenService
	kafka          EventPublisher
	logger         *slog.Logger
	verifyTTL      time.Duration
}

func NewResendVerificationUseCase(
	credentialRepo domain.CredentialRepository,
	verifyRepo domain.VerifyTokenRepository,
	tokenService domain.TokenService,
	kafka EventPublisher,
	logger *slog.Logger,
	verifyTTL time.Duration,
) *ResendVerificationUseCase {
	return &ResendVerificationUseCase{
		credentialRepo: credentialRepo,
		verifyRepo:     verifyRepo,
		tokenService:   tokenService,
		kafka:          kafka,
		logger:         logger,
		verifyTTL:      verifyTTL,
	}
}

func (uc *ResendVerificationUseCase) Execute(ctx context.Context, input ResendVerificationInput) error {
	cred, err := uc.credentialRepo.FindByEmail(ctx, input.Email)
	if err != nil {
		if err == domain.ErrUserNotFound {
			return domain.ErrUserNotFound
		}
		return fmt.Errorf("find credential: %w", err)
	}

	if cred.Verified {
		uc.logger.Info("resend verification skipped, already verified", "email", input.Email)
		return nil
	}

	profile, err := uc.credentialRepo.FindProfileByUserID(ctx, cred.ID)
	name := input.Email
	if err == nil && profile != nil {
		name = profile.Name
	}

	verifyToken, err := uc.tokenService.GenerateRefreshToken()
	if err != nil {
		return fmt.Errorf("generate verify token: %w", err)
	}

	if err := uc.verifyRepo.Save(ctx, verifyToken, cred.ID, uc.verifyTTL); err != nil {
		return fmt.Errorf("save verify token: %w", err)
	}

	if err := uc.kafka.PublishVerificationCreated(cred.ID.String(), cred.Email, name, verifyToken); err != nil {
		uc.logger.Warn("failed to publish verification.created event", "error", err)
	}

	uc.logger.Info("verification email resent", "user_id", cred.ID.String(), "email", cred.Email)
	return nil
}
