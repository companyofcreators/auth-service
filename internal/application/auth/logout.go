package auth

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"

	domain "github.com/companyofcreators/auth-service/internal/domain/auth"
)

type LogoutInput struct {
	UserID       string
	RefreshToken string
}

type LogoutUseCase struct {
	refreshRepo domain.RefreshTokenRepository
	kafka       EventPublisher
	logger      *slog.Logger
}

func NewLogoutUseCase(
	refreshRepo domain.RefreshTokenRepository,
	kafka EventPublisher,
	logger *slog.Logger,
) *LogoutUseCase {
	return &LogoutUseCase{
		refreshRepo: refreshRepo,
		kafka:       kafka,
		logger:      logger,
	}
}

func (uc *LogoutUseCase) Execute(ctx context.Context, input LogoutInput) error {
	userID, err := uuid.Parse(input.UserID)
	if err != nil {
		return fmt.Errorf("invalid user id: %w", err)
	}

	if err := uc.refreshRepo.Delete(ctx, userID); err != nil {
		uc.logger.Warn("failed to delete refresh token during logout", "error", err)
	}

	if err := uc.kafka.PublishAuthLogout(input.UserID); err != nil {
		uc.logger.Warn("failed to publish auth.logout event", "error", err)
	}

	uc.logger.Info("user logged out", "user_id", input.UserID)

	return nil
}
