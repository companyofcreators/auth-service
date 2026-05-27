package auth

import (
	"context"
	"fmt"

	domain "github.com/companyofcreators/auth-service/internal/domain/auth"
)

type ValidateInput struct {
	AccessToken string
}

type ValidateOutput struct {
	UserID string
	Email  string
	Roles  []string
}

type ValidateUseCase struct {
	tokenService domain.TokenService
}

func NewValidateUseCase(tokenService domain.TokenService) *ValidateUseCase {
	return &ValidateUseCase{tokenService: tokenService}
}

func (uc *ValidateUseCase) Execute(ctx context.Context, input ValidateInput) (*ValidateOutput, error) {
	userID, email, roles, err := uc.tokenService.ValidateAccessToken(input.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("invalid access token: %w", err)
	}

	return &ValidateOutput{
		UserID: userID,
		Email:  email,
		Roles:  roles,
	}, nil
}
