package auth

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type CredentialRepository interface {
	Create(ctx context.Context, c *Credential) error
	FindByEmail(ctx context.Context, email string) (*Credential, error)
	FindByID(ctx context.Context, id uuid.UUID) (*Credential, error)
	SetVerified(ctx context.Context, id uuid.UUID) error
	InsertRole(ctx context.Context, userID uuid.UUID, role string) error
	GetRoles(ctx context.Context, userID uuid.UUID) ([]string, error)
}

type RefreshTokenRepository interface {
	Save(ctx context.Context, userID uuid.UUID, tokenHash string, ttl time.Duration) error
	Find(ctx context.Context, userID uuid.UUID) (string, error)
	Delete(ctx context.Context, userID uuid.UUID) error
	DeleteAll(ctx context.Context, userID uuid.UUID) error
	FindUserIDByHash(ctx context.Context, tokenHash string) (uuid.UUID, error)
}

type VerifyTokenRepository interface {
	Save(ctx context.Context, token string, userID uuid.UUID, ttl time.Duration) error
	Get(ctx context.Context, token string) (uuid.UUID, error)
	Delete(ctx context.Context, token string) error
}
