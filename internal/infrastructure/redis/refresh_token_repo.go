package redis

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	goredis "github.com/redis/go-redis/v9"

	domain "github.com/companyofcreators/auth-service/internal/domain/auth"
)

const refreshKeyPrefix = "refresh:"
const refreshLookupPrefix = "refresh_lookup:"
const verifyKeyPrefix = "verify:"

type RefreshTokenRepo struct {
	client *goredis.Client
}

func NewRefreshTokenRepo(client *goredis.Client) *RefreshTokenRepo {
	return &RefreshTokenRepo{client: client}
}

func (r *RefreshTokenRepo) Save(ctx context.Context, userID uuid.UUID, tokenHash string, ttl time.Duration) error {
	key := fmt.Sprintf("%s%s", refreshKeyPrefix, userID.String())
	err := r.client.Set(ctx, key, tokenHash, ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to save refresh token: %w", err)
	}

	lookupKey := fmt.Sprintf("%s%s", refreshLookupPrefix, tokenHash)
	err = r.client.Set(ctx, lookupKey, userID.String(), ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to save refresh token lookup: %w", err)
	}

	return nil
}

func (r *RefreshTokenRepo) Find(ctx context.Context, userID uuid.UUID) (string, error) {
	key := fmt.Sprintf("%s%s", refreshKeyPrefix, userID.String())
	tokenHash, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, goredis.Nil) {
			return "", domain.ErrInvalidRefreshToken
		}
		return "", fmt.Errorf("failed to find refresh token: %w", err)
	}
	return tokenHash, nil
}

func (r *RefreshTokenRepo) Delete(ctx context.Context, userID uuid.UUID) error {
	key := fmt.Sprintf("%s%s", refreshKeyPrefix, userID.String())

	tokenHash, err := r.client.Get(ctx, key).Result()
	if err == nil && tokenHash != "" {
		lookupKey := fmt.Sprintf("%s%s", refreshLookupPrefix, tokenHash)
		if derr := r.client.Del(ctx, lookupKey).Err(); derr != nil {
			slog.Warn("failed to delete refresh token lookup", "error", derr)
		}
	}

	err = r.client.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("failed to delete refresh token: %w", err)
	}
	return nil
}

func (r *RefreshTokenRepo) DeleteAll(ctx context.Context, userID uuid.UUID) error {
	key := fmt.Sprintf("%s%s", refreshKeyPrefix, userID.String())

	tokenHash, err := r.client.Get(ctx, key).Result()
	if err == nil && tokenHash != "" {
		lookupKey := fmt.Sprintf("%s%s", refreshLookupPrefix, tokenHash)
		if derr := r.client.Del(ctx, lookupKey).Err(); derr != nil {
			slog.Warn("failed to delete refresh token lookup", "error", derr)
		}
	}

	err = r.client.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("failed to delete all refresh tokens: %w", err)
	}
	return nil
}

func (r *RefreshTokenRepo) FindUserIDByHash(ctx context.Context, tokenHash string) (uuid.UUID, error) {
	lookupKey := fmt.Sprintf("%s%s", refreshLookupPrefix, tokenHash)
	val, err := r.client.Get(ctx, lookupKey).Result()
	if err != nil {
		if errors.Is(err, goredis.Nil) {
			return uuid.Nil, domain.ErrInvalidRefreshToken
		}
		return uuid.Nil, fmt.Errorf("failed to find user id by hash: %w", err)
	}

	userID, err := uuid.Parse(val)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to parse user id: %w", err)
	}

	return userID, nil
}

type VerifyTokenRepo struct {
	client *goredis.Client
}

func NewVerifyTokenRepo(client *goredis.Client) *VerifyTokenRepo {
	return &VerifyTokenRepo{client: client}
}

func (r *VerifyTokenRepo) Save(ctx context.Context, token string, userID uuid.UUID, ttl time.Duration) error {
	key := fmt.Sprintf("%s%s", verifyKeyPrefix, token)
	err := r.client.Set(ctx, key, userID.String(), ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to save verify token: %w", err)
	}
	return nil
}

func (r *VerifyTokenRepo) Get(ctx context.Context, token string) (uuid.UUID, error) {
	key := fmt.Sprintf("%s%s", verifyKeyPrefix, token)
	val, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, goredis.Nil) {
			return uuid.Nil, domain.ErrInvalidVerifyToken
		}
		return uuid.Nil, fmt.Errorf("failed to get verify token: %w", err)
	}

	userID, err := uuid.Parse(val)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to parse user id from verify token: %w", err)
	}

	return userID, nil
}

func (r *VerifyTokenRepo) Delete(ctx context.Context, token string) error {
	key := fmt.Sprintf("%s%s", verifyKeyPrefix, token)
	err := r.client.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("failed to delete verify token: %w", err)
	}
	return nil
}
