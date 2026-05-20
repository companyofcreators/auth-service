package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	domain "github.com/companyofcreators/auth-service/internal/domain/auth"
)

type CredentialRepo struct {
	db *sqlx.DB
}

func NewCredentialRepo(db *sqlx.DB) *CredentialRepo {
	return &CredentialRepo{db: db}
}

func (r *CredentialRepo) Create(ctx context.Context, c *domain.Credential) error {
	query := `INSERT INTO credentials (id, email, password_hash, verified, created_at)
		VALUES ($1, $2, $3, $4, $5)`

	_, err := r.db.ExecContext(ctx, query,
		c.ID, c.Email, c.PasswordHash, c.Verified, c.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to insert credential: %w", err)
	}

	return nil
}

func (r *CredentialRepo) FindByEmail(ctx context.Context, email string) (*domain.Credential, error) {
	query := `SELECT id, email, password_hash, verified, created_at FROM credentials WHERE email = $1`

	var c domain.Credential
	err := r.db.GetContext(ctx, &c, query, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to find credential by email: %w", err)
	}

	return &c, nil
}

func (r *CredentialRepo) FindByID(ctx context.Context, id uuid.UUID) (*domain.Credential, error) {
	query := `SELECT id, email, password_hash, verified, created_at FROM credentials WHERE id = $1`

	var c domain.Credential
	err := r.db.GetContext(ctx, &c, query, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to find credential by id: %w", err)
	}

	return &c, nil
}

func (r *CredentialRepo) SetVerified(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE credentials SET verified = TRUE WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to set verified: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return domain.ErrUserNotFound
	}

	return nil
}

func (r *CredentialRepo) InsertRole(ctx context.Context, userID uuid.UUID, role string) error {
	query := `INSERT INTO user_roles (user_id, role) VALUES ($1, $2) ON CONFLICT DO NOTHING`

	_, err := r.db.ExecContext(ctx, query, userID, role)
	if err != nil {
		return fmt.Errorf("failed to insert role: %w", err)
	}

	return nil
}

func (r *CredentialRepo) GetRoles(ctx context.Context, userID uuid.UUID) ([]string, error) {
	query := `SELECT role FROM user_roles WHERE user_id = $1 ORDER BY role`

	var roles []string
	err := r.db.SelectContext(ctx, &roles, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get roles: %w", err)
	}

	if roles == nil {
		roles = []string{}
	}

	return roles, nil
}
