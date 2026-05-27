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
	query := `SELECT id, email, password_hash, verified, created_at, is_banned, COALESCE(banned_reason, '') AS banned_reason FROM credentials WHERE email = $1`

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
	query := `SELECT id, email, password_hash, verified, created_at, is_banned, COALESCE(banned_reason, '') AS banned_reason FROM credentials WHERE id = $1`

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

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return domain.ErrUserNotFound
	}

	return nil
}

func (r *CredentialRepo) CreateProfile(ctx context.Context, p *domain.UserProfile) error {
	query := `INSERT INTO user_profiles (user_id, name, first_name, last_name, middle_name, birthdate, phone)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err := r.db.ExecContext(ctx, query,
		p.UserID, p.Name, p.FirstName, p.LastName, p.MiddleName, p.Birthdate, p.Phone,
	)
	if err != nil {
		return fmt.Errorf("failed to insert user profile: %w", err)
	}

	return nil
}

func (r *CredentialRepo) FindProfileByUserID(ctx context.Context, userID uuid.UUID) (*domain.UserProfile, error) {
	query := `SELECT user_id, name, first_name, last_name, middle_name, birthdate, phone, created_at, updated_at
		FROM user_profiles WHERE user_id = $1`

	var p domain.UserProfile
	err := r.db.GetContext(ctx, &p, query, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to find profile by user id: %w", err)
	}

	return &p, nil
}

func (r *CredentialRepo) InsertRole(ctx context.Context, userID uuid.UUID, role string) error {
	query := `INSERT INTO user_roles (user_id, role) VALUES ($1, $2) ON CONFLICT DO NOTHING`

	_, err := r.db.ExecContext(ctx, query, userID, role)
	if err != nil {
		return fmt.Errorf("failed to insert role: %w", err)
	}

	return nil
}

// RemoveRole deletes a role for the given user. It is idempotent — no error
// if the role doesn't exist.
func (r *CredentialRepo) RemoveRole(ctx context.Context, userID uuid.UUID, role string) error {
	query := `DELETE FROM user_roles WHERE user_id = $1 AND role = $2`

	_, err := r.db.ExecContext(ctx, query, userID, role)
	if err != nil {
		return fmt.Errorf("failed to remove role: %w", err)
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

// CreateTx inserts a credential within the given transaction.
func (r *CredentialRepo) CreateTx(ctx context.Context, tx *sql.Tx, c *domain.Credential) error {
	query := `INSERT INTO credentials (id, email, password_hash, verified, created_at)
		VALUES ($1, $2, $3, $4, $5)`

	_, err := tx.ExecContext(ctx, query,
		c.ID, c.Email, c.PasswordHash, c.Verified, c.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to insert credential: %w", err)
	}

	return nil
}

// InsertRoleTx inserts a role within the given transaction.
func (r *CredentialRepo) InsertRoleTx(ctx context.Context, tx *sql.Tx, userID uuid.UUID, role string) error {
	query := `INSERT INTO user_roles (user_id, role) VALUES ($1, $2) ON CONFLICT DO NOTHING`

	_, err := tx.ExecContext(ctx, query, userID, role)
	if err != nil {
		return fmt.Errorf("failed to insert role: %w", err)
	}

	return nil
}

// BanUser sets is_banned to true and stores the ban reason for the given user.
func (r *CredentialRepo) BanUser(ctx context.Context, userID uuid.UUID, reason string) error {
	query := `UPDATE credentials SET is_banned = TRUE, banned_reason = $2 WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, userID, reason)
	if err != nil {
		return fmt.Errorf("failed to ban user: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return domain.ErrUserNotFound
	}

	return nil
}

// UnbanUser clears the is_banned flag and removes the ban reason for the given user.
func (r *CredentialRepo) UnbanUser(ctx context.Context, userID uuid.UUID) error {
	query := `UPDATE credentials SET is_banned = FALSE, banned_reason = '' WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to unban user: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return domain.ErrUserNotFound
	}

	return nil
}

// CreateProfileTx inserts a user profile within the given transaction.
func (r *CredentialRepo) CreateProfileTx(ctx context.Context, tx *sql.Tx, p *domain.UserProfile) error {
	query := `INSERT INTO user_profiles (user_id, name, first_name, last_name, middle_name, birthdate, phone)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err := tx.ExecContext(ctx, query,
		p.UserID, p.Name, p.FirstName, p.LastName, p.MiddleName, p.Birthdate, p.Phone,
	)
	if err != nil {
		return fmt.Errorf("failed to insert user profile: %w", err)
	}

	return nil
}

// DeleteUser permanently removes a user and all related data in a transaction.
func (r *CredentialRepo) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, "DELETE FROM user_profiles WHERE user_id = $1", userID); err != nil {
		return fmt.Errorf("delete profiles: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM user_roles WHERE user_id = $1", userID); err != nil {
		return fmt.Errorf("delete roles: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM credentials WHERE id = $1", userID); err != nil {
		return fmt.Errorf("delete credentials: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit delete: %w", err)
	}

	return nil
}
