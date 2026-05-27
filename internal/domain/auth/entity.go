package auth

import (
	"time"

	"github.com/google/uuid"
)

type Credential struct {
	ID           uuid.UUID `db:"id"`
	Email        string    `db:"email"`
	PasswordHash string    `db:"password_hash"`
	CreatedAt    time.Time `db:"created_at"`
	Verified     bool      `db:"verified"`
	IsBanned     bool      `db:"is_banned"`
	BannedReason string    `db:"banned_reason"`
}

type RefreshToken struct {
	UserID    uuid.UUID `db:"user_id"`
	TokenHash string    `db:"token_hash"`
	ExpiresAt time.Time `db:"expires_at"`
}

type UserRole struct {
	UserID    uuid.UUID `db:"user_id"`
	Role      string    `db:"role"`
	CreatedAt time.Time `db:"created_at"`
}

type UserProfile struct {
	UserID     uuid.UUID `db:"user_id"`
	Name       string    `db:"name"`
	FirstName  string    `db:"first_name"`
	LastName   string    `db:"last_name"`
	MiddleName string    `db:"middle_name"`
	Birthdate  *string   `db:"birthdate"`
	Phone      string    `db:"phone"`
	CreatedAt  time.Time `db:"created_at"`
	UpdatedAt  time.Time `db:"updated_at"`
}
