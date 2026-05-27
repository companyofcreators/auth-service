package db

import (
	"database/sql"
	"fmt"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

type Postgres struct {
	db *sqlx.DB
}

func Connect(dsn string) (*Postgres, error) {
	db, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &Postgres{db: db}, nil
}

// DB returns the underlying *sql.DB for transaction support.
func (p *Postgres) DB() *sql.DB {
	return p.db.DB
}

// SqlxDB returns the underlying *sqlx.DB for repositories that need sqlx extensions.
func (p *Postgres) SqlxDB() *sqlx.DB {
	return p.db
}

// Close closes the underlying database connection.
func (p *Postgres) Close() error {
	return p.db.Close()
}

func RunMigrations(db *sqlx.DB) error {
	migrations := []string{
		`CREATE EXTENSION IF NOT EXISTS "uuid-ossp"`,
		`CREATE TABLE IF NOT EXISTS credentials (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			email VARCHAR(255) UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			verified BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS user_roles (
			user_id UUID NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
			role VARCHAR(50) NOT NULL CHECK (role IN ('user', 'master', 'moderator', 'admin')),
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			PRIMARY KEY (user_id, role)
		)`,
		`CREATE TABLE IF NOT EXISTS user_profiles (
			user_id UUID PRIMARY KEY REFERENCES credentials(id) ON DELETE CASCADE,
			name VARCHAR(200) NOT NULL DEFAULT '',
			first_name VARCHAR(100) NOT NULL DEFAULT '',
			last_name VARCHAR(100) NOT NULL DEFAULT '',
			middle_name VARCHAR(100) NOT NULL DEFAULT '',
			birthdate DATE,
			phone VARCHAR(50) NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_credentials_email ON credentials(email)`,
		`ALTER TABLE credentials ADD COLUMN IF NOT EXISTS is_banned BOOLEAN NOT NULL DEFAULT false`,
		`ALTER TABLE credentials ADD COLUMN IF NOT EXISTS banned_reason TEXT`,
	}

	for _, m := range migrations {
		if _, err := db.Exec(m); err != nil {
			return fmt.Errorf("migration failed: %w", err)
		}
	}

	return nil
}
