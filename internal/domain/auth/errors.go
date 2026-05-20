package auth

import "errors"

var (
	ErrInvalidCredentials  = errors.New("invalid credentials")
	ErrEmailTaken          = errors.New("email already taken")
	ErrUserNotFound        = errors.New("user not found")
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	ErrEmailNotVerified    = errors.New("email not verified")
	ErrInvalidVerifyToken  = errors.New("invalid or expired verification token")
	ErrTokenExpired        = errors.New("token expired")
)
