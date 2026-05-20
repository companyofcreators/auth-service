package auth

import (
	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	jwt.RegisteredClaims
	Email string   `json:"email"`
	Roles []string `json:"roles"`
}

type TokenService interface {
	GenerateAccessToken(userID, email string, roles []string) (string, error)
	GenerateRefreshToken() (string, error)
	ValidateAccessToken(tokenString string) (userID, email string, roles []string, err error)
	ParseAccessToken(tokenString string) (*Claims, error)
}
