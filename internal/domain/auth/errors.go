package auth

import "errors"

var (
	ErrInvalidCredentials  = errors.New("неверные учётные данные")
	ErrEmailTaken          = errors.New("email уже занят")
	ErrUserNotFound        = errors.New("пользователь не найден")
	ErrInvalidRefreshToken = errors.New("недействительный refresh-токен")
	ErrEmailNotVerified    = errors.New("email не подтверждён")
	ErrInvalidVerifyToken  = errors.New("недействительный или истёкший токен верификации")
	ErrTokenExpired        = errors.New("срок действия токена истёк")
	ErrUserBanned          = errors.New("пользователь заблокирован")
)
