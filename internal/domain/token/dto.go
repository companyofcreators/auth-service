package token

type LoginRequest struct {
	Email    string `json:"email" validate:"email"`
	Password string `json:"password" validate:"required,min=8"`
}

type RegisterRequest struct {
	Email      string `json:"email" validate:"email"`
	Password   string `json:"password" validate:"required,min=8"`
	Name       string `json:"name" validate:"required"`
	Phone      string `json:"phone" validate:"required"`
	Role       string `json:"role" validate:"required"`
	Patronymic string `json:"patronymic,omitempty"`
	LastName   string `json:"last_name" validate:"required"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}
