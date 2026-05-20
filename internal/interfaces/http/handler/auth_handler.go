package handler

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	app "github.com/companyofcreators/auth-service/internal/application/auth"
	domain "github.com/companyofcreators/auth-service/internal/domain/auth"
	"github.com/companyofcreators/auth-service/pkg"
)

type RegisterRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
	Name     string `json:"name" validate:"required,min=1,max=100"`
	Phone    string `json:"phone" validate:"required"`
	Role     string `json:"role"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type AuthResponse struct {
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token"`
	UserID       string   `json:"user_id"`
	Email        string   `json:"email"`
	Roles        []string `json:"roles"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

type SuccessResponse struct {
	Message string `json:"message"`
}

type AuthHandler struct {
	register    *app.RegisterUseCase
	login       *app.LoginUseCase
	refresh     *app.RefreshUseCase
	validate    *app.ValidateUseCase
	logout      *app.LogoutUseCase
	verifyEmail *app.VerifyEmailUseCase
	logger      *slog.Logger
	accessTTL   int
	refreshTTL  int
	env         string
}

func NewAuthHandler(
	register *app.RegisterUseCase,
	login *app.LoginUseCase,
	refresh *app.RefreshUseCase,
	validate *app.ValidateUseCase,
	logout *app.LogoutUseCase,
	verifyEmail *app.VerifyEmailUseCase,
	logger *slog.Logger,
	accessTTL int,
	refreshTTL int,
	env string,
) *AuthHandler {
	return &AuthHandler{
		register:    register,
		login:       login,
		refresh:     refresh,
		validate:    validate,
		logout:      logout,
		verifyEmail: verifyEmail,
		logger:      logger,
		accessTTL:   accessTTL,
		refreshTTL:  refreshTTL,
		env:         env,
	}
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := pkg.ValidateStruct(req); err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	result, err := h.register.Execute(r.Context(), app.RegisterInput{
		Email:    req.Email,
		Password: req.Password,
		Name:     req.Name,
		Phone:    req.Phone,
		Role:     req.Role,
	})
	if err != nil {
		if errors.Is(err, domain.ErrEmailTaken) {
			h.writeError(w, http.StatusConflict, "email already taken")
			return
		}
		h.logger.Error("register failed", "error", err)
		h.writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	h.setCookies(w, result.AccessToken, result.RefreshToken)
	h.writeJSON(w, http.StatusCreated, AuthResponse{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		UserID:       result.UserID,
		Email:        result.Email,
		Roles:        result.Roles,
	})
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := pkg.ValidateStruct(req); err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	result, err := h.login.Execute(r.Context(), app.LoginInput{
		Email:    req.Email,
		Password: req.Password,
	})
	if err != nil {
		if errors.Is(err, domain.ErrInvalidCredentials) {
			h.writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		if errors.Is(err, domain.ErrEmailNotVerified) {
			h.writeError(w, http.StatusForbidden, "email not verified")
			return
		}
		h.logger.Error("login failed", "error", err)
		h.writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	h.setCookies(w, result.AccessToken, result.RefreshToken)
	h.writeJSON(w, http.StatusOK, AuthResponse{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		UserID:       result.UserID,
		Email:        result.Email,
		Roles:        result.Roles,
	})
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	refreshToken := h.getRefreshTokenFromCookie(r)
	if refreshToken == "" {
		h.writeError(w, http.StatusUnauthorized, "refresh token not found")
		return
	}

	result, err := h.refresh.Execute(r.Context(), app.RefreshInput{
		RefreshToken: refreshToken,
	})
	if err != nil {
		if errors.Is(err, domain.ErrInvalidRefreshToken) {
			h.writeError(w, http.StatusUnauthorized, "invalid refresh token")
			return
		}
		h.logger.Error("refresh failed", "error", err)
		h.writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	h.setCookies(w, result.AccessToken, result.RefreshToken)
	h.writeJSON(w, http.StatusOK, AuthResponse{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		UserID:       result.UserID,
		Email:        result.Email,
		Roles:        result.Roles,
	})
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserIDFromContext(r)
	if userID == "" {
		h.writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	refreshToken := h.getRefreshTokenFromCookie(r)

	if err := h.logout.Execute(r.Context(), app.LogoutInput{
		UserID:       userID,
		RefreshToken: refreshToken,
	}); err != nil {
		h.logger.Error("logout failed", "error", err)
		h.writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	h.clearCookies(w)
	h.writeJSON(w, http.StatusOK, SuccessResponse{Message: "logged out"})
}

func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		h.writeError(w, http.StatusBadRequest, "token is required")
		return
	}

	if err := h.verifyEmail.Execute(r.Context(), app.VerifyEmailInput{
		Token: token,
	}); err != nil {
		if errors.Is(err, domain.ErrInvalidVerifyToken) {
			h.writeError(w, http.StatusBadRequest, "invalid or expired verification token")
			return
		}
		h.logger.Error("verify email failed", "error", err)
		h.writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	h.writeJSON(w, http.StatusOK, SuccessResponse{Message: "email verified successfully"})
}

func (h *AuthHandler) Validate(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if token == "" {
		h.writeError(w, http.StatusUnauthorized, "authorization header required")
		return
	}

	if len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}

	result, err := h.validate.Execute(r.Context(), app.ValidateInput{
		AccessToken: token,
	})
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "invalid access token")
		return
	}

	h.writeJSON(w, http.StatusOK, AuthResponse{
		UserID: result.UserID,
		Email:  result.Email,
		Roles:  result.Roles,
	})
}

func (h *AuthHandler) setCookies(w http.ResponseWriter, accessToken, refreshToken string) {
	secure := h.env == "production"

	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   h.accessTTL,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   h.refreshTTL,
	})
}

func (h *AuthHandler) clearCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   h.env == "production",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   h.env == "production",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func (h *AuthHandler) getRefreshTokenFromCookie(r *http.Request) string {
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		return ""
	}
	return cookie.Value
}

func (h *AuthHandler) getUserIDFromContext(r *http.Request) string {
	userID := r.Context().Value("user_id")
	if userID == nil {
		return ""
	}
	id, ok := userID.(string)
	if !ok {
		return ""
	}
	return id
}

func (h *AuthHandler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to write json response", "error", err)
	}
}

func (h *AuthHandler) writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	errResp := ErrorResponse{
		Error:   http.StatusText(status),
		Message: message,
	}
	json.NewEncoder(w).Encode(errResp)
}
