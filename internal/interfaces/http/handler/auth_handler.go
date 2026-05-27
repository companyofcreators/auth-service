package handler

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"unicode"

	app "github.com/companyofcreators/auth-service/internal/application/auth"
	domain "github.com/companyofcreators/auth-service/internal/domain/auth"
	"github.com/companyofcreators/auth-service/pkg"
)

type RegisterRequest struct {
	Email      string `json:"email" validate:"required,email"`
	Password   string `json:"password" validate:"required,min=8"`
	FirstName  string `json:"first_name" validate:"required,min=1,max=100"`
	LastName   string `json:"last_name" validate:"required,min=1,max=100"`
	MiddleName string `json:"middle_name" validate:"omitempty,max=100"`
	Birthdate  string `json:"birthdate" validate:"omitempty,datetime=2006-01-02"`
	Phone      string `json:"phone" validate:"required"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type AuthResponse struct {
	AccessToken  string   `json:"access_token,omitempty"`
	RefreshToken string   `json:"refresh_token,omitempty"`
	UserID       string   `json:"user_id"`
	Email        string   `json:"email"`
	Roles        []string `json:"roles"`
	Message      string   `json:"message,omitempty"`
}

type ResendVerificationRequest struct {
	Email string `json:"email"`
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
	resendVerify *app.ResendVerificationUseCase
	logger      *slog.Logger
	accessTTL   int
	refreshTTL  int
	env         string
	frontendURL string
}

func NewAuthHandler(
	register *app.RegisterUseCase,
	login *app.LoginUseCase,
	refresh *app.RefreshUseCase,
	validate *app.ValidateUseCase,
	logout *app.LogoutUseCase,
	verifyEmail *app.VerifyEmailUseCase,
	resendVerify *app.ResendVerificationUseCase,
	logger *slog.Logger,
	accessTTL int,
	refreshTTL int,
	env string,
	frontendURL string,
) *AuthHandler {
	return &AuthHandler{
		register:     register,
		login:        login,
		refresh:      refresh,
		validate:     validate,
		logout:       logout,
		verifyEmail:  verifyEmail,
		resendVerify: resendVerify,
		logger:       logger,
		accessTTL:    accessTTL,
		refreshTTL:   refreshTTL,
		env:          env,
		frontendURL:  frontendURL,
	}
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "некорректное тело запроса")
		return
	}

	if verrs := pkg.ValidateStruct(req); verrs != nil {
		pkg.WriteValidationErrors(w, verrs)
		return
	}

	if !isPasswordComplex(req.Password) {
		h.writeError(w, http.StatusBadRequest, "пароль должен содержать минимум 8 символов, заглавную букву и цифру")
		return
	}

	result, err := h.register.Execute(r.Context(), app.RegisterInput{
		Email:      req.Email,
		Password:   req.Password,
		FirstName:  req.FirstName,
		LastName:   req.LastName,
		MiddleName: req.MiddleName,
		Birthdate:  req.Birthdate,
		Phone:      req.Phone,
	})
	if err != nil {
		if errors.Is(err, domain.ErrEmailTaken) {
			h.writeError(w, http.StatusConflict, "email уже занят")
			return
		}
		h.logger.Error("register failed", "error", err)
		h.writeError(w, http.StatusInternalServerError, "внутренняя ошибка сервера")
		return
	}

	if result.AccessToken != "" {
		h.setCookies(w, result.AccessToken, result.RefreshToken)
	}
	h.writeJSON(w, http.StatusCreated, AuthResponse{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		UserID:       result.UserID,
		Email:        result.Email,
		Roles:        result.Roles,
		Message:      result.Message,
	})
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "некорректное тело запроса")
		return
	}

	if verrs := pkg.ValidateStruct(req); verrs != nil {
		pkg.WriteValidationErrors(w, verrs)
		return
	}

	result, err := h.login.Execute(r.Context(), app.LoginInput{
		Email:    req.Email,
		Password: req.Password,
	})
	if err != nil {
		if errors.Is(err, domain.ErrInvalidCredentials) {
			h.writeError(w, http.StatusUnauthorized, "неверные учётные данные")
			return
		}
		if errors.Is(err, domain.ErrEmailNotVerified) {
			h.writeError(w, http.StatusForbidden, "email не подтверждён")
			return
		}
		if errors.Is(err, domain.ErrUserBanned) {
			msg := strings.TrimSuffix(err.Error(), ": пользователь заблокирован")
			h.writeError(w, http.StatusForbidden, msg)
			return
		}
		h.logger.Error("login failed", "error", err)
		h.writeError(w, http.StatusInternalServerError, "внутренняя ошибка сервера")
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
		h.writeError(w, http.StatusUnauthorized, "refresh-токен не найден")
		return
	}

	result, err := h.refresh.Execute(r.Context(), app.RefreshInput{
		RefreshToken: refreshToken,
	})
	if err != nil {
		if errors.Is(err, domain.ErrInvalidRefreshToken) {
			h.writeError(w, http.StatusUnauthorized, "недействительный refresh-токен")
			return
		}
		h.logger.Error("refresh failed", "error", err)
		h.writeError(w, http.StatusInternalServerError, "внутренняя ошибка сервера")
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
	userID := r.Header.Get("X-User-Id")
	if userID == "" {
		h.writeError(w, http.StatusUnauthorized, "не авторизован")
		return
	}

	refreshToken := h.getRefreshTokenFromCookie(r)

	if err := h.logout.Execute(r.Context(), app.LogoutInput{
		UserID:       userID,
		RefreshToken: refreshToken,
	}); err != nil {
		h.logger.Error("logout failed", "error", err)
		h.writeError(w, http.StatusInternalServerError, "внутренняя ошибка сервера")
		return
	}

	h.clearCookies(w)
	h.writeJSON(w, http.StatusOK, SuccessResponse{Message: "выход выполнен"})
}

func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		writeVerifyHTML(w, false, "Токен не указан. Пожалуйста, перейдите по ссылке из письма.")
		return
	}

	if err := h.verifyEmail.Execute(r.Context(), app.VerifyEmailInput{
		Token: token,
	}); err != nil {
		if errors.Is(err, domain.ErrInvalidVerifyToken) {
			writeVerifyHTML(w, false, "Недействительный или истёкший токен. Возможно, он уже был использован или срок действия истёк. Запросите новое письмо на странице входа.")
			return
		}
		h.logger.Error("verify email failed", "error", err)
		writeVerifyHTML(w, false, "Внутренняя ошибка сервера. Попробуйте позже.")
		return
	}

	writeVerifyHTML(w, true, "Email успешно подтверждён! Теперь вы можете войти в приложение.")
}

func (h *AuthHandler) ResendVerification(w http.ResponseWriter, r *http.Request) {
	var req ResendVerificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "некорректное тело запроса")
		return
	}

	if req.Email == "" {
		h.writeError(w, http.StatusBadRequest, "email обязателен")
		return
	}

	if err := h.resendVerify.Execute(r.Context(), app.ResendVerificationInput{
		Email: req.Email,
	}); err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			h.writeJSON(w, http.StatusOK, SuccessResponse{Message: "если учётная запись существует, письмо отправлено"})
			return
		}
		h.logger.Error("resend verification failed", "error", err)
		h.writeError(w, http.StatusInternalServerError, "внутренняя ошибка сервера")
		return
	}

	h.writeJSON(w, http.StatusOK, SuccessResponse{Message: "письмо с подтверждением отправлено повторно"})
}

func writeVerifyHTML(w http.ResponseWriter, success bool, message string) {
	statusColor := "#16a34a"
	statusIcon := "✓"
	statusTitle := "Готово!"
	if !success {
		statusColor = "#ef4444"
		statusIcon = "✗"
		statusTitle = "Ошибка"
	}

	html := `<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Quicky — ` + statusTitle + `</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, #2563eb 0%, #7c3aed 100%);
  padding: 20px;
}
.card {
  background: #fff;
  border-radius: 16px;
  padding: 40px 32px;
  width: 100%;
  max-width: 380px;
  text-align: center;
  box-shadow: 0 20px 60px rgba(0,0,0,0.15);
}
.icon {
  width: 64px; height: 64px;
  border-radius: 50%;
  background: ` + statusColor + `;
  color: #fff;
  font-size: 32px;
  line-height: 64px;
  margin: 0 auto 20px;
}
h1 { font-size: 22px; color: #1e293b; margin-bottom: 10px; }
p { font-size: 15px; color: #64748b; line-height: 1.6; margin-bottom: 24px; }
.btn {
  display: inline-block;
  width: 100%;
  padding: 14px 20px;
  background: #2563eb;
  color: #fff;
  text-decoration: none;
  border-radius: 10px;
  font-size: 15px;
  font-weight: 600;
  border: none;
  cursor: pointer;
}
.logo {
  font-size: 28px;
  font-weight: 800;
  color: #2563eb;
  margin-bottom: 20px;
}
</style>
</head>
<body>
<div class="card">
  <div class="logo">Quicky</div>
  <div class="icon">` + statusIcon + `</div>
  <h1>` + statusTitle + `</h1>
  <p>` + message + `</p>
  <a href="/login" class="btn">Перейти ко входу</a>
</div>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

func (h *AuthHandler) setCookies(w http.ResponseWriter, accessToken, refreshToken string) {
	secure := h.env == "production"

	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   h.accessTTL,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
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
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   h.env == "production",
		SameSite: http.SameSiteStrictMode,
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

func isPasswordComplex(password string) bool {
	if len(password) < 8 {
		return false
	}
	hasUpper := false
	hasDigit := false
	for _, r := range password {
		if unicode.IsUpper(r) {
			hasUpper = true
		}
		if unicode.IsDigit(r) {
			hasDigit = true
		}
	}
	return hasUpper && hasDigit
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
		Error:   statusText(status),
		Message: message,
	}
	json.NewEncoder(w).Encode(errResp)
}

func statusText(code int) string {
	switch code {
	case http.StatusBadRequest:
		return "некорректный запрос"
	case http.StatusUnauthorized:
		return "не авторизован"
	case http.StatusForbidden:
		return "доступ запрещён"
	case http.StatusNotFound:
		return "не найдено"
	case http.StatusConflict:
		return "конфликт"
	case http.StatusUnprocessableEntity:
		return "ошибка валидации"
	case http.StatusTooManyRequests:
		return "слишком много запросов"
	case http.StatusInternalServerError:
		return "внутренняя ошибка сервера"
	default:
		return "ошибка"
	}
}
