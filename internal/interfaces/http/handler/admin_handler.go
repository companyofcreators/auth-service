package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	domain "github.com/companyofcreators/auth-service/internal/domain/auth"
)

// BanRequest is the request body for banning a user.
type BanRequest struct {
	Reason string `json:"reason"`
}

// AdminHandler holds dependencies for admin HTTP handlers.
type AdminHandler struct {
	credentialRepo domain.CredentialRepository
	logger         *slog.Logger
}

// NewAdminHandler creates a new AdminHandler.
func NewAdminHandler(
	credentialRepo domain.CredentialRepository,
	logger *slog.Logger,
) *AdminHandler {
	return &AdminHandler{
		credentialRepo: credentialRepo,
		logger:         logger,
	}
}

// BanUser bans the user identified by {id} in the URL path.
func (h *AdminHandler) BanUser(w http.ResponseWriter, r *http.Request) {
	userIDStr := chi.URLParam(r, "id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "некорректный идентификатор пользователя")
		return
	}

	var req BanRequest
	if r.Body != nil {
		if decodeErr := json.NewDecoder(r.Body).Decode(&req); decodeErr != nil {
			// Body might be empty or have no reason - that's acceptable.
			// We only log the issue, but don't fail.
			h.logger.Debug("failed to decode ban request body, using empty reason", "error", decodeErr)
		}
	}

	if err := h.credentialRepo.BanUser(r.Context(), userID, req.Reason); err != nil {
		h.logger.Error("failed to ban user", "error", err, "user_id", userID)
		h.writeError(w, http.StatusInternalServerError, "внутренняя ошибка сервера")
		return
	}

	h.logger.Info("user banned", "user_id", userID, "reason", req.Reason)
	h.writeJSON(w, http.StatusOK, SuccessResponse{Message: "пользователь заблокирован"})
}

// UnbanUser lifts the ban on the user identified by {id} in the URL path.
func (h *AdminHandler) UnbanUser(w http.ResponseWriter, r *http.Request) {
	userIDStr := chi.URLParam(r, "id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "некорректный идентификатор пользователя")
		return
	}

	if err := h.credentialRepo.UnbanUser(r.Context(), userID); err != nil {
		h.logger.Error("failed to unban user", "error", err, "user_id", userID)
		h.writeError(w, http.StatusInternalServerError, "внутренняя ошибка сервера")
		return
	}

	h.logger.Info("user unbanned", "user_id", userID)
	h.writeJSON(w, http.StatusOK, SuccessResponse{Message: "пользователь разблокирован"})
}

// AddRole adds a role to the user. POST /internal/users/{id}/roles/{role}
func (h *AdminHandler) AddRole(w http.ResponseWriter, r *http.Request) {
	userIDStr := chi.URLParam(r, "id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "некорректный идентификатор пользователя")
		return
	}

	role := chi.URLParam(r, "role")
	if role == "" {
		h.writeError(w, http.StatusBadRequest, "роль обязательна")
		return
	}

	if err := h.credentialRepo.InsertRole(r.Context(), userID, role); err != nil {
		h.logger.Error("failed to add role", "error", err, "user_id", userID, "role", role)
		h.writeError(w, http.StatusInternalServerError, "внутренняя ошибка сервера")
		return
	}

	h.logger.Info("role added", "user_id", userID, "role", role)
	h.writeJSON(w, http.StatusOK, SuccessResponse{Message: "роль добавлена"})
}

// RemoveRole removes a role from the user. DELETE /internal/users/{id}/roles/{role}
func (h *AdminHandler) RemoveRole(w http.ResponseWriter, r *http.Request) {
	userIDStr := chi.URLParam(r, "id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "некорректный идентификатор пользователя")
		return
	}

	role := chi.URLParam(r, "role")
	if role == "" {
		h.writeError(w, http.StatusBadRequest, "роль обязательна")
		return
	}

	if err := h.credentialRepo.RemoveRole(r.Context(), userID, role); err != nil {
		h.logger.Error("failed to remove role", "error", err, "user_id", userID, "role", role)
		h.writeError(w, http.StatusInternalServerError, "внутренняя ошибка сервера")
		return
	}

	h.logger.Info("role removed", "user_id", userID, "role", role)
	h.writeJSON(w, http.StatusOK, SuccessResponse{Message: "роль удалена"})
}

// DeleteUser deletes the user identified by {id} in the URL path.
func (h *AdminHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	userIDStr := chi.URLParam(r, "id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "некорректный идентификатор пользователя")
		return
	}

	if err := h.credentialRepo.DeleteUser(r.Context(), userID); err != nil {
		h.logger.Error("failed to delete user", "error", err, "user_id", userID)
		h.writeError(w, http.StatusInternalServerError, "внутренняя ошибка сервера")
		return
	}

	h.logger.Info("user deleted", "user_id", userID)
	h.writeJSON(w, http.StatusOK, SuccessResponse{Message: "пользователь удалён"})
}

func (h *AdminHandler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to write json response", "error", err)
	}
}

func (h *AdminHandler) writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	errResp := ErrorResponse{
		Error:   statusText(status),
		Message: message,
	}
	json.NewEncoder(w).Encode(errResp)
}
