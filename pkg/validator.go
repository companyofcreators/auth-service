package pkg

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"github.com/go-playground/validator/v10"
)

var validate *validator.Validate

func init() {
	validate = validator.New()
	validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		tag := fld.Tag.Get("json")
		name := strings.SplitN(tag, ",", 2)[0]
		if name == "" || name == "-" {
			return fld.Name
		}
		return name
	})
}

// ValidationErrors maps JSON field names to Russian error descriptions.
type ValidationErrors map[string]string

// ValidateStruct validates a struct and returns field-level errors with Russian messages.
// Returns nil if validation passes.
func ValidateStruct(s interface{}) ValidationErrors {
	err := validate.Struct(s)
	if err == nil {
		return nil
	}

	verrs, ok := err.(validator.ValidationErrors)
	if !ok {
		return ValidationErrors{"_error": "некорректные данные"}
	}

	errors := make(ValidationErrors)
	for _, e := range verrs {
		field := e.Field() // Now returns JSON field name due to RegisterTagNameFunc
		if field == "" {
			field = e.StructField()
		}
		errors[field] = tagToRussian(e)
	}
	return errors
}

// tagToRussian converts a validator tag to a Russian message.
func tagToRussian(e validator.FieldError) string {
	param := e.Param()
	switch e.Tag() {
	case "required":
		return "обязательное поле"
	case "email":
		return "некорректный формат email"
	case "min":
		return fmt.Sprintf("минимум %s", param)
	case "max":
		return fmt.Sprintf("максимум %s", param)
	case "gt":
		return fmt.Sprintf("должно быть больше %s", param)
	case "gte":
		return fmt.Sprintf("должно быть не менее %s", param)
	case "lt":
		return fmt.Sprintf("должно быть меньше %s", param)
	case "lte":
		return fmt.Sprintf("должно быть не более %s", param)
	case "url":
		return "некорректный URL"
	case "uuid":
		return "недействительный UUID"
	case "datetime":
		return "некорректный формат даты"
	default:
		return fmt.Sprintf("не прошло валидацию: %s", e.Tag())
	}
}

// WriteValidationErrors writes validation errors in the {"errors": {...}} format.
func WriteValidationErrors(w http.ResponseWriter, verrs ValidationErrors) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnprocessableEntity)
	resp := map[string]any{"errors": verrs}
	json.NewEncoder(w).Encode(resp)
}
