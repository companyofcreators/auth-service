package pkg

import (
	"fmt"
	"strings"

	"github.com/go-playground/validator/v10"
)

var validate *validator.Validate

func init() {
	validate = validator.New()
}

func ValidateStruct(s interface{}) error {
	err := validate.Struct(s)
	if err != nil {
		var messages []string
		for _, err := range err.(validator.ValidationErrors) {
			messages = append(messages, fmt.Sprintf("field '%s' failed validation: %s", err.Field(), err.Tag()))
		}
		return fmt.Errorf("validation failed: %s", strings.Join(messages, "; "))
	}
	return nil
}
