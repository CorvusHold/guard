package validation

import (
	"strings"

	"github.com/go-playground/validator/v10"
)

// ErrorBody is a standard validation error payload.
type ErrorBody struct {
	Error  string              `json:"error"`
	Fields map[string][]string `json:"fields"`
}

// ErrorResponse converts a validator error into a structured response.
func ErrorResponse(err error) ErrorBody {
	fields := map[string][]string{}
	if verrs, ok := err.(validator.ValidationErrors); ok {
		for _, fe := range verrs {
			field := strings.ToLower(fe.Field())
			fields[field] = append(fields[field], fe.Tag())
		}
	}
	if len(fields) == 0 {
		return ErrorBody{Error: err.Error(), Fields: fields}
	}
	return ErrorBody{Error: "validation_failed", Fields: fields}
}
