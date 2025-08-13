package validation

import (
	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
)

type defaultValidator struct{ v *validator.Validate }

func (d *defaultValidator) Validate(i interface{}) error {
	return d.v.Struct(i)
}

// New returns an echo.Validator implementation.
func New() echo.Validator {
	v := validator.New(validator.WithRequiredStructEnabled())
	return &defaultValidator{v: v}
}
