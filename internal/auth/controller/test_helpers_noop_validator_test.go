package controller

// noopValidator implements echo.Validator but performs no validation.
// Many integration tests only need a non-nil validator instance.
type noopValidator struct{}

func (noopValidator) Validate(i interface{}) error { return nil }
