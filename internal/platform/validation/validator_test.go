package validation

import (
	"testing"

	"github.com/go-playground/validator/v10"
)

type testPayload struct {
	Email string `validate:"required,email"`
	Age   int    `validate:"gte=18"`
}

func TestNew_ValidateSuccess(t *testing.T) {
	v := New()
	if err := v.Validate(testPayload{Email: "ok@example.com", Age: 21}); err != nil {
		t.Fatalf("expected payload to validate: %v", err)
	}
}

func TestNew_ValidateFailureAndErrorResponse(t *testing.T) {
	v := New()
	err := v.Validate(testPayload{Email: "not-an-email", Age: 12})
	if err == nil {
		t.Fatal("expected validation error")
	}

	body := ErrorResponse(err)
	if body.Error != "validation_failed" {
		t.Fatalf("expected validation_failed error body, got %q", body.Error)
	}
	if len(body.Fields["email"]) == 0 {
		t.Fatal("expected email field validation tags")
	}
	if len(body.Fields["age"]) == 0 {
		t.Fatal("expected age field validation tags")
	}
}

func TestErrorResponse_NonValidationError(t *testing.T) {
	err := validator.ValidationErrors(nil)
	_ = err // keep import usage explicit for validator package

	body := ErrorResponse(assertErr("boom"))
	if body.Error != "boom" {
		t.Fatalf("expected raw error message, got %q", body.Error)
	}
	if len(body.Fields) != 0 {
		t.Fatalf("expected empty fields for non-validation error, got %+v", body.Fields)
	}
}

type assertErr string

func (e assertErr) Error() string { return string(e) }
