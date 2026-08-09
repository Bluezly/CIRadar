package logsafe

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestKindDoesNotExposeErrorText(t *testing.T) {
	secret := "token=super-secret-value"
	got := Kind(errors.New(secret))
	if got != "error" {
		t.Fatalf("kind=%q", got)
	}
	if strings.Contains(got, secret) {
		t.Fatal("error text leaked")
	}
}

func TestKindClassifiesContextErrors(t *testing.T) {
	if got := Kind(context.Canceled); got != "context_canceled" {
		t.Fatalf("canceled kind=%q", got)
	}
	if got := Kind(context.DeadlineExceeded); got != "deadline_exceeded" {
		t.Fatalf("deadline kind=%q", got)
	}
}
