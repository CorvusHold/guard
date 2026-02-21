package logger

import (
	"testing"

	"github.com/rs/zerolog"
)

func TestNew_UsesDebugLevelForDev(t *testing.T) {
	l := New("dev")
	if got := l.GetLevel(); got != zerolog.DebugLevel {
		t.Fatalf("expected debug level for dev, got %s", got)
	}
}

func TestNew_UsesInfoLevelForNonDev(t *testing.T) {
	l := New("production")
	if got := l.GetLevel(); got != zerolog.InfoLevel {
		t.Fatalf("expected info level for production, got %s", got)
	}
}

func TestNop_DisabledLogger(t *testing.T) {
	l := Nop()
	if got := l.GetLevel(); got != zerolog.TraceLevel {
		t.Fatalf("expected trace level default for nop logger, got %s", got)
	}
	// smoke check: logger writes to discard and should never panic.
	l.Info().Str("k", "v").Msg("nop")
}
