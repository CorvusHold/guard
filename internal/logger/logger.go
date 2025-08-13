package logger

import (
	"io"
	"os"
	"strings"

	"github.com/rs/zerolog"
)

// New returns a configured zerolog.Logger. In development, it uses a human-friendly console writer.
func New(appEnv string) zerolog.Logger {
	isDev := strings.ToLower(appEnv) == "development"
	if isDev {
		cw := zerolog.NewConsoleWriter(func(w *zerolog.ConsoleWriter) {
			w.Out = os.Stdout
			w.TimeFormat = "2006-01-02 15:04:05"
		})
		return zerolog.New(cw).With().Timestamp().Logger()
	}
	return zerolog.New(os.Stdout).With().Timestamp().Logger()
}

// Nop returns a disabled logger, useful for tests.
func Nop() zerolog.Logger {
	return zerolog.New(io.Discard)
}
