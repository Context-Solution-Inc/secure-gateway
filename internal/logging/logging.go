// Package logging configures the structured logger (slog) for the relay.
//
// Payload contents MUST NEVER be logged (PRD FR-5.4 / §9.3). Connection
// lifecycle and auth decisions are logged with account_id/pair_id/jti only.
// This package exposes a small set of typed field helpers so call sites cannot
// accidentally pass opaque payload bytes into a log record.
package logging

import (
	"io"
	"log/slog"
	"strings"
)

// New builds a slog.Logger writing to w with the given level and format.
// format is "json" or "text"; level is debug|info|warn|error.
func New(w io.Writer, level, format string) *slog.Logger {
	opts := &slog.HandlerOptions{Level: parseLevel(level)}
	var h slog.Handler
	if strings.EqualFold(format, "text") {
		h = slog.NewTextHandler(w, opts)
	} else {
		h = slog.NewJSONHandler(w, opts)
	}
	return slog.New(h)
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// Connection field keys. Use these constants so all components emit consistent
// structured fields that dashboards and alerts can rely on.
const (
	FieldAccountID  = "account_id"
	FieldPairID     = "pair_id"
	FieldDeviceID   = "device_id"
	FieldRole       = "role"
	FieldJTI        = "jti"
	FieldConnID     = "conn_id"
	FieldInstanceID = "instance_id"
	FieldCloseCode  = "close_code"
	FieldReason     = "reason"
	FieldRemoteIP   = "remote_ip"
)
