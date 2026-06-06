package session

import "github.com/google/uuid"

// newID returns a UUIDv7 string (time-ordered) for connection and envelope ids.
func newID() (string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

// NewConnID generates a fresh connection identifier.
func NewConnID() string {
	id, err := newID()
	if err != nil {
		// uuid.NewV7 only errors on entropy failure; fall back to random v4.
		return uuid.NewString()
	}
	return id
}
