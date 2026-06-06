// Package protocol defines the relay wire envelope and control vocabulary
// (PRD FR-4, Appendix B).
//
// The relay reads only the v/type/id fields for routing and control. The
// payload is opaque end-to-end ciphertext: it is never decoded, inspected, or
// logged (FR-4.2, FR-5.4).
package protocol

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/coder/websocket"
)

// Version is the current envelope schema version.
const Version = 1

// Message types (FR-4.1).
const (
	TypeMsg         = "msg"          // application data (peer <-> peer)
	TypeAck         = "ack"          // application-level acknowledgement by id
	TypeAuthRefresh = "auth_refresh" // client -> relay: fresh token over the live socket
	TypeError       = "error"        // relay -> client: error condition
	TypeSys         = "sys"          // relay -> client: presence / lifecycle
)

// Sys message kinds (FR-4.2), carried in the System envelope's Kind field.
const (
	SysPeerOnline  = "peer_online"
	SysPeerOffline = "peer_offline"
	SysEviction    = "eviction"
	SysShutdown    = "shutdown"
)

// Error codes carried in Error envelopes.
const (
	ErrPeerOffline  = "peer_offline"
	ErrProtocol     = "protocol_error"
	ErrUnauthorized = "unauthorized"
)

// Close codes (Appendix B). 1000/1001 are standard; 4001-4005 are app-specific.
const (
	CloseSuperseded   websocket.StatusCode = 4001 // slot evicted; do not auto-reconnect
	CloseTokenExpired websocket.StatusCode = 4003 // refresh token, reconnect
	CloseRevoked      websocket.StatusCode = 4004 // license/pairing revoked; do not reconnect
	CloseProtocol     websocket.StatusCode = 4005 // protocol error / oversize
)

// Envelope is the v1 message frame. Field names are fixed to allow a later
// binary encoding (FR-4.1).
type Envelope struct {
	V       int             `json:"v"`
	Type    string          `json:"type"`
	ID      string          `json:"id"`
	TS      int64           `json:"ts"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// ErrOversize indicates a frame exceeded the configured maximum.
var ErrOversize = errors.New("frame exceeds maximum message size")

// Decode parses and validates a raw frame against the size limit.
// It validates only the relay-relevant structural fields; Payload is left
// opaque. maxBytes <= 0 disables the size check (the transport read limit is
// the authoritative guard; this is defense in depth).
func Decode(raw []byte, maxBytes int64) (*Envelope, error) {
	if maxBytes > 0 && int64(len(raw)) > maxBytes {
		return nil, ErrOversize
	}
	var e Envelope
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, fmt.Errorf("malformed envelope: %w", err)
	}
	if err := e.validate(); err != nil {
		return nil, err
	}
	return &e, nil
}

func (e *Envelope) validate() error {
	if e.V != Version {
		return fmt.Errorf("unsupported envelope version %d", e.V)
	}
	switch e.Type {
	case TypeMsg, TypeAck, TypeAuthRefresh, TypeError, TypeSys:
	default:
		return fmt.Errorf("unknown message type %q", e.Type)
	}
	if e.ID == "" {
		return errors.New("envelope missing id")
	}
	return nil
}

// Encode serializes an envelope to JSON bytes.
func (e *Envelope) Encode() ([]byte, error) {
	return json.Marshal(e)
}

// System is the structured payload of a relay-originated sys message. It is
// placed in the envelope Payload as JSON (this is relay control data, not user
// ciphertext).
type System struct {
	Kind   string `json:"kind"`
	Detail string `json:"detail,omitempty"`
}

// ErrorBody is the structured payload of a relay-originated error message.
type ErrorBody struct {
	Code   string `json:"code"`
	Detail string `json:"detail,omitempty"`
}

// NewSys builds a sys envelope with the given id (uuidv7) and unix-millis ts.
func NewSys(id string, ts int64, kind, detail string) (*Envelope, error) {
	body, err := json.Marshal(System{Kind: kind, Detail: detail})
	if err != nil {
		return nil, err
	}
	return &Envelope{V: Version, Type: TypeSys, ID: id, TS: ts, Payload: body}, nil
}

// NewError builds an error envelope.
func NewError(id string, ts int64, code, detail string) (*Envelope, error) {
	body, err := json.Marshal(ErrorBody{Code: code, Detail: detail})
	if err != nil {
		return nil, err
	}
	return &Envelope{V: Version, Type: TypeError, ID: id, TS: ts, Payload: body}, nil
}
