// Package testclient is a reusable Go relay client for integration and soak
// tests. It connects with a bearer token, sends/receives envelopes, refreshes
// tokens over the live socket, and reports the close code.
package testclient

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/coder/websocket"

	"github.com/context-solutions-inc/secure-gateway/internal/relay/protocol"
)

// Client wraps a single relay connection.
type Client struct {
	conn *websocket.Conn
}

// Dial connects to wsURL (ws:// or wss://) presenting the token in the
// Authorization header (never in the URL).
func Dial(ctx context.Context, wsURL, bearer string, httpClient *http.Client) (*Client, error) {
	hdr := http.Header{}
	if bearer != "" {
		hdr.Set("Authorization", "Bearer "+bearer)
	}
	conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: hdr,
		HTTPClient: httpClient,
	})
	if err != nil {
		return nil, err
	}
	conn.SetReadLimit(1 << 20)
	return &Client{conn: conn}, nil
}

// SendMsg sends a msg-type envelope carrying the given opaque payload bytes.
func (c *Client) SendMsg(ctx context.Context, id string, payload []byte) error {
	pl, err := json.Marshal(payload) // base64-encodes as a JSON string
	if err != nil {
		return err
	}
	env := &protocol.Envelope{V: 1, Type: protocol.TypeMsg, ID: id, TS: time.Now().UnixMilli(), Payload: pl}
	return c.send(ctx, env)
}

// SendRefresh sends an auth_refresh control frame with a new bearer token.
func (c *Client) SendRefresh(ctx context.Context, newToken string) error {
	body, _ := json.Marshal(map[string]string{"token": newToken})
	env := &protocol.Envelope{V: 1, Type: protocol.TypeAuthRefresh, ID: "refresh", TS: time.Now().UnixMilli(), Payload: body}
	return c.send(ctx, env)
}

// SendRaw writes raw bytes as a single message (for protocol-error tests).
func (c *Client) SendRaw(ctx context.Context, data []byte) error {
	return c.conn.Write(ctx, websocket.MessageText, data)
}

func (c *Client) send(ctx context.Context, env *protocol.Envelope) error {
	b, err := env.Encode()
	if err != nil {
		return err
	}
	return c.conn.Write(ctx, websocket.MessageText, b)
}

// Recv reads the next envelope.
func (c *Client) Recv(ctx context.Context) (*protocol.Envelope, error) {
	_, data, err := c.conn.Read(ctx)
	if err != nil {
		return nil, err
	}
	var env protocol.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, err
	}
	return &env, nil
}

// RecvType reads until it sees an envelope of the given type (skipping others
// such as sys presence frames), or ctx expires.
func (c *Client) RecvType(ctx context.Context, msgType string) (*protocol.Envelope, error) {
	for {
		env, err := c.Recv(ctx)
		if err != nil {
			return nil, err
		}
		if env.Type == msgType {
			return env, nil
		}
	}
}

// DecodePayload unmarshals a msg payload back to the original bytes sent by
// SendMsg.
func DecodePayload(env *protocol.Envelope) ([]byte, error) {
	var b []byte
	if err := json.Unmarshal(env.Payload, &b); err != nil {
		return nil, err
	}
	return b, nil
}

// WaitClose blocks until the connection closes and returns the close code and
// reason.
func (c *Client) WaitClose(ctx context.Context) (websocket.StatusCode, string) {
	for {
		_, _, err := c.conn.Read(ctx)
		if err != nil {
			return websocket.CloseStatus(err), err.Error()
		}
	}
}

// Close closes the connection normally.
func (c *Client) Close() {
	_ = c.conn.Close(websocket.StatusNormalClosure, "")
}
