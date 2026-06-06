package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/coder/websocket"
)

func jsonUnmarshal(data []byte, v any) error { return json.Unmarshal(data, v) }

// contains reports whether the handshake error string mentions the HTTP status.
func contains(errStr string, status int) bool {
	return strings.Contains(errStr, strconv.Itoa(status))
}

// dialRaw dials a WebSocket URL with no Authorization header (for negative tests).
func dialRaw(ctx context.Context, url string) (*websocket.Conn, *http.Response, error) {
	return websocket.Dial(ctx, url, nil)
}
