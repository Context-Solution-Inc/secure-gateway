package protocol

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestDecodeRoundTrip(t *testing.T) {
	orig := &Envelope{V: 1, Type: TypeMsg, ID: "01890c2e-aaaa-7bbb-8ccc-ddddeeeeffff", TS: 1765432100123, Payload: json.RawMessage(`"c29tZQ"`)}
	raw, err := orig.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(raw, 256*1024)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.V != 1 || got.Type != TypeMsg || got.ID != orig.ID || got.TS != orig.TS {
		t.Errorf("round trip mismatch: %+v", got)
	}
	if string(got.Payload) != string(orig.Payload) {
		t.Errorf("payload mismatch: %s vs %s", got.Payload, orig.Payload)
	}
}

func TestDecodeOversize(t *testing.T) {
	big := make([]byte, 1024)
	for i := range big {
		big[i] = 'x'
	}
	pl, _ := json.Marshal(string(big))
	e := &Envelope{V: 1, Type: TypeMsg, ID: "x", Payload: pl}
	raw, _ := e.Encode()
	if _, err := Decode(raw, 100); !errors.Is(err, ErrOversize) {
		t.Fatalf("expected ErrOversize, got %v", err)
	}
}

func TestDecodeValidation(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"bad json", `{not json`, "malformed"},
		{"wrong version", `{"v":2,"type":"msg","id":"x"}`, "unsupported envelope version"},
		{"unknown type", `{"v":1,"type":"frobnicate","id":"x"}`, "unknown message type"},
		{"missing id", `{"v":1,"type":"msg","id":""}`, "missing id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decode([]byte(tt.raw), 0)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestNewSysAndError(t *testing.T) {
	sys, err := NewSys("id1", 123, SysPeerOnline, "")
	if err != nil {
		t.Fatal(err)
	}
	if sys.Type != TypeSys {
		t.Errorf("type = %q", sys.Type)
	}
	var body System
	if err := json.Unmarshal(sys.Payload, &body); err != nil {
		t.Fatal(err)
	}
	if body.Kind != SysPeerOnline {
		t.Errorf("kind = %q", body.Kind)
	}

	e, err := NewError("id2", 456, ErrPeerOffline, "no peer")
	if err != nil {
		t.Fatal(err)
	}
	var eb ErrorBody
	if err := json.Unmarshal(e.Payload, &eb); err != nil {
		t.Fatal(err)
	}
	if eb.Code != ErrPeerOffline || eb.Detail != "no peer" {
		t.Errorf("error body = %+v", eb)
	}
}
