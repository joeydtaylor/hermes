package receiver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/joeydtaylor/hermes/hermes"
)

var (
	ErrMissingType  = errors.New("missing X-Relay-Type")
	ErrTypeMismatch = errors.New("relay type mismatch")
	ErrDecode       = errors.New("decode error")
	ErrBodyRead     = errors.New("body read error")
	ErrEmptyBody    = errors.New("empty body")
)

// ExtractType returns the declared relay type header.
func ExtractType(r *http.Request) (string, error) {
	typ := r.Header.Get("X-Relay-Type")
	if typ == "" {
		return "", ErrMissingType
	}
	return typ, nil
}

// DecodeExact reads the body and enforces that it matches expectedType
// using Hermes' type registry & codecs (strict JSON).
// It returns the canonical bytes and the typed value T.
func DecodeExact[T any](r *http.Request, expectedType string) (canonical []byte, v T, _ error) {
	if expectedType == "" {
		var zero T
		return nil, zero, fmt.Errorf("%w: expected type empty", ErrTypeMismatch)
	}
	got, err := ExtractType(r)
	if err != nil {
		var zero T
		return nil, zero, err
	}
	if got != expectedType {
		var zero T
		return nil, zero, fmt.Errorf("%w: got=%q want=%q", ErrTypeMismatch, got, expectedType)
	}

	b, err := io.ReadAll(r.Body)
	if err != nil {
		var zero T
		return nil, zero, ErrBodyRead
	}
	if len(b) == 0 {
		var zero T
		return nil, zero, ErrEmptyBody
	}

	// Validate & canonicalize via registry; then unmarshal into T for handler ergonomics.
	_, canon, err := hermes.ValidateAndCanonicalize(expectedType, b)
	if err != nil {
		var zero T
		return nil, zero, fmt.Errorf("%w: %v", ErrDecode, err)
	}

	var out T
	if err := json.Unmarshal(canon, &out); err != nil {
		var zero T
		return nil, zero, fmt.Errorf("%w (post-canonical): %v", ErrDecode, err)
	}
	return canon, out, nil
}

// TypedHandler wraps an application handler with strict type enforcement.
// expectedType must be registered on startup (same registry as ingress).
func TypedHandler[T any](
	expectedType string,
	fn func(ctx context.Context, v T) (resp any, status int, err error),
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, v, err := DecodeExact[T](r, expectedType)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp, status, err := fn(r.Context(), v)
		if err != nil {
			http.Error(w, err.Error(), statusIf(status, http.StatusInternalServerError))
			return
		}
		writeJSON(w, resp, statusIf(status, http.StatusOK))
	}
}

func writeJSON(w http.ResponseWriter, v any, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v == nil {
		w.Write([]byte(`{}`))
		return
	}
	b, _ := json.Marshal(v)
	w.Write(b)
}

func statusIf(s, def int) int {
	if s > 0 {
		return s
	}
	return def
}
