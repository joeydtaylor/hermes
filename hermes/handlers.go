// hermes/handlers.go
package hermes

import "context"

// InprocHandler is the signature for user-defined in-process handlers.
// 'in' is the raw request body, 'status' is HTTP status code to send.
type InprocHandler func(ctx context.Context, in []byte) (out []byte, status int, err error)

var registry = map[string]InprocHandler{}

// Register makes a handler available under a name referenced in manifest.toml
func Register(name string, h InprocHandler) {
	registry[name] = h
}

// Lookup retrieves a registered in-proc handler by name.
func Lookup(name string) (InprocHandler, bool) {
	h, ok := registry[name]
	return h, ok
}
