// hermes/relay.go
package hermes

import "context"

type TypedPublisher interface {
	// Publish typed message to topic, value must be of the exact registered type.
	Publish(ctx context.Context, topic, typeName string, v any, headers map[string]string) error
}

type RelayRequest struct {
	Topic   string
	Body    []byte
	Headers map[string]string
}

type RelayClient interface {
	Request(ctx context.Context, rr RelayRequest) ([]byte, error)
	Publish(ctx context.Context, rr RelayRequest) error
}

type NoopRelay struct{}

func (NoopRelay) Request(context.Context, RelayRequest) ([]byte, error) {
	return nil, ErrNoRelay
}

func (NoopRelay) Publish(context.Context, RelayRequest) error {
	return ErrNoRelay
}

var ErrNoRelay = errorString("relay: no client configured")

type errorString string

func (e errorString) Error() string { return string(e) }
