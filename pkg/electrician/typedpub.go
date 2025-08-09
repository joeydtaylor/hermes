// pkg/electrician/typedpub.go
package electrician

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/joeydtaylor/electrician/pkg/builder"
	"github.com/joeydtaylor/hermes/hermes/transform"
)

// ---- Typed publish surface (no dependency on hermes) ----

type typedPublisher struct {
	mu         sync.RWMutex
	submitters map[string]func(context.Context, any) error
}

// Publish uses (or lazily builds) a submitter for the given type.
func (tp *typedPublisher) Publish(ctx context.Context, topic, typeName string, v any, headers map[string]string) error {
	// Fast path?
	tp.mu.RLock()
	fn, ok := tp.submitters[typeName]
	tp.mu.RUnlock()
	if ok {
		return fn(ctx, v)
	}

	// Build lazily (Fx init-order safe)
	tp.mu.Lock()
	defer tp.mu.Unlock()
	if fn2, ok2 := tp.submitters[typeName]; ok2 {
		return fn2(ctx, v)
	}
	mk := pubReg[typeName]
	if mk == nil {
		return fmt.Errorf("typed publisher: no submitter for %q", typeName)
	}
	sf, err := mk(ctx)
	if err != nil {
		return fmt.Errorf("typed publisher: build %q: %w", typeName, err)
	}
	if tp.submitters == nil {
		tp.submitters = map[string]func(context.Context, any) error{}
	}
	tp.submitters[typeName] = sf
	return sf(ctx, v)
}

// ---- Registries ----

var (
	mu     sync.RWMutex
	pubReg = map[string]func(ctx context.Context) (func(context.Context, any) error, error){}
	rcvReg = map[string]func(ctx context.Context, address string, buffer int, names []string) (func(), error){}
)

// EnableBuilderType registers both:
//   - a typed publisher factory for T
//   - a receiver starter (by datatype name) that resolves manifest transformer names
func EnableBuilderType[T any](typeName string) {
	mu.Lock()
	defer mu.Unlock()

	// Publisher factory
	if _, exists := pubReg[typeName]; !exists {
		pubReg[typeName] = func(ctx context.Context) (func(context.Context, any) error, error) {
			// If no targets, be a no-op so router can still run.
			if strings.TrimSpace(os.Getenv("ELECTRICIAN_TARGET")) == "" {
				return func(context.Context, any) error { return nil }, nil
			}

			useTLS := strings.EqualFold(os.Getenv("ELECTRICIAN_TLS_ENABLE"), "true")
			tlsCrt := envOr("ELECTRICIAN_TLS_CLIENT_CRT", "keys/tls/client.crt")
			tlsKey := envOr("ELECTRICIAN_TLS_CLIENT_KEY", "keys/tls/client.key")
			tlsCA := envOr("ELECTRICIAN_TLS_CA", "keys/tls/ca.crt")
			tlsInsecure := strings.EqualFold(os.Getenv("ELECTRICIAN_TLS_INSECURE"), "true")

			useSnappy := strings.EqualFold(os.Getenv("ELECTRICIAN_COMPRESS"), "snappy")
			useAESGCM := strings.EqualFold(os.Getenv("ELECTRICIAN_ENCRYPT"), "aesgcm")

			var aesKey string
			if useAESGCM {
				k := strings.TrimSpace(os.Getenv("ELECTRICIAN_AES256_KEY_HEX"))
				rawKey, err := hex.DecodeString(k)
				if err != nil || len(rawKey) != 32 {
					return nil, fmt.Errorf("ELECTRICIAN_AES256_KEY_HEX must be 64 hex chars (32 bytes): %w", err)
				}
				aesKey = string(rawKey)
			}

			staticHeaders := parseKV(os.Getenv("ELECTRICIAN_STATIC_HEADERS"))

			oauthIssuer := strings.TrimSpace(os.Getenv("OAUTH_ISSUER_BASE"))
			oauthJWKS := strings.TrimSpace(os.Getenv("OAUTH_JWKS_URL"))
			oauthClientID := strings.TrimSpace(os.Getenv("OAUTH_CLIENT_ID"))
			oauthSecret := strings.TrimSpace(os.Getenv("OAUTH_CLIENT_SECRET"))
			oauthScopes := splitCSV(os.Getenv("OAUTH_SCOPES"))
			oauthLeeway := parseDur(envOr("OAUTH_REFRESH_LEEWAY", "20s"))
			oauthEnabled := oauthIssuer != "" && oauthClientID != "" && oauthSecret != ""

			logger := builder.NewLogger(builder.LoggerWithDevelopment(true))
			ctx = context.Background()

			// Wire[T]
			wire := builder.NewWire[T](ctx, builder.WireWithLogger[T](logger))

			// Options
			perf := builder.NewPerformanceOptions(useSnappy, builder.COMPRESS_SNAPPY)
			sec := builder.NewSecurityOptions(useAESGCM, builder.ENCRYPTION_AES_GCM)
			tlsCfg := builder.NewTlsClientConfig(useTLS, tlsCrt, tlsKey, tlsCA, tls.VersionTLS13, tls.VersionTLS13)

			targets := strings.Split(strings.TrimSpace(os.Getenv("ELECTRICIAN_TARGET")), ",")

			var start func(context.Context) error
			if oauthEnabled {
				authOpts := builder.NewForwardRelayAuthenticationOptionsOAuth2(nil)
				if oauthJWKS != "" {
					authOpts = builder.NewForwardRelayAuthenticationOptionsOAuth2(
						builder.NewForwardRelayOAuth2JWTOptions(oauthIssuer, oauthJWKS, []string{}, oauthScopes, 300),
					)
				}
				authHTTP := &http.Client{
					Timeout: 10 * time.Second,
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{
							MinVersion:         tls.VersionTLS13,
							MaxVersion:         tls.VersionTLS13,
							InsecureSkipVerify: tlsInsecure, // dev only
						},
					},
				}
				ts := builder.NewForwardRelayRefreshingClientCredentialsSource(
					oauthIssuer, oauthClientID, oauthSecret, oauthScopes, oauthLeeway, authHTTP,
				)

				relay := builder.NewForwardRelay[T](
					ctx,
					builder.ForwardRelayWithLogger[T](logger),
					builder.ForwardRelayWithTarget[T](targets...),
					builder.ForwardRelayWithPerformanceOptions[T](perf),
					builder.ForwardRelayWithSecurityOptions[T](sec, aesKey),
					builder.ForwardRelayWithTLSConfig[T](tlsCfg),
					builder.ForwardRelayWithStaticHeaders[T](staticHeaders),
					builder.ForwardRelayWithAuthenticationOptions[T](authOpts),
					builder.ForwardRelayWithOAuthBearer[T](ts),
					builder.ForwardRelayWithInput(wire),
				)
				start = relay.Start
			} else {
				relay := builder.NewForwardRelay[T](
					ctx,
					builder.ForwardRelayWithLogger[T](logger),
					builder.ForwardRelayWithTarget[T](targets...),
					builder.ForwardRelayWithPerformanceOptions[T](perf),
					builder.ForwardRelayWithSecurityOptions[T](sec, aesKey),
					builder.ForwardRelayWithTLSConfig[T](tlsCfg),
					builder.ForwardRelayWithStaticHeaders[T](staticHeaders),
					builder.ForwardRelayWithInput(wire),
				)
				start = relay.Start
			}

			if err := wire.Start(ctx); err != nil {
				return nil, fmt.Errorf("wire start: %w", err)
			}
			if err := start(ctx); err != nil {
				return nil, fmt.Errorf("relay start: %w", err)
			}

			// Submitter; allow []byte convenience
			return func(ctx context.Context, v any) error {
				if tv, ok := v.(T); ok {
					return wire.Submit(ctx, tv)
				}
				if b, ok := v.([]byte); ok {
					var tmp T
					if err := json.Unmarshal(b, &tmp); err != nil {
						return fmt.Errorf("decode %q: %w", typeName, err)
					}
					return wire.Submit(ctx, tmp)
				}
				return fmt.Errorf("typed submit %q: unexpected value type", typeName)
			}, nil
		}
	}

	// Receiver starter (used by server.go manifest boot)
	if _, exists := rcvReg[typeName]; !exists {
		rcvReg[typeName] = func(ctx context.Context, address string, buffer int, names []string) (func(), error) {
			// Resolve concrete transformers for T in requested order.
			tfs, err := transform.Resolve[T](typeName, names)
			if err != nil {
				return nil, err
			}
			// Adapt to []func(T) (T, error)
			fns := make([]func(T) (T, error), len(tfs))
			for i := range tfs {
				tf := tfs[i]
				fns[i] = func(v T) (T, error) { return tf(v) }
			}
			return StartReceiverForwardFromEnv[T](ctx, address, buffer, fns...)
		}
	}
}

// NewTypedPublisherFromEnv returns a publisher instance with lazy builders.
// In server wiring, expose it to Fx as hermes.TypedPublisher using fx.As.
func NewTypedPublisherFromEnv() (*typedPublisher, error) {
	// If no targets configured, return nil so the router falls back to byte-level publish.
	if strings.TrimSpace(os.Getenv("ELECTRICIAN_TARGET")) == "" {
		return nil, nil
	}
	return &typedPublisher{
		submitters: map[string]func(context.Context, any) error{},
	}, nil
}

// StartReceiverForwardFromEnvByName is used by server.go to start receivers generically.
func StartReceiverForwardFromEnvByName(
	ctx context.Context,
	address string,
	buffer int,
	datatype string,
	transformerNames []string,
) (func(), error) {
	mu.RLock()
	mk, ok := rcvReg[datatype]
	mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("datatype not enabled: %s", datatype)
	}
	return mk(ctx, address, buffer, transformerNames)
}
