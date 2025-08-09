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
	"github.com/joeydtaylor/hermes/hermes"
)

// Public surface: hermes.TypedPublisher only.
type typedPublisher struct {
	submitters map[string]func(context.Context, any) error
}

func (tp *typedPublisher) Publish(ctx context.Context, topic, typeName string, v any, headers map[string]string) error {
	fn, ok := tp.submitters[typeName]
	if !ok {
		return fmt.Errorf("typed publisher: no submitter for %q", typeName)
	}
	return fn(ctx, v)
}

var (
	mu  sync.RWMutex
	reg = map[string]func(ctx context.Context) (func(context.Context, any) error, error){}
)

// EnableBuilderType wires a generic submitter for T to a type name. Internal registry.
func EnableBuilderType[T any](typeName string) {
	mu.Lock()
	defer mu.Unlock()
	if _, exists := reg[typeName]; exists {
		return
	}
	reg[typeName] = func(ctx context.Context) (func(context.Context, any) error, error) {
		// --- Feature toggles / inputs from env (same contract as byte relay) ---
		rawTargets := strings.TrimSpace(os.Getenv("ELECTRICIAN_TARGET"))
		if rawTargets == "" {
			return func(context.Context, any) error { return nil }, nil // no-op if no targets
		}
		targets := strings.Split(rawTargets, ",")

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

		// Wire[T]
		wire := builder.NewWire[T](ctx, builder.WireWithLogger[T](logger))

		// Options (on/off via flags)
		perf := builder.NewPerformanceOptions(useSnappy, builder.COMPRESS_SNAPPY)
		sec := builder.NewSecurityOptions(useAESGCM, builder.ENCRYPTION_AES_GCM)
		tlsCfg := builder.NewTlsClientConfig(useTLS, tlsCrt, tlsKey, tlsCA, tls.VersionTLS13, tls.VersionTLS13)

		var start func(context.Context) error

		if oauthEnabled {
			// Auth options (use concrete type param; avoid interface in var)
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

// NewTypedPublisherFromEnv builds submitters for enabled types. No targets => nil.
func NewTypedPublisherFromEnv() (hermes.TypedPublisher, error) {
	// If no targets configured, return nil so the router falls back to byte-level publish.
	if strings.TrimSpace(os.Getenv("ELECTRICIAN_TARGET")) == "" {
		return nil, nil
	}

	mu.RLock()
	defer mu.RUnlock()

	out := &typedPublisher{submitters: make(map[string]func(context.Context, any) error, len(reg))}
	ctx := context.Background()
	for name, mk := range reg {
		fn, err := mk(ctx)
		if err != nil {
			return nil, fmt.Errorf("build submitter %q: %w", name, err)
		}
		out.submitters[name] = fn
	}
	return out, nil
}
