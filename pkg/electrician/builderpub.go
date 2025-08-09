// pkg/electrician/builderpub.go
package electrician

// Publish-only RelayClient implemented with Electrician builder primitives.
// Internals are hidden: no builder.* types are stored on the struct.
// Adds optional TLS, compression, encryption, static headers, and OAuth2 CC.

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/joeydtaylor/electrician/pkg/builder"
	"github.com/joeydtaylor/hermes/hermes"
)

type builderClient struct {
	once   sync.Once
	start  error
	submit func(context.Context, []byte) error // captures wire.Submit
}

// NewBuilderRelayFromEnv returns a publish-capable hermes.RelayClient
// powered by Electrician's ForwardRelay[[]byte]. It expects:
//
//	ELECTRICIAN_TARGET          = "host:port[,host2:port2]"   (required)
//
// Optional features (all off by default):
//
//	ELECTRICIAN_TLS_ENABLE      = "true" | "false"
//	ELECTRICIAN_TLS_CLIENT_CRT  = path (default: keys/tls/client.crt)
//	ELECTRICIAN_TLS_CLIENT_KEY  = path (default: keys/tls/client.key)
//	ELECTRICIAN_TLS_CA          = path (default: keys/tls/ca.crt)
//	ELECTRICIAN_TLS_INSECURE    = "true" | "false"  (dev only; for OAuth HTTP client)
//
//	ELECTRICIAN_COMPRESS        = "snappy" | ""     (snappy enabled when "snappy")
//	ELECTRICIAN_ENCRYPT         = "aesgcm" | ""     (AES-GCM when "aesgcm")
//	ELECTRICIAN_AES256_KEY_HEX  = 64 hex chars (32 bytes)
//
//	ELECTRICIAN_STATIC_HEADERS  = "k=v,k2=v2"
//
// OAuth2 client credentials (optional; all must be set to enable):
//
//	OAUTH_ISSUER_BASE           = "https://issuer.example"
//	OAUTH_JWKS_URL              = "https://issuer.example/.well-known/jwks.json" (optional; for receiver hints)
//	OAUTH_CLIENT_ID             = "client-id"
//	OAUTH_CLIENT_SECRET         = "client-secret"
//	OAUTH_SCOPES                = "s1,s2"
//	OAUTH_REFRESH_LEEWAY        = "20s" (optional; default 20s)
//
// If ELECTRICIAN_TARGET is absent, it returns hermes.NoopRelay{}.
func NewBuilderRelayFromEnv() (hermes.RelayClient, error) {
	raw := strings.TrimSpace(os.Getenv("ELECTRICIAN_TARGET"))
	if raw == "" {
		return hermes.NoopRelay{}, nil
	}
	targets := strings.Split(raw, ",")

	// --- Feature toggles / inputs from env ---
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

	// Build internals (not stored on the struct; captured by closures).
	ctx := context.Background()
	wire := builder.NewWire[[]byte](ctx, builder.WireWithLogger[[]byte](logger))

	// Always-construct options with on/off flags where supported.
	perf := builder.NewPerformanceOptions(useSnappy, builder.COMPRESS_SNAPPY)
	sec := builder.NewSecurityOptions(useAESGCM, builder.ENCRYPTION_AES_GCM)
	tlsCfg := builder.NewTlsClientConfig(
		useTLS,
		tlsCrt, tlsKey, tlsCA,
		tls.VersionTLS13, tls.VersionTLS13,
	)

	// Construct relay with/without OAuth2 bearer as the only conditional branch.
	var relayStart func(context.Context) error

	if oauthEnabled {
		// Build auth options (use concrete type, not interface).
		var authOpts = builder.NewForwardRelayAuthenticationOptionsOAuth2(nil)
		if oauthJWKS != "" {
			authOpts = builder.NewForwardRelayAuthenticationOptionsOAuth2(
				builder.NewForwardRelayOAuth2JWTOptions(oauthIssuer, oauthJWKS, []string{}, oauthScopes, 300),
			)
		}

		// HTTP client for token fetch (TLS1.3; optional insecure for local).
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

		relay := builder.NewForwardRelay[[]byte](
			ctx,
			builder.ForwardRelayWithLogger[[]byte](logger),
			builder.ForwardRelayWithTarget[[]byte](targets...),
			builder.ForwardRelayWithPerformanceOptions[[]byte](perf),
			builder.ForwardRelayWithSecurityOptions[[]byte](sec, aesKey),
			builder.ForwardRelayWithTLSConfig[[]byte](tlsCfg),
			builder.ForwardRelayWithStaticHeaders[[]byte](staticHeaders),
			builder.ForwardRelayWithAuthenticationOptions[[]byte](authOpts),
			builder.ForwardRelayWithOAuthBearer[[]byte](ts),
			builder.ForwardRelayWithInput(wire),
		)
		relayStart = relay.Start
	} else {
		relay := builder.NewForwardRelay[[]byte](
			ctx,
			builder.ForwardRelayWithLogger[[]byte](logger),
			builder.ForwardRelayWithTarget[[]byte](targets...),
			builder.ForwardRelayWithPerformanceOptions[[]byte](perf),
			builder.ForwardRelayWithSecurityOptions[[]byte](sec, aesKey),
			builder.ForwardRelayWithTLSConfig[[]byte](tlsCfg),
			builder.ForwardRelayWithStaticHeaders[[]byte](staticHeaders),
			builder.ForwardRelayWithInput(wire),
		)
		relayStart = relay.Start
	}

	c := &builderClient{
		submit: func(ctx context.Context, b []byte) error { return wire.Submit(ctx, b) },
	}
	c.once.Do(func() {
		if err := wire.Start(ctx); err != nil {
			c.start = fmt.Errorf("builder wire start: %w", err)
			return
		}
		if err := relayStart(ctx); err != nil {
			c.start = fmt.Errorf("builder relay start: %w", err)
			return
		}
	})
	if c.start != nil {
		return nil, c.start
	}
	return c, nil
}

// Request is unsupported in builder mode (stream/publish only).
func (c *builderClient) Request(ctx context.Context, rr hermes.RelayRequest) ([]byte, error) {
	return nil, fmt.Errorf("electrician(builder): request/reply unsupported")
}

// Publish sends bytes into the pipeline. Topic/headers ride the relay path.
func (c *builderClient) Publish(ctx context.Context, rr hermes.RelayRequest) error {
	if rr.Topic == "" {
		return fmt.Errorf("relay: missing topic")
	}
	if c.start != nil {
		return c.start
	}
	return c.submit(ctx, rr.Body)
}

// --- small helpers ---

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func parseKV(s string) map[string]string {
	if s == "" {
		return nil
	}
	out := map[string]string{}
	for _, kv := range strings.Split(s, ",") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		p := strings.SplitN(kv, "=", 2)
		if len(p) == 2 {
			out[strings.TrimSpace(p[0])] = strings.TrimSpace(p[1])
		}
	}
	return out
}
