package electrician

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/joeydtaylor/electrician/pkg/builder"
)

// StartReceiverForwardFromEnv wires: ReceivingRelay[T] -> Wire[T]{transforms...} -> ForwardRelay[T].
//
// Forward env (same contract as NewBuilderRelayFromEnv):
//
//	ELECTRICIAN_TARGET, ELECTRICIAN_TLS_ENABLE, ELECTRICIAN_TLS_CLIENT_CRT, ELECTRICIAN_TLS_CLIENT_KEY, ELECTRICIAN_TLS_CA
//	ELECTRICIAN_TLS_INSECURE, ELECTRICIAN_COMPRESS, ELECTRICIAN_ENCRYPT, ELECTRICIAN_AES256_KEY_HEX
//	ELECTRICIAN_STATIC_HEADERS, OAUTH_ISSUER_BASE, OAUTH_JWKS_URL, OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET, OAUTH_SCOPES, OAUTH_REFRESH_LEEWAY
//
// Receive env:
//
//	ELECTRICIAN_RX_TLS_ENABLE, ELECTRICIAN_RX_TLS_SERVER_CRT, ELECTRICIAN_RX_TLS_SERVER_KEY, ELECTRICIAN_RX_TLS_CA, ELECTRICIAN_RX_TLS_SERVER_NAME
//	OAUTH_JWKS_URL, OAUTH_ISSUER_BASE, OAUTH_REQUIRED_AUD, OAUTH_SCOPES,
//	OAUTH_INTROSPECT_URL, OAUTH_INTROSPECT_AUTH, OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET, OAUTH_INTROSPECT_BEARER
func StartReceiverForwardFromEnv[T any](ctx context.Context, address string, buffer int, transforms ...func(T) (T, error)) (stop func(), err error) {
	if strings.TrimSpace(address) == "" {
		return nil, errors.New("receiver: address required")
	}
	if buffer <= 0 {
		buffer = 1024
	}

	logger := builder.NewLogger(builder.LoggerWithDevelopment(true))

	// Composite transformer
	composite := func(v T) (T, error) {
		cur := v
		for _, fn := range transforms {
			var err error
			cur, err = fn(cur)
			if err != nil {
				return cur, err
			}
		}
		return cur, nil
	}

	// ---- Wire
	wire := builder.NewWire[T](
		ctx,
		builder.WireWithLogger[T](logger),
		builder.WireWithTransformer[T](composite),
	)

	// =======================
	// Forward hop (publisher)
	// =======================
	targets := splitCSV(os.Getenv("ELECTRICIAN_TARGET"))
	useTLS := strings.EqualFold(os.Getenv("ELECTRICIAN_TLS_ENABLE"), "true")
	tlsCrt := envOr("ELECTRICIAN_TLS_CLIENT_CRT", "keys/tls/client.crt")
	tlsKey := envOr("ELECTRICIAN_TLS_CLIENT_KEY", "keys/tls/client.key")
	tlsCA := envOr("ELECTRICIAN_TLS_CA", "keys/tls/ca.crt")
	tlsInsecure := strings.EqualFold(os.Getenv("ELECTRICIAN_TLS_INSECURE"), "true")

	useSnappy := strings.EqualFold(os.Getenv("ELECTRICIAN_COMPRESS"), "snappy")
	useAESGCM := strings.EqualFold(os.Getenv("ELECTRICIAN_ENCRYPT"), "aesgcm")
	var fwdAES string
	if useAESGCM {
		k := strings.TrimSpace(os.Getenv("ELECTRICIAN_AES256_KEY_HEX"))
		raw, e := hex.DecodeString(k)
		if e != nil || len(raw) != 32 {
			return nil, errors.New("forward: ELECTRICIAN_AES256_KEY_HEX must be 64 hex chars (32 bytes)")
		}
		fwdAES = string(raw)
	}

	staticHeaders := parseKV(os.Getenv("ELECTRICIAN_STATIC_HEADERS"))

	issuer := strings.TrimSpace(os.Getenv("OAUTH_ISSUER_BASE"))
	jwksURL := strings.TrimSpace(os.Getenv("OAUTH_JWKS_URL"))
	clientID := strings.TrimSpace(os.Getenv("OAUTH_CLIENT_ID"))
	clientSecret := strings.TrimSpace(os.Getenv("OAUTH_CLIENT_SECRET"))
	scopes := splitCSV(os.Getenv("OAUTH_SCOPES"))
	leeway := parseDur(envOr("OAUTH_REFRESH_LEEWAY", "20s"))
	oauthEnabled := issuer != "" && clientID != "" && clientSecret != ""

	perf := builder.NewPerformanceOptions(useSnappy, builder.COMPRESS_SNAPPY)
	sec := builder.NewSecurityOptions(useAESGCM, builder.ENCRYPTION_AES_GCM)
	tlsCli := builder.NewTlsClientConfig(useTLS, tlsCrt, tlsKey, tlsCA, tls.VersionTLS13, tls.VersionTLS13)

	var forwardStart func(context.Context) error
	var forwardStop func()

	if oauthEnabled {
		authOpts := builder.NewForwardRelayAuthenticationOptionsOAuth2(nil)
		if jwksURL != "" {
			authOpts = builder.NewForwardRelayAuthenticationOptionsOAuth2(
				builder.NewForwardRelayOAuth2JWTOptions(issuer, jwksURL, splitCSV(os.Getenv("OAUTH_REQUIRED_AUD")), scopes, 300),
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

		// --- NEW: preflight token warmup before starting the forward relay ---
		// This avoids noisy startup ERRORs if the token endpoint is briefly unavailable.
		preflightTimeout := parseDur(envOr("OAUTH_PREFLIGHT_TIMEOUT", "8s"))
		_ = preflightOAuthToken(ctx, authHTTP, issuer, clientID, clientSecret, scopes, preflightTimeout)

		ts := builder.NewForwardRelayRefreshingClientCredentialsSource(issuer, clientID, clientSecret, scopes, leeway, authHTTP)

		f := builder.NewForwardRelay[T](
			ctx,
			builder.ForwardRelayWithLogger[T](logger),
			builder.ForwardRelayWithTarget[T](targets...),
			builder.ForwardRelayWithPerformanceOptions[T](perf),
			builder.ForwardRelayWithSecurityOptions[T](sec, fwdAES),
			builder.ForwardRelayWithTLSConfig[T](tlsCli),
			builder.ForwardRelayWithStaticHeaders[T](staticHeaders),
			builder.ForwardRelayWithAuthenticationOptions[T](authOpts),
			builder.ForwardRelayWithOAuthBearer[T](ts),
			builder.ForwardRelayWithInput(wire),
		)
		forwardStart, forwardStop = f.Start, f.Stop
	} else {
		f := builder.NewForwardRelay[T](
			ctx,
			builder.ForwardRelayWithLogger[T](logger),
			builder.ForwardRelayWithTarget[T](targets...),
			builder.ForwardRelayWithPerformanceOptions[T](perf),
			builder.ForwardRelayWithSecurityOptions[T](sec, fwdAES),
			builder.ForwardRelayWithTLSConfig[T](tlsCli),
			builder.ForwardRelayWithStaticHeaders[T](staticHeaders),
			builder.ForwardRelayWithInput(wire),
		)
		forwardStart, forwardStop = f.Start, f.Stop
	}

	// ====================
	// Receive hop (server)
	// ====================
	rxTLSEnable := strings.EqualFold(os.Getenv("ELECTRICIAN_RX_TLS_ENABLE"), "true")
	rxCrt := envOr("ELECTRICIAN_RX_TLS_SERVER_CRT", "keys/tls/server.crt")
	rxKey := envOr("ELECTRICIAN_RX_TLS_SERVER_KEY", "keys/tls/server.key")
	rxCA := envOr("ELECTRICIAN_RX_TLS_CA", "keys/tls/ca.crt")
	rxName := os.Getenv("ELECTRICIAN_RX_TLS_SERVER_NAME")

	tlsSrv := builder.NewTlsServerConfig(
		rxTLSEnable,
		rxCrt, rxKey, rxCA, rxName,
		tls.VersionTLS13, tls.VersionTLS13,
	)

	decKey := ""
	if k := strings.TrimSpace(os.Getenv("ELECTRICIAN_AES256_KEY_HEX")); k != "" {
		raw, e := hex.DecodeString(k)
		if e != nil || len(raw) != 32 {
			return nil, errors.New("receiver: ELECTRICIAN_AES256_KEY_HEX must be 64 hex chars (32 bytes)")
		}
		decKey = string(raw)
	}

	// Receiver OAuth2: build concrete opts inline to keep pointer types
	var receiverStart func(context.Context) error
	var receiverStop func()
	{
		jwks := strings.TrimSpace(os.Getenv("OAUTH_JWKS_URL"))
		introspectURL := strings.TrimSpace(os.Getenv("OAUTH_INTROSPECT_URL"))

		switch {
		case jwks != "" && introspectURL != "":
			oauth := builder.NewReceivingRelayMergeOAuth2Options(
				builder.NewReceivingRelayOAuth2JWTOptions(
					issuer,
					jwks,
					splitCSV(os.Getenv("OAUTH_REQUIRED_AUD")),
					scopes,
					300,
				),
				builder.NewReceivingRelayOAuth2IntrospectionOptions(
					introspectURL,
					envOr("OAUTH_INTROSPECT_AUTH", "basic"),
					clientID,
					clientSecret,
					os.Getenv("OAUTH_INTROSPECT_BEARER"),
					300,
				),
			)
			auth := builder.NewReceivingRelayAuthenticationOptionsOAuth2(oauth)

			rx := builder.NewReceivingRelay[T](
				ctx,
				builder.ReceivingRelayWithAddress[T](address),
				builder.ReceivingRelayWithBufferSize[T](uint32(buffer)),
				builder.ReceivingRelayWithLogger[T](logger),
				builder.ReceivingRelayWithOutput(wire),
				builder.ReceivingRelayWithTLSConfig[T](tlsSrv),
				builder.ReceivingRelayWithDecryptionKey[T](decKey),
				builder.ReceivingRelayWithAuthenticationOptions[T](auth),
			)
			receiverStart, receiverStop = rx.Start, rx.Stop

		case jwks != "":
			oauth := builder.NewReceivingRelayMergeOAuth2Options(
				builder.NewReceivingRelayOAuth2JWTOptions(
					issuer,
					jwks,
					splitCSV(os.Getenv("OAUTH_REQUIRED_AUD")),
					scopes,
					300,
				),
				nil,
			)
			auth := builder.NewReceivingRelayAuthenticationOptionsOAuth2(oauth)

			rx := builder.NewReceivingRelay[T](
				ctx,
				builder.ReceivingRelayWithAddress[T](address),
				builder.ReceivingRelayWithBufferSize[T](uint32(buffer)),
				builder.ReceivingRelayWithLogger[T](logger),
				builder.ReceivingRelayWithOutput(wire),
				builder.ReceivingRelayWithTLSConfig[T](tlsSrv),
				builder.ReceivingRelayWithDecryptionKey[T](decKey),
				builder.ReceivingRelayWithAuthenticationOptions[T](auth),
			)
			receiverStart, receiverStop = rx.Start, rx.Stop

		case introspectURL != "":
			oauth := builder.NewReceivingRelayMergeOAuth2Options(
				nil,
				builder.NewReceivingRelayOAuth2IntrospectionOptions(
					introspectURL,
					envOr("OAUTH_INTROSPECT_AUTH", "basic"),
					clientID,
					clientSecret,
					os.Getenv("OAUTH_INTROSPECT_BEARER"),
					300,
				),
			)
			auth := builder.NewReceivingRelayAuthenticationOptionsOAuth2(oauth)

			rx := builder.NewReceivingRelay[T](
				ctx,
				builder.ReceivingRelayWithAddress[T](address),
				builder.ReceivingRelayWithBufferSize[T](uint32(buffer)),
				builder.ReceivingRelayWithLogger[T](logger),
				builder.ReceivingRelayWithOutput(wire),
				builder.ReceivingRelayWithTLSConfig[T](tlsSrv),
				builder.ReceivingRelayWithDecryptionKey[T](decKey),
				builder.ReceivingRelayWithAuthenticationOptions[T](auth),
			)
			receiverStart, receiverStop = rx.Start, rx.Stop

		default:
			// No OAuth on receiver
			rx := builder.NewReceivingRelay[T](
				ctx,
				builder.ReceivingRelayWithAddress[T](address),
				builder.ReceivingRelayWithBufferSize[T](uint32(buffer)),
				builder.ReceivingRelayWithLogger[T](logger),
				builder.ReceivingRelayWithOutput(wire),
				builder.ReceivingRelayWithTLSConfig[T](tlsSrv),
				builder.ReceivingRelayWithDecryptionKey[T](decKey),
			)
			receiverStart, receiverStop = rx.Start, rx.Stop
		}
	}

	// Start: wire -> forward -> receiver
	if err := wire.Start(ctx); err != nil {
		return nil, err
	}
	if err := forwardStart(ctx); err != nil {
		return nil, err
	}
	if err := receiverStart(ctx); err != nil {
		return nil, err
	}

	// Stop in reverse
	return func() {
		receiverStop()
		forwardStop()
		wire.Stop()
	}, nil
}

// -----------------------
// Helpers (preflight etc)
// -----------------------

func preflightOAuthToken(ctx context.Context, hc *http.Client, issuer, clientID, clientSecret string, scopes []string, total time.Duration) error {
	// Nothing to do if obviously misconfigured
	if issuer == "" || clientID == "" || clientSecret == "" {
		return nil
	}

	tokenURL := strings.TrimRight(issuer, "/") + "/api/auth/oauth/token"
	// Basic sanity
	if _, err := url.Parse(tokenURL); err != nil {
		return nil // don't block startup on a bad parse; forward relay will surface config errors
	}

	// Backoff: 250ms -> 500ms -> 1s -> 2s ... until total budget is spent
	deadline := time.Now().Add(total)
	sleep := 250 * time.Millisecond

	for {
		// Respect ctx and budget
		if time.Now().After(deadline) || ctx.Err() != nil {
			return ctx.Err()
		}

		reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		form := url.Values{}
		form.Set("grant_type", "client_credentials")
		if len(scopes) > 0 {
			form.Set("scope", strings.Join(scopes, " "))
		}
		form.Set("client_id", clientID)
		form.Set("client_secret", clientSecret)

		req, _ := http.NewRequestWithContext(reqCtx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := hc.Do(req)
		cancel()

		if err == nil && resp != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				// Success: token endpoint is responsive; good to start the forward relay
				return nil
			}
		}

		// Not ready yet; wait and retry until budget is gone
		time.Sleep(sleep)
		// cap the backoff around 2s to keep preflight snappy
		if sleep < 2*time.Second {
			sleep *= 2
		}
	}
}
