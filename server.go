// server.go
package main

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/joeydtaylor/hermes/app/handlers"
	"github.com/joeydtaylor/hermes/app/types"
	"github.com/joeydtaylor/hermes/hermes"
	"github.com/joeydtaylor/hermes/middleware/auth"
	"github.com/joeydtaylor/hermes/middleware/logger"
	"github.com/joeydtaylor/hermes/middleware/metrics"
	"github.com/joeydtaylor/hermes/transport/httpx"
	"github.com/joho/godotenv"
	"go.uber.org/fx"
	"go.uber.org/zap"

	// Electrician adapters (forward relay / typed publisher)
	"github.com/joeydtaylor/hermes/pkg/electrician"
)

// ---- Adapter: electrician.RelayClient -> hermes.RelayClient ----

type relayAdapter struct {
	inner electrician.RelayClient
}

func (a relayAdapter) Request(ctx context.Context, rr hermes.RelayRequest) ([]byte, error) {
	return a.inner.Request(ctx, electrician.RelayRequest{
		Topic:   rr.Topic,
		Body:    rr.Body,
		Headers: rr.Headers,
	})
}

func (a relayAdapter) Publish(ctx context.Context, rr hermes.RelayRequest) error {
	return a.inner.Publish(ctx, electrician.RelayRequest{
		Topic:   rr.Topic,
		Body:    rr.Body,
		Headers: rr.Headers,
	})
}

// Provide a hermes.RelayClient by constructing the electrician client and wrapping it.
func provideRelayForHermes() (hermes.RelayClient, error) {
	ec, err := electrician.NewBuilderRelayFromEnv()
	if err != nil {
		return nil, err
	}
	if ec == nil {
		// no targets => noop; propagate nil so router can still boot
		return nil, nil
	}
	return relayAdapter{inner: ec}, nil
}

func provideRouter(
	a auth.Middleware,
	lm logger.Middleware,
	/* name:"metrics" */ m http.Handler,
	typed hermes.TypedPublisher,
	rel hermes.RelayClient,
	r httpx.Router,
	zl *zap.Logger,
) http.Handler {
	cfg, err := hermes.LoadConfig(envOr("HERMES_MANIFEST", "manifest.toml"))
	if err != nil {
		log.Fatalf("manifest load: %v", err)
	}

	// If the manifest has any relay.publish handlers, ensure RelayClient is present.
	needsRelay := false
	for _, rt := range cfg.Routes {
		if rt.Handler.Type == hermes.HandlerType("relay.publish") {
			needsRelay = true
			break
		}
	}
	if needsRelay && rel == nil {
		zl.Error("relay.publish configured but no RelayClient",
			zap.String("ELECTRICIAN_TARGET", os.Getenv("ELECTRICIAN_TARGET")),
			zap.String("OAUTH_ISSUER_BASE", os.Getenv("OAUTH_ISSUER_BASE")),
			zap.String("OAUTH_CLIENT_ID", os.Getenv("OAUTH_CLIENT_ID")),
			// don't log secrets
		)
		// If you want fail-fast here, flip to Fatal:
		// zl.Fatal("relay client missing; check ELECTRICIAN_TARGET and OAUTH_* env")
	}

	return hermes.BuildRouter(cfg, hermes.BuildDeps{
		Auth:    a,
		LogMW:   lm,
		Metrics: m,
		Relay:   rel,
		Typed:   typed,
		Router:  r,
	})
}

type serverDeps struct {
	fx.In
	Logger *zap.Logger
	App    http.Handler `name:"app"`
}

func registerHooks(lc fx.Lifecycle, d serverDeps) {
	addr := envOr("SERVER_LISTEN_ADDRESS", ":4000")
	cert := os.Getenv("SSL_SERVER_CERTIFICATE")
	key := os.Getenv("SSL_SERVER_KEY")

	srv := &http.Server{
		Addr:         addr,
		Handler:      d.App,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
		// default to TLS1.3; cleared below if serving plaintext
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13},
	}
	useTLS := fileExists(cert) && fileExists(key)

	// Load manifest once to boot any receivers.
	cfgPath := envOr("HERMES_MANIFEST", "manifest.toml")
	cfg, err := hermes.LoadConfig(cfgPath)
	if err != nil {
		d.Logger.Fatal("manifest load failed", zap.Error(err), zap.String("path", cfgPath))
	}

	recvCtx, recvCancel := context.WithCancel(context.Background())

	lc.Append(fx.Hook{
		OnStart: func(context.Context) error {
			// Boot receivers defined in manifest (non-blocking per receiver + pipeline).
			go func() {
				for _, rc := range cfg.Receivers {
					buf := rc.BufferSize
					if buf <= 0 {
						buf = 1024
					}
					for _, pl := range rc.Pipeline {
						datatype := pl.DataType
						names := append([]string(nil), pl.Transformers...)

						go func(address string, buffer int, dt string, tnames []string) {
							stop, err := electrician.StartReceiverForwardFromEnvByName(
								recvCtx, address, buffer, dt, tnames,
							)
							if err != nil {
								d.Logger.Error("receiver start failed",
									zap.String("address", address),
									zap.String("datatype", dt),
									zap.Strings("transformers", tnames),
									zap.Error(err),
								)
								return
							}
							d.Logger.Info("receiver started",
								zap.String("address", address),
								zap.String("datatype", dt),
								zap.Strings("transformers", tnames),
							)
							go func() {
								<-recvCtx.Done()
								if stop != nil {
									stop()
								}
							}()
						}(rc.Address, buf, datatype, names)
					}
				}
			}()

			// Start HTTP server.
			if useTLS {
				d.Logger.Info("server starting (TLS)", zap.String("addr", addr), zap.String("cert", cert))
				go func() {
					if err := srv.ListenAndServeTLS(cert, key); err != nil && err != http.ErrServerClosed {
						d.Logger.Fatal("server failed", zap.Error(err))
					}
				}()
			} else {
				d.Logger.Info("server starting (PLAINTEXT)", zap.String("addr", addr))
				go func() {
					// Clear TLS when serving plaintext.
					srv.TLSConfig = nil
					if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
						d.Logger.Fatal("server failed", zap.Error(err))
					}
				}()
			}
			return nil
		},
		OnStop: func(ctx context.Context) error {
			d.Logger.Info("server stopping")
			recvCancel()
			return srv.Shutdown(ctx)
		},
	})
}

func fileExists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	_ = godotenv.Load()
	if os.Getenv("HERMES_MANIFEST") == "" {
		os.Setenv("HERMES_MANIFEST", "manifest.toml")
	}

	fx.New(
		// Middleware modules
		auth.Module,
		logger.Module,

		// Metrics (named)
		fx.Provide(fx.Annotate(metrics.ProvideMetrics, fx.ResultTags(`name:"metrics"`))),

		// Router implementation
		fx.Provide(httpx.NewChi),

		// Electrician publish path:
		// - typed publisher (adapts to hermes.TypedPublisher)
		fx.Provide(
			fx.Annotate(
				electrician.NewTypedPublisherFromEnv,
				fx.As(new(hermes.TypedPublisher)),
			),
		),
		// - byte relay client (wrap electrician client into hermes interface)
		fx.Provide(provideRelayForHermes),

		// Register user datatypes + transformers BEFORE router/receivers boot
		fx.Invoke(types.RegisterAll),
		fx.Invoke(handlers.Register),

		// Router
		fx.Provide(
			fx.Annotate(
				provideRouter,
				// Param tags for: a, lm, m(name:"metrics"), typed, rel, r, zl
				fx.ParamTags(``, ``, `name:"metrics"`, ``, ``, ``, ``),
				fx.ResultTags(`name:"app"`),
			),
		),

		// App lifecycle (starts receivers + HTTP server)
		fx.Invoke(registerHooks),
	).Run()
}
