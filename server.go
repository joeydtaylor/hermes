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

func provideRouter(
	a auth.Middleware,
	lm logger.Middleware,
	/* named */ m http.Handler,
	typed hermes.TypedPublisher,
	rel hermes.RelayClient,
	r httpx.Router,
) http.Handler {
	cfg, err := hermes.LoadConfig(envOr("HERMES_MANIFEST", "manifest.toml"))
	if err != nil {
		log.Fatalf("manifest load: %v", err)
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
		// We default to TLS1.3; cleared below if serving plaintext
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
			// Boot receivers defined in manifest (non-blocking per receiver).
			go func() {
				for _, rc := range cfg.Receivers {
					// NOTE: This starts a generic receiver with no transforms.
					// If you want manifest-based transforms, wire them here by datatype.
					addr := rc.Address
					buf := rc.BufferSize
					if buf <= 0 {
						buf = 1024
					}

					// For now, we only start a Feedback receiver to match your manifest/datatype.
					go func(address string, buffer int) {
						stop, err := electrician.StartReceiverForwardFromEnv[types.Feedback](recvCtx, address, buffer /* no transforms for now */)
						if err != nil {
							d.Logger.Error("receiver start failed", zap.String("address", address), zap.Error(err))
							return
						}
						// Ensure we stop this receiver when app stops.
						go func() {
							<-recvCtx.Done()
							if stop != nil {
								stop()
							}
						}()
						d.Logger.Info("receiver started", zap.String("address", address))
					}(addr, buf)
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
		auth.Module,
		logger.Module,

		fx.Provide(fx.Annotate(metrics.ProvideMetrics, fx.ResultTags(`name:"metrics"`))),
		fx.Provide(httpx.NewChi),

		// Forward relay + typed publisher (Electrician)
		fx.Provide(electrician.NewTypedPublisherFromEnv),
		fx.Provide(electrician.NewBuilderRelayFromEnv),

		// Router
		fx.Provide(
			fx.Annotate(
				provideRouter,
				fx.ParamTags(``, ``, `name:"metrics"`, ``, ``, ``),
				fx.ResultTags(`name:"app"`),
			),
		),

		// App registrations + lifecycle
		fx.Invoke(handlers.Register),
		fx.Invoke(types.RegisterAll),
		fx.Invoke(registerHooks),
	).Run()
}
