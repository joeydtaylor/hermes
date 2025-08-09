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

	// Electrician adapters
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
	addr := envOr("SERVER_LISTEN_ADDRESS", ":8080")
	cert := os.Getenv("SSL_SERVER_CERTIFICATE")
	key := os.Getenv("SSL_SERVER_KEY")

	srv := &http.Server{
		Addr:         addr,
		Handler:      d.App,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
		// lock to TLS 1.3 if we have cert+key
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13},
	}

	useTLS := fileExists(cert) && fileExists(key)

	lc.Append(fx.Hook{
		OnStart: func(context.Context) error {
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
					// disable TLSConfig when serving plaintext to avoid confusion
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

		fx.Provide(electrician.NewTypedPublisherFromEnv),
		fx.Provide(electrician.NewBuilderRelayFromEnv),

		fx.Provide(
			fx.Annotate(
				provideRouter,
				fx.ParamTags(``, ``, `name:"metrics"`, ``, ``, ``),
				fx.ResultTags(`name:"app"`),
			),
		),

		fx.Invoke(handlers.Register),
		fx.Invoke(types.RegisterAll),
		fx.Invoke(registerHooks),
	).Run()
}
