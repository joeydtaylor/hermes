// request_logger.go
package logger

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	chimd "github.com/go-chi/chi/v5/middleware"
	"github.com/joeydtaylor/hermes/middleware/auth"
	"github.com/joeydtaylor/hermes/utils"
	"go.uber.org/fx"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

type Middleware struct{}

func ProvideLoggerMiddleware() Middleware { return Middleware{} }
func ProvideLogger() *zap.Logger          { return NewLog("system.log") }

// package-level singleton for access logs
var httpAccessLogger = NewLog("http-access.log")

func ensureLogDir() string {
	dir := "log"
	_ = os.MkdirAll(dir, 0o755)
	return dir
}

func NewLog(n string) *zap.Logger {
	_ = ensureLogDir()

	cfg := zap.NewProductionEncoderConfig()
	cfg.MessageKey = zapcore.OmitKey

	console := zapcore.Lock(os.Stdout)

	var logPath string
	if runtime.GOOS == "windows" {
		logPath = filepath.Join("log", n)
	} else {
		logPath = fmt.Sprintf("%s/%s", "log", n)
	}

	w := zapcore.AddSync(&lumberjack.Logger{
		Filename:   logPath,
		MaxSize:    50, // MB
		MaxBackups: 3,
		MaxAge:     7, // days
	})

	core := zapcore.NewTee(
		zapcore.NewCore(zapcore.NewJSONEncoder(cfg), w, zap.InfoLevel),
		zapcore.NewCore(zapcore.NewJSONEncoder(cfg), console, zap.InfoLevel),
	)
	return zap.New(core)
}

func (Middleware) Middleware(ca auth.Middleware) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			l := httpAccessLogger

			// Wrap writer
			ww := utils.NewWrapResponseWriter(w, r.ProtoMajor)

			// Read and RESTORE request body so downstream can consume it
			var body []byte
			if r.Body != nil {
				if b, err := io.ReadAll(r.Body); err == nil {
					body = b
				}
				r.Body.Close()
				r.Body = io.NopCloser(bytes.NewReader(body))
			}

			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}

			start := time.Now()
			defer func() {
				lat := time.Since(start)

				// bounded URI (path only) to avoid metric/log cardinality blowups
				pathOnly := r.URL.Path

				log := l.With(
					zap.String("dateTime", start.UTC().Format(time.RFC1123)),
					zap.String("requestId", chimd.GetReqID(r.Context())),
					zap.String("httpScheme", scheme),
					zap.Bool("isAuthenticated", ca.IsAuthenticated(r.Context())),
					zap.String("username", ca.GetUser(r.Context()).Username),
					zap.String("role", ca.GetUser(r.Context()).Role.Name),
					zap.String("authenticationProvider", ca.GetUser(r.Context()).AuthenticationSource.Provider),
					zap.String("httpProto", r.Proto),
					zap.String("httpMethod", r.Method),
					zap.String("remoteAddr", r.RemoteAddr),
					zap.String("uri", pathOnly),
					zap.Duration("lat", lat),
					zap.Int("responseSize", ww.BytesWritten()),
					zap.Int("status", ww.Status()),
				)

				// Redact by default; allowlist small JSON bodies only.
				if shouldLogBody(r, body) {
					log.Info("", zap.ByteString("requestData", body))
				} else {
					log.Info("")
				}
			}()

			next.ServeHTTP(ww, r)
		})
	}
}

// Only log small JSON request bodies on allowlisted routes.
func shouldLogBody(r *http.Request, body []byte) bool {
	if r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodPatch {
		return false
	}
	if len(body) == 0 || len(body) > 1<<16 { // 64 KiB cap
		return false
	}
	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		return false
	}
	switch r.URL.Path {
	case "/echo", "/feedback": // extend as needed
		return true
	default:
		return false
	}
}

var Module = fx.Options(
	fx.Provide(ProvideLoggerMiddleware),
	fx.Provide(ProvideLogger),
)
