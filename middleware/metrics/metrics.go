// metrics/metrics.go
package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/middleware"
	"github.com/joeydtaylor/hermes/middleware/auth"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/fx"
)

var (
	responseTime = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "response_time",
			Help:    "http response time.",
			Buckets: []float64{0.5, 1, 5, 10, 30, 60},
		},
	)

	totalHttpRequestsFromRole = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "total_http_requests_from_role", Help: "http requests from role"},
		[]string{"role"},
	)

	totalHttpRequestsToUri = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "total_http_requests_to_uri", Help: "http requests to uri"},
		[]string{"code", "uri", "method"},
	)

	totalHttpRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "total_http_requests", Help: "http requests by code, and method"},
		[]string{"code", "method"},
	)
)

func Collect(ca auth.Middleware) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			startTime := time.Now()

			defer func() {
				endTime := time.Since(startTime)
				if r.URL.Path != "/metrics" {
					role := ca.GetUser(r.Context()).Role.Name
					code := strconv.Itoa(ww.Status())
					uri := r.URL.Path // path only; avoid cardinality explosion
					method := r.Method

					totalHttpRequestsFromRole.WithLabelValues(role).Inc()
					totalHttpRequestsToUri.WithLabelValues(code, uri, method).Inc()
					totalHttpRequests.WithLabelValues(code, method).Inc()
					responseTime.Observe(endTime.Seconds())
				}
			}()

			next.ServeHTTP(ww, r)
		})
	}
}

func NewPromHttpHandler() http.Handler { return promhttp.Handler() }
func ProvideMetrics() http.Handler     { return NewPromHttpHandler() }

func init() {
	prometheus.MustRegister(
		responseTime,
		totalHttpRequestsFromRole,
		totalHttpRequestsToUri,
		totalHttpRequests,
	)
}

var Module = fx.Options(
	fx.Provide(ProvideMetrics),
)
