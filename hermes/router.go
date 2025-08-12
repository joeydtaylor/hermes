// hermes/router.go
package hermes

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"

	chimd "github.com/go-chi/chi/v5/middleware"
	"github.com/joeydtaylor/hermes/hermes/transform"
	"github.com/joeydtaylor/hermes/middleware/auth"
	"github.com/joeydtaylor/hermes/middleware/logger"
	hmetrics "github.com/joeydtaylor/hermes/middleware/metrics"
	httpx "github.com/joeydtaylor/hermes/transport/httpx"
)

type BuildDeps struct {
	Auth    *auth.Middleware
	LogMW   *logger.Middleware
	Metrics http.Handler
	Relay   RelayClient
	Router  httpx.Router
	Typed   TypedPublisher
	Creds   CredentialsProvider
}

// cache env once
var (
	sessionCookieName  = strings.TrimSpace(os.Getenv("SESSION_COOKIE_NAME"))
	staticBearerCached = strings.TrimSpace(os.Getenv("ELECTRICIAN_STATIC_BEARER"))
)

func BuildRouter(cfg Config, d BuildDeps) http.Handler {
	r := d.Router
	r.Use(chimd.RequestID, chimd.Recoverer, chimd.Heartbeat("/ping"))
	if d.Auth != nil {
		r.Use(d.Auth.Middleware())
		if d.LogMW != nil {
			r.Use(d.LogMW.Middleware(d.Auth))
		}
		// metrics collector that references auth state without copying it
		r.Use(hmetrics.Collect(d.Auth))
	} else {
		if d.LogMW != nil {
			r.Use(d.LogMW.Middleware(nil))
		}
	}

	r.Handle(http.MethodGet, "/metrics", d.Metrics)

	for _, rt := range cfg.Routes {
		h := wrapRoute(rt, d)
		if rt.Policy.TimeoutMS > 0 {
			t := time.Duration(rt.Policy.TimeoutMS) * time.Millisecond
			h = withTimeout(h, t)
		}
		h = withGuard(h, d.Auth, rt.Guard)

		switch strings.ToUpper(rt.Method) {
		case http.MethodGet:
			r.Get(rt.Path, h)
		case http.MethodPost:
			r.Post(rt.Path, h)
		case http.MethodPut:
			r.Put(rt.Path, h)
		case http.MethodDelete:
			r.Delete(rt.Path, h)
		default:
			r.Handle(rt.Method, rt.Path, h)
		}
	}
	return r.Mux()
}

func withTimeout(next http.HandlerFunc, d time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), d)
		defer cancel()
		next(w, r.WithContext(ctx))
	}
}

func withGuard(next http.HandlerFunc, a *auth.Middleware, g Guard) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// If no auth middleware wired, only allow when route doesn't require auth
		if a == nil {
			if g.RequireAuth || len(g.Users) > 0 || len(g.Roles) > 0 {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			next(w, r)
			return
		}

		if g.RequireAuth && !a.IsAuthenticated(r.Context()) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if len(g.Users) > 0 {
			u := a.GetUser(r.Context()).Username
			if u == "" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			for _, x := range g.Users {
				if u == x {
					next(w, r)
					return
				}
			}
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if len(g.Roles) > 0 {
			u := a.GetUser(r.Context())
			if u.Username == "" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			if a.IsAdmin(r.Context()) {
				next(w, r)
				return
			}
			for _, x := range g.Roles {
				if u.Role.Name == x {
					next(w, r)
					return
				}
			}
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func wrapRoute(rt Route, d BuildDeps) http.HandlerFunc {
	switch rt.Handler.Type {
	case HandlerInproc:
		h, ok := Lookup(rt.Handler.Name)
		if !ok {
			return func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "handler not found", http.StatusInternalServerError)
			}
		}
		return func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			out, status, err := h(r.Context(), body)
			if err != nil {
				http.Error(w, err.Error(), statusIf(status, http.StatusInternalServerError))
				return
			}
			writeJSON(w, out, statusIf(status, http.StatusOK))
		}

	case HandlerRelayReq:
		return func(w http.ResponseWriter, r *http.Request) {
			if d.Relay == nil {
				http.Error(w, "relay unavailable", http.StatusBadGateway)
				return
			}
			body, _ := io.ReadAll(r.Body)
			ctx := r.Context()
			if dl := rt.Handler.Relay.DeadlineMS; dl > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Duration(dl)*time.Millisecond)
				defer cancel()
			}
			hdrs := map[string]string{}
			if rid := chimd.GetReqID(ctx); rid != "" {
				hdrs["X-Request-Id"] = rid
			}
			if creds, err := issueCreds(d, r, rt); err == nil && creds.HeaderName != "" && creds.HeaderValue != "" {
				hdrs[creds.HeaderName] = creds.HeaderValue
				for k, v := range creds.Extra {
					hdrs[k] = v
				}
			}
			reply, err := d.Relay.Request(ctx, RelayRequest{
				Topic:   rt.Handler.Relay.Topic,
				Body:    body,
				Headers: hdrs,
			})
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			writeJSON(w, reply, http.StatusOK)
		}

	case HandlerRelayPublish:
		return func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			canon := body

			// 1) Canonicalize if a datatype is declared
			typeName := strings.TrimSpace(rt.Handler.Relay.DataType)
			if typeName != "" {
				_, out, err := ValidateAndCanonicalize(typeName, body)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				canon = out
			}

			// 2) Publish-side transforms (manifest-driven)
			if rs := rt.Handler.Relay; rs != nil && len(rs.Transformers) > 0 && typeName != "" {
				fmt.Printf("DEBUG publish: applying %v for type %q\n", rs.Transformers, typeName)

				adapters, elemType, err := transform.ResolveWithType(typeName, rs.Transformers)
				if err != nil {
					http.Error(w, "transform resolve: "+err.Error(), http.StatusBadRequest)
					return
				}

				dstPtr := reflect.New(elemType).Interface()
				if err := json.Unmarshal(canon, dstPtr); err != nil {
					http.Error(w, "decode: "+err.Error(), http.StatusBadRequest)
					return
				}
				val := reflect.ValueOf(dstPtr).Elem().Interface()
				fmt.Printf("DEBUG publish: before transforms: %#v\n", val)

				for _, fn := range adapters {
					val, err = fn(val)
					if err != nil {
						http.Error(w, "transform: "+err.Error(), http.StatusBadRequest)
						return
					}
					fmt.Printf("DEBUG publish: after step: %#v\n", val)
				}

				out, err := json.Marshal(val)
				if err != nil {
					http.Error(w, "encode: "+err.Error(), http.StatusBadRequest)
					return
				}
				canon = out

				// safety: re-canonicalize
				if _, out2, err := ValidateAndCanonicalize(typeName, canon); err == nil {
					canon = out2
				}
			} else if typeName != "" {
				fmt.Printf("DEBUG publish: no transforms for type %q (list empty or missing)\n", typeName)
			}

			// 3A) Typed path
			if d.Typed != nil && typeName != "" {
				if _, elemType, err := transform.ResolveWithType(typeName, rt.Handler.Relay.Transformers); err == nil && elemType != nil {
					dstPtr := reflect.New(elemType).Interface()
					if err := json.Unmarshal(canon, dstPtr); err != nil {
						http.Error(w, "decode typed: "+err.Error(), http.StatusBadRequest)
						return
					}
					val := reflect.ValueOf(dstPtr).Elem().Interface()

					hdrs := map[string]string{"X-Relay-Type": typeName}
					if rid := chimd.GetReqID(r.Context()); rid != "" {
						hdrs["X-Request-Id"] = rid
					}
					if creds, err := issueCreds(d, r, rt); err == nil && creds.HeaderName != "" {
						hdrs[creds.HeaderName] = creds.HeaderValue
						for k, v := range creds.Extra {
							hdrs[k] = v
						}
					}
					if err := d.Typed.Publish(r.Context(), rt.Handler.Relay.Topic, typeName, val, hdrs); err != nil {
						http.Error(w, err.Error(), http.StatusBadGateway)
						return
					}
					w.WriteHeader(http.StatusAccepted)
					return
				}
			}

			// 3B) Byte-level path
			if d.Relay == nil {
				http.Error(w, "relay unavailable", http.StatusBadGateway)
				return
			}
			hdrs := map[string]string{"Content-Type": "application/json"}
			if typeName != "" {
				hdrs["X-Relay-Type"] = typeName
			}
			if rid := chimd.GetReqID(r.Context()); rid != "" {
				hdrs["X-Request-Id"] = rid
			}
			if creds, err := issueCreds(d, r, rt); err == nil && creds.HeaderName != "" {
				hdrs[creds.HeaderName] = creds.HeaderValue
				for k, v := range creds.Extra {
					hdrs[k] = v
				}
			}
			if err := d.Relay.Publish(r.Context(), RelayRequest{
				Topic:   rt.Handler.Relay.Topic,
				Body:    canon,
				Headers: hdrs,
			}); err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			w.WriteHeader(http.StatusAccepted)
		}

	case HandlerProxy:
		return func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "proxy handler not implemented", http.StatusNotImplemented)
		}

	default:
		return func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "unknown handler type", http.StatusInternalServerError)
		}
	}
}

func writeJSON(w http.ResponseWriter, payload []byte, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if len(payload) > 0 {
		_, _ = w.Write(payload)
		return
	}
	_, _ = w.Write([]byte(`{}`))
}

func statusIf(s, def int) int {
	if s > 0 {
		return s
	}
	return def
}

func issueCreds(d BuildDeps, r *http.Request, rt Route) (DownstreamCredentials, error) {
	if d.Creds == nil {
		if rt.Policy.DownAuth == nil || rt.Policy.DownAuth.Type == "none" {
			return DownstreamCredentials{}, nil
		}
		switch rt.Policy.DownAuth.Type {
		case "passthrough-cookie":
			if sessionCookieName == "" {
				return DownstreamCredentials{}, nil
			}
			return PassthroughCookieProvider{CookieName: sessionCookieName}.Issue(r.Context(), r, rt)
		case "static-bearer":
			if staticBearerCached != "" {
				val := staticBearerCached
				if !strings.HasPrefix(val, "Bearer ") {
					val = "Bearer " + val
				}
				return DownstreamCredentials{HeaderName: "Authorization", HeaderValue: val}, nil
			}
			return StaticBearerProvider{}.Issue(r.Context(), r, rt)
		case "token-exchange":
			return TokenExchangeProvider{Auth: d.Auth}.Issue(r.Context(), r, rt)
		}
		return DownstreamCredentials{}, nil
	}
	return d.Creds.Issue(r.Context(), r, rt)
}
