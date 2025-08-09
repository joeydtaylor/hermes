package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"go.uber.org/fx"
)

type Role struct {
	Name string `json:"name"`
}

type AuthenticationSource struct {
	Provider string `json:"provider"`
}

type User struct {
	Username             string               `json:"username"`
	AuthenticationSource AuthenticationSource `json:"authenticationSource"`
	Role                 Role                 `json:"role"`
}

type contextKey struct{ name string }

var userCtxKey = &contextKey{"user"}

type Middleware struct {
	httpClient *http.Client
	sessionAPI string
	cookieName string
	adminRole  string
	devBypass  bool
}

// DI provider
func ProvideAuthentication() Middleware {
	return Middleware{
		httpClient: &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:       10,
				IdleConnTimeout:    30 * time.Second,
				DisableCompression: false,
			},
			Timeout: 5 * time.Second, // per-request overall timeout
		},
		sessionAPI: os.Getenv("SESSION_STATE_API"),
		cookieName: os.Getenv("SESSION_COOKIE_NAME"),
		adminRole:  os.Getenv("ADMIN_ROLE_NAME"),
		devBypass:  os.Getenv("AUTH_DEV_BYPASS") == "true",
	}
}

// Auth middleware: hydrate context with User if valid; otherwise 401 and stop.
func (m Middleware) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Dev bypass for local testing (NEVER enable in prod)
			if m.devBypass {
				if u := devUserFromHeaders(r); u.Username != "" {
					ctx := context.WithValue(r.Context(), userCtxKey, u)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			// No cookie: continue unauthenticated.
			if m.cookieName == "" {
				next.ServeHTTP(w, r)
				return
			}
			c, err := r.Cookie(m.cookieName)
			if err != nil || c == nil || c.Value == "" {
				next.ServeHTTP(w, r)
				return
			}

			u, err := m.validateSession(r.Context(), c)
			if err != nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			if u.Username == "" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), userCtxKey, u)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (m Middleware) validateSession(ctx context.Context, c *http.Cookie) (User, error) {
	if m.sessionAPI == "" {
		return User{}, errors.New("SESSION_STATE_API not set")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.sessionAPI, nil)
	if err != nil {
		return User{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.AddCookie(c)

	res, err := m.httpClient.Do(req)
	if err != nil {
		return User{}, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return User{}, fmt.Errorf("session api status %d", res.StatusCode)
	}

	var u User
	if err := json.NewDecoder(res.Body).Decode(&u); err != nil {
		return User{}, err
	}
	return u, nil
}

// -------- helpers / predicates --------

/* Get user from context */
func (Middleware) GetUser(ctx context.Context) User {
	if user, ok := ctx.Value(userCtxKey).(User); ok {
		return user
	}
	return User{}
}

/* Validate user has role by name (or is admin) */
func (m Middleware) IsRole(ctx context.Context, role Role) bool {
	if u, ok := ctx.Value(userCtxKey).(User); ok {
		return u.Role.Name == role.Name || (m.adminRole != "" && u.Role.Name == m.adminRole)
	}
	return false
}

/* Validate user is admin */
func (m Middleware) IsAdmin(ctx context.Context) bool {
	if u, ok := ctx.Value(userCtxKey).(User); ok && m.adminRole != "" {
		return u.Role.Name == m.adminRole
	}
	return false
}

/* Validate user is Username (or admin) */
func (m Middleware) IsUser(ctx context.Context, username string) bool {
	if u, ok := ctx.Value(userCtxKey).(User); ok {
		return u.Username == username || (m.adminRole != "" && u.Role.Name == m.adminRole)
	}
	return false
}

/* Validate user is authenticated */
func (Middleware) IsAuthenticated(ctx context.Context) bool {
	u, ok := ctx.Value(userCtxKey).(User)
	return ok && u.Username != ""
}

// Dev-only user injection via headers when AUTH_DEV_BYPASS=true
func devUserFromHeaders(r *http.Request) User {
	user := r.Header.Get("X-Dev-User")
	if user == "" {
		return User{}
	}
	role := r.Header.Get("X-Dev-Role")
	prov := r.Header.Get("X-Dev-Provider")
	return User{
		Username:             user,
		AuthenticationSource: AuthenticationSource{Provider: prov},
		Role:                 Role{Name: role},
	}
}

var Module = fx.Options(
	fx.Provide(ProvideAuthentication),
)
