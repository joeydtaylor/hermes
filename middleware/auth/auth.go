// middleware/auth/auth.go
package auth

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
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

	// Assertion verification
	assertCookieName string
	assertKeyURL     string
	assertKeyKID     string
	assertIssuer     string
	assertAudience   string
	assertLeeway     time.Duration

	// guarded by mu
	mu         sync.RWMutex
	assertKey  *rsa.PublicKey
	assertETag string
	cacheTTL   time.Duration
	lastFetch  time.Time
}

// -------------------- DI provider --------------------

func ProvideAuthentication() *Middleware {
	hc := &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:       10,
			IdleConnTimeout:    30 * time.Second,
			DisableCompression: false,
		},
		Timeout: 8 * time.Second,
	}

	leeway := 60 * time.Second
	if v := strings.TrimSpace(os.Getenv("ASSERTION_LEEWAY_SECONDS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			leeway = time.Duration(n) * time.Second
		}
	}

	assertCookie := strings.TrimSpace(os.Getenv("ASSERTION_COOKIE_NAME"))
	if assertCookie == "" {
		assertCookie = "assert"
	}

	m := &Middleware{
		httpClient:       hc,
		sessionAPI:       os.Getenv("SESSION_STATE_API"),
		cookieName:       os.Getenv("SESSION_COOKIE_NAME"),
		adminRole:        os.Getenv("ADMIN_ROLE_NAME"),
		devBypass:        os.Getenv("AUTH_DEV_BYPASS") == "true",
		assertCookieName: assertCookie,
		assertKeyURL:     strings.TrimSpace(os.Getenv("ASSERTION_KEY_URL")), // JWKS/PEM endpoint
		assertKeyKID:     strings.TrimSpace(os.Getenv("ASSERTION_KEY_KID")),
		assertIssuer:     strings.TrimSpace(os.Getenv("ASSERTION_ISSUER")),
		assertAudience:   strings.TrimSpace(os.Getenv("ASSERTION_AUDIENCE")),
		assertLeeway:     leeway,
		cacheTTL:         1 * time.Hour, // default; overridable by Cache-Control
	}

	// Fetch assertion key on startup (non-fatal)
	if m.assertKeyURL != "" {
		if err := m.refreshAssertionKey(context.Background()); err == nil {
			go m.backgroundRefresh()
		}
	}

	return m
}

// -------------------- Key refresh logic --------------------

func (m *Middleware) backgroundRefresh() {
	for {
		sleep := m.getCacheTTL()
		if sleep < 5*time.Second {
			sleep = 5 * time.Second
		}
		time.Sleep(sleep)
		_ = m.refreshAssertionKey(context.Background())
	}
}

func (m *Middleware) refreshAssertionKey(ctx context.Context) error {
	if m.assertKeyURL == "" {
		return errors.New("ASSERTION_KEY_URL not set")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.assertKeyURL, nil)
	if err != nil {
		return err
	}
	if etag := m.getETag(); etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	req.Header.Set("Accept", "*/*")

	res, err := m.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	// Honor 304 with previous key
	if res.StatusCode == http.StatusNotModified && m.getKey() != nil {
		m.updateCacheTTLFromHeaders(res)
		m.setLastFetch(time.Now())
		return nil
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return fmt.Errorf("key fetch %s: %s", m.assertKeyURL, res.Status)
	}

	ct := strings.ToLower(strings.TrimSpace(res.Header.Get("Content-Type")))
	var pub *rsa.PublicKey

	if strings.Contains(ct, "application/json") || strings.HasSuffix(strings.ToLower(m.assertKeyURL), ".json") {
		// JWKS
		var jwks struct {
			Keys []struct {
				Kty string `json:"kty"`
				Use string `json:"use"`
				Alg string `json:"alg"`
				Kid string `json:"kid"`
				N   string `json:"n"`
				E   string `json:"e"`
			} `json:"keys"`
		}
		if err := json.NewDecoder(res.Body).Decode(&jwks); err != nil {
			return err
		}

		var sel *struct {
			Kty, Use, Alg, Kid, N, E string
		}

		for i := range jwks.Keys {
			k := &jwks.Keys[i]
			if k.Kty != "RSA" {
				continue
			}
			if m.assertKeyKID != "" {
				if k.Kid == m.assertKeyKID {
					sel = &struct {
						Kty, Use, Alg, Kid, N, E string
					}{k.Kty, k.Use, k.Alg, k.Kid, k.N, k.E}
					break
				}
				continue
			}
			// default: first RSA signing key (RS256)
			if (k.Use == "" || k.Use == "sig") && (k.Alg == "" || strings.EqualFold(k.Alg, "RS256")) {
				sel = &struct {
					Kty, Use, Alg, Kid, N, E string
				}{k.Kty, k.Use, k.Alg, k.Kid, k.N, k.E}
				break
			}
		}
		if sel == nil {
			return errors.New("no suitable RSA key in JWKS")
		}
		nBytes, err := b64url(sel.N)
		if err != nil {
			return fmt.Errorf("bad jwks.n: %w", err)
		}
		eBytes, err := b64url(sel.E)
		if err != nil {
			return fmt.Errorf("bad jwks.e: %w", err)
		}
		pub = &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: bytesToInt(eBytes),
		}
	} else {
		// PEM
		b, err := io.ReadAll(res.Body)
		if err != nil {
			return err
		}
		block, _ := pem.Decode(b)
		if block == nil {
			return errors.New("no PEM block in response")
		}
		keyAny, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return err
		}
		rk, ok := keyAny.(*rsa.PublicKey)
		if !ok {
			return errors.New("PEM is not RSA public key")
		}
		pub = rk
	}

	// commit new state under lock
	m.mu.Lock()
	m.assertKey = pub
	m.assertETag = res.Header.Get("ETag")
	m.updateCacheTTLFromHeadersLocked(res) // expects m.mu held
	m.lastFetch = time.Now()
	m.mu.Unlock()
	return nil
}

func (m *Middleware) updateCacheTTLFromHeaders(res *http.Response) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updateCacheTTLFromHeadersLocked(res)
}

func (m *Middleware) updateCacheTTLFromHeadersLocked(res *http.Response) {
	cc := res.Header.Get("Cache-Control")
	if cc == "" {
		return
	}
	parts := strings.Split(cc, ",")
	for _, p := range parts {
		p = strings.TrimSpace(strings.ToLower(p))
		if strings.HasPrefix(p, "max-age=") {
			if s, err := strconv.Atoi(strings.TrimPrefix(p, "max-age=")); err == nil && s >= 5 {
				m.cacheTTL = time.Duration(s) * time.Second
				return
			}
		}
	}
}

func (m *Middleware) getKey() *rsa.PublicKey {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.assertKey
}

func (m *Middleware) getETag() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.assertETag
}

func (m *Middleware) getCacheTTL() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cacheTTL
}

func (m *Middleware) setLastFetch(t time.Time) {
	m.mu.Lock()
	m.lastFetch = t
	m.mu.Unlock()
}

// -------------------- Assertion validation --------------------

func (m *Middleware) validateAssertion(raw string) (User, error) {
	pub := m.getKey()
	if pub == nil {
		return User{}, errors.New("assertion key not configured")
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(m.assertLeeway),
	)

	var claims struct {
		jwt.RegisteredClaims
		Ver   int      `json:"ver"`
		SID   string   `json:"sid"`
		UID   string   `json:"uid"`
		Org   string   `json:"org"`
		Roles []string `json:"roles"`
		Role  string   `json:"role"`
	}

	tok, err := parser.ParseWithClaims(raw, &claims, func(t *jwt.Token) (any, error) {
		return pub, nil
	})
	if err != nil || !tok.Valid {
		return User{}, errors.New("invalid assertion")
	}

	if m.assertIssuer != "" && claims.Issuer != m.assertIssuer {
		return User{}, errors.New("bad issuer")
	}

	if m.assertAudience != "" {
		found := false
		for _, a := range claims.Audience {
			if a == m.assertAudience {
				found = true
				break
			}
		}
		if !found {
			return User{}, errors.New("bad audience")
		}
	}

	username := claims.UID
	if username == "" {
		username = claims.Subject
	}
	if username == "" {
		return User{}, errors.New("missing uid")
	}

	return User{
		Username:             username,
		AuthenticationSource: AuthenticationSource{Provider: "assert"},
		Role:                 Role{Name: firstNonEmpty(claims.Role, first(claims.Roles...))},
	}, nil
}

// -------------------- HTTP middleware --------------------

func (m *Middleware) Middleware() func(http.Handler) http.Handler {
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

			// 1) If assertion cookie present, validate locally
			if ac, _ := r.Cookie(m.assertCookieName); ac != nil && ac.Value != "" && m.getKey() != nil {
				if u, err := m.validateAssertion(ac.Value); err == nil && u.Username != "" {
					ctx := context.WithValue(r.Context(), userCtxKey, u)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
				// fall through on error; do not 401 yet
			}

			// 2) Fallback to session API if session cookie present
			if m.cookieName != "" {
				if c, err := r.Cookie(m.cookieName); err == nil && c != nil && c.Value != "" {
					if u, err := m.validateSession(r.Context(), c); err == nil && u.Username != "" {
						ctx := context.WithValue(r.Context(), userCtxKey, u)
						next.ServeHTTP(w, r.WithContext(ctx))
						return
					}
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
			}

			// 3) No cookies; continue unauthenticated
			next.ServeHTTP(w, r)
		})
	}
}

func (m *Middleware) validateSession(ctx context.Context, c *http.Cookie) (User, error) {
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

// -------------------- helpers / predicates --------------------

func (m *Middleware) GetUser(ctx context.Context) User {
	if user, ok := ctx.Value(userCtxKey).(User); ok {
		return user
	}
	return User{}
}

func (m *Middleware) IsRole(ctx context.Context, role Role) bool {
	if u, ok := ctx.Value(userCtxKey).(User); ok {
		return u.Role.Name == role.Name || (m.adminRole != "" && u.Role.Name == m.adminRole)
	}
	return false
}

func (m *Middleware) IsAdmin(ctx context.Context) bool {
	if u, ok := ctx.Value(userCtxKey).(User); ok && m.adminRole != "" {
		return u.Role.Name == m.adminRole
	}
	return false
}

func (m *Middleware) IsUser(ctx context.Context, username string) bool {
	if u, ok := ctx.Value(userCtxKey).(User); ok {
		return u.Username == username || (m.adminRole != "" && u.Role.Name == m.adminRole)
	}
	return false
}

func (m *Middleware) IsAuthenticated(ctx context.Context) bool {
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

// -------------------- small utils --------------------

func first(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func firstNonEmpty(a string, b string) string {
	if a != "" {
		return a
	}
	return b
}

func b64url(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func bytesToInt(b []byte) int {
	// little helper for RSA exponent
	n := 0
	for _, v := range b {
		n = n<<8 | int(v)
	}
	if n == 0 {
		return 65537
	}
	return n
}
