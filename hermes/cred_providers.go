// hermes/cred_providers.go
package hermes

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/joeydtaylor/hermes/middleware/auth"
)

type NoAuthProvider struct{}

func (NoAuthProvider) Issue(context.Context, *http.Request, Route) (DownstreamCredentials, error) {
	return DownstreamCredentials{}, nil
}

type PassthroughCookieProvider struct {
	CookieName string
	HeaderName string // default: "Cookie"
}

func (p PassthroughCookieProvider) Issue(_ context.Context, r *http.Request, _ Route) (DownstreamCredentials, error) {
	if p.HeaderName == "" {
		p.HeaderName = "Cookie"
	}
	if p.CookieName == "" {
		return DownstreamCredentials{}, nil
	}
	c, err := r.Cookie(p.CookieName)
	if err != nil || c == nil || c.Value == "" {
		return DownstreamCredentials{}, nil
	}
	return DownstreamCredentials{
		HeaderName:  p.HeaderName,
		HeaderValue: fmt.Sprintf("%s=%s", p.CookieName, c.Value),
	}, nil
}

type StaticBearerProvider struct {
	HeaderName string // default: "Authorization"
	EnvVar     string // default: ELECTRICIAN_STATIC_BEARER
}

func (p StaticBearerProvider) Issue(_ context.Context, _ *http.Request, _ Route) (DownstreamCredentials, error) {
	h := p.HeaderName
	if h == "" {
		h = "Authorization"
	}
	env := p.EnvVar
	if env == "" {
		env = "ELECTRICIAN_STATIC_BEARER"
	}
	val := os.Getenv(env)
	if val == "" {
		return DownstreamCredentials{}, nil
	}
	if !strings.HasPrefix(val, "Bearer ") {
		val = "Bearer " + val
	}
	return DownstreamCredentials{HeaderName: h, HeaderValue: val}, nil
}

type TokenExchangeProvider struct {
	Auth auth.Middleware
	// Real impl would call an exchange service using:
	//   TOKEN_EXCHANGE_URL, TOKEN_EXCHANGE_TIMEOUT_MS, etc.
}

func (p TokenExchangeProvider) Issue(ctx context.Context, r *http.Request, route Route) (DownstreamCredentials, error) {
	u := p.Auth.GetUser(r.Context())
	if u.Username == "" {
		return DownstreamCredentials{}, nil
	}
	aud := ""
	if route.Policy.DownAuth != nil {
		aud = route.Policy.DownAuth.Audience
	}
	// Placeholder token; replace with a call to your exchanger.
	token := fmt.Sprintf("dev.%s.%s", u.Username, aud)
	return DownstreamCredentials{
		HeaderName:  "Authorization",
		HeaderValue: "Bearer " + token,
	}, nil
}
