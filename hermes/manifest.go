package hermes

import (
	"errors"
	"fmt"
	"path"
	"strings"
)

type HandlerType string

const (
	HandlerInproc       HandlerType = "inproc"
	HandlerRelayReq     HandlerType = "relay.request"
	HandlerRelayPublish HandlerType = "relay.publish"
	HandlerProxy        HandlerType = "proxy"
)

type Config struct {
	Routes []Route `toml:"route"`
}

type Route struct {
	Path    string   `toml:"path"`
	Method  string   `toml:"method"`
	Guard   Guard    `toml:"guard"`
	Policy  Policy   `toml:"policy"`
	Handler HSpec    `toml:"handler"`
	Codec   string   `toml:"codec"`
	Tags    []string `toml:"tags"`
}

type Guard struct {
	Roles       []string `toml:"roles"`
	Users       []string `toml:"users"`
	RequireAuth bool     `toml:"require_auth"`
}

type DownstreamAuth struct {
	Type     string   `toml:"type"`     // "none" | "passthrough-cookie" | "static-bearer" | "token-exchange"
	Scopes   []string `toml:"scopes"`   // for token-exchange
	Audience string   `toml:"audience"` // for token-exchange
	Header   string   `toml:"header"`   // for static-bearer custom header (default: Authorization)
}

type Policy struct {
	TimeoutMS   int             `toml:"timeout_ms"`
	Retry       *RetryPolicy    `toml:"retry"`
	RateLimit   *RateLimit      `toml:"rate_limit"`
	Breaker     *Breaker        `toml:"breaker"`
	ForwardHdrs []string        `toml:"forward_headers"`
	DownAuth    *DownstreamAuth `toml:"downstream_auth"`
}

type RetryPolicy struct {
	Attempts  int `toml:"attempts"`
	BackoffMS int `toml:"backoff_ms"`
}

type RateLimit struct {
	RPS   int `toml:"rps"`
	Burst int `toml:"burst"`
}

type Breaker struct {
	FailureRateThreshold float64 `toml:"failure_rate_threshold"`
	OpenForMS            int     `toml:"open_for_ms"`
}

type HSpec struct {
	Type  HandlerType `toml:"type"`
	Name  string      `toml:"name"`
	Proxy *ProxySpec  `toml:"proxy"`
	Relay *RelaySpec  `toml:"relay"`
}

type ProxySpec struct {
	URL         string   `toml:"url"`
	PassHeaders []string `toml:"pass_headers"`
}

type RelaySpec struct {
	Topic       string `toml:"topic"`
	ExpectReply bool   `toml:"expect_reply"`
	DeadlineMS  int    `toml:"deadline_ms"`
	DataType    string `toml:"datatype,omitempty"`
}

// -------- Validation / Normalization ----------

func (c *Config) Validate() error {
	if len(c.Routes) == 0 {
		return errors.New("no routes defined")
	}
	for i := range c.Routes {
		if err := c.Routes[i].normalize(); err != nil {
			return fmt.Errorf("route %d: %w", i, err)
		}
		if err := c.Routes[i].validate(); err != nil {
			return fmt.Errorf("route %d (%s %s): %w",
				i, c.Routes[i].Method, c.Routes[i].Path, err)
		}
		// Fast-fail: datatype must be registered when present
		if rs := c.Routes[i].Handler.Relay; rs != nil && strings.TrimSpace(rs.DataType) != "" {
			if _, ok := typeReg[rs.DataType]; !ok {
				return fmt.Errorf("handler.relay.datatype %q not registered", rs.DataType)
			}
		}
	}
	return nil
}

func (r *Route) normalize() error {
	if r.Path == "" {
		return errors.New("path is required")
	}
	if !strings.HasPrefix(r.Path, "/") {
		r.Path = "/" + r.Path
	}
	if r.Path != "/" {
		r.Path = path.Clean(r.Path)
	}
	r.Method = strings.ToUpper(strings.TrimSpace(r.Method))
	if r.Method == "" {
		r.Method = "GET"
	}
	r.Codec = strings.ToLower(strings.TrimSpace(r.Codec))
	return nil
}

func (r *Route) validate() error {
	switch r.Handler.Type {
	case HandlerInproc:
		if r.Handler.Name == "" {
			return errors.New("handler.name required for inproc")
		}
	case HandlerRelayReq, HandlerRelayPublish:
		if r.Handler.Relay == nil || r.Handler.Relay.Topic == "" {
			return errors.New("handler.relay.topic required for relay")
		}
	case HandlerProxy:
		if r.Handler.Proxy == nil || r.Handler.Proxy.URL == "" {
			return errors.New("handler.proxy.url required for proxy")
		}
	default:
		return fmt.Errorf("unknown handler type %q", r.Handler.Type)
	}

	if da := r.Policy.DownAuth; da != nil {
		switch da.Type {
		case "none", "passthrough-cookie", "static-bearer", "token-exchange":
		default:
			return fmt.Errorf("policy.downstream_auth.type %q invalid", da.Type)
		}
	}

	if r.Policy.TimeoutMS < 0 {
		return errors.New("policy.timeout_ms must be >= 0")
	}
	if rp := r.Policy.Retry; rp != nil {
		if rp.Attempts < 0 {
			return errors.New("policy.retry.attempts must be >= 0")
		}
		if rp.BackoffMS < 0 {
			return errors.New("policy.retry.backoff_ms must be >= 0")
		}
	}
	if rl := r.Policy.RateLimit; rl != nil {
		if rl.RPS < 0 || rl.Burst < 0 {
			return errors.New("policy.rate_limit values must be >= 0")
		}
	}
	if br := r.Policy.Breaker; br != nil {
		if br.FailureRateThreshold < 0 || br.FailureRateThreshold > 1 {
			return errors.New("policy.breaker.failure_rate_threshold must be in [0,1]")
		}
		if br.OpenForMS < 0 {
			return errors.New("policy.breaker.open_for_ms must be >= 0")
		}
	}
	return nil
}
