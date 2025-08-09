// runtime_options.go
package electrician

import (
	"crypto/tls"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"time"
)

type RuntimeOptions struct {
	Targets []string

	// TLS
	TLSEnable    bool
	TLSClientCrt string
	TLSClientKey string
	TLSCA        string
	TLSMin       uint16
	TLSMax       uint16
	InsecureTLS  bool // dev only

	// Perf/Security
	CompressSnappy bool
	EncryptAESGCM  bool
	AESKey         []byte // 32 bytes

	// OAuth2 CC
	OAuthIssuer   string
	OAuthJWKS     string
	OAuthClientID string
	OAuthSecret   string
	OAuthScopes   []string
	OAuthLeeway   time.Duration

	// Static headers
	StaticHeaders map[string]string
}

func LoadRuntimeOptionsFromEnv() (RuntimeOptions, error) {
	opt := RuntimeOptions{
		Targets:        splitCSV(os.Getenv("ELECTRICIAN_TARGET")),
		TLSEnable:      os.Getenv("ELECTRICIAN_TLS_ENABLE") == "true",
		TLSClientCrt:   getenv("ELECTRICIAN_TLS_CLIENT_CRT", "keys/tls/client.crt"),
		TLSClientKey:   getenv("ELECTRICIAN_TLS_CLIENT_KEY", "keys/tls/client.key"),
		TLSCA:          getenv("ELECTRICIAN_TLS_CA", "keys/tls/ca.crt"),
		TLSMin:         tls.VersionTLS13,
		TLSMax:         tls.VersionTLS13,
		InsecureTLS:    os.Getenv("ELECTRICIAN_TLS_INSECURE") == "true",
		CompressSnappy: os.Getenv("ELECTRICIAN_COMPRESS") == "snappy",
		EncryptAESGCM:  os.Getenv("ELECTRICIAN_ENCRYPT") == "aesgcm",

		OAuthIssuer:   os.Getenv("OAUTH_ISSUER_BASE"),
		OAuthJWKS:     os.Getenv("OAUTH_JWKS_URL"),
		OAuthClientID: os.Getenv("OAUTH_CLIENT_ID"),
		OAuthSecret:   os.Getenv("OAUTH_CLIENT_SECRET"),
		OAuthScopes:   splitCSV(os.Getenv("OAUTH_SCOPES")),
		OAuthLeeway:   parseDur(getenv("OAUTH_REFRESH_LEEWAY", "20s")),

		StaticHeaders: parseHeaders(os.Getenv("ELECTRICIAN_STATIC_HEADERS")), // "k=v,k2=v2"
	}

	if k := strings.TrimSpace(os.Getenv("ELECTRICIAN_AES256_KEY_HEX")); k != "" {
		raw, err := hex.DecodeString(k)
		if err != nil {
			return RuntimeOptions{}, err
		}
		if len(raw) != 32 {
			return RuntimeOptions{}, errors.New("ELECTRICIAN_AES256_KEY_HEX must decode to 32 bytes")
		}
		opt.AESKey = raw
	}

	return opt, nil
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if x := strings.TrimSpace(p); x != "" {
			out = append(out, x)
		}
	}
	return out
}

func parseHeaders(s string) map[string]string {
	if s == "" {
		return nil
	}
	out := map[string]string{}
	for _, kv := range strings.Split(s, ",") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		p := strings.SplitN(kv, "=", 2)
		if len(p) == 2 {
			out[strings.TrimSpace(p[0])] = strings.TrimSpace(p[1])
		}
	}
	return out
}

func parseDur(s string) time.Duration {
	d, _ := time.ParseDuration(s)
	if d == 0 {
		d = 20 * time.Second
	}
	return d
}
