# 🚀 Hermes

**Hermes** is a manifest-driven, type-safe HTTP gateway for Electrician-powered services ⚡. It enforces authentication, role-based guards, and strict JSON schemas **at the edge** before delivering encrypted, authenticated messages over secure mTLS/AES-GCM channels to typed relays 🔒.

Hermes makes it easy to front one or more Electrician services with a secure, observable API surface that can be extended with minimal code.

---

## ✨ Features

* **📜 Manifest-driven routing**

  * Declarative routes in `manifest.toml`.
  * Per-route guards (`require_auth`, roles, allowed users).
  * Per-route downstream auth (`passthrough-cookie`, `static-bearer`, `token-exchange` placeholder).
* **🛡 Strict type enforcement**

  * Canonical JSON round-trip with `codec.JSONStrict`.
  * Unknown fields, wrong types, or trailing bytes → `400`.
* **📦 Typed publish pipeline**

  * `datatype` in manifest maps to registered Go struct.
  * Typed Electrician ForwardRelay publishing (fan-out to multiple targets).
* **🔐 End-to-end security**

  * HTTPS/TLS 1.3 frontend.
  * mTLS + AES-256-GCM payload encryption to receiving relays.
  * Optional Snappy compression.
  * Optional OAuth2 client-credentials bearer injection.
* **📊 Observability**

  * Structured logs (zap + lumberjack rotation).
  * `/metrics` for Prometheus.
  * Trace IDs propagate end-to-end.
* **🛠 Minimal developer surface**

  * `.env` for runtime config (TLS, encryption, OAuth2, relay targets).
  * `manifest.toml` for routes and policies.
  * `app/types/register.go` for type definitions.
  * `app/handlers/inproc.go` for in-process HTTP handlers.

---

## 🔍 How it Works

### 1️⃣ Incoming Request

1. Client connects to Hermes over **HTTPS** (TLS certs from `.env`).
2. Session cookie `s` is validated via `SESSION_STATE_API` (SAML for customers, OIDC for admins/support).
3. Guard checks from manifest (`require_auth`, roles, allowed users).
4. If the route specifies a `datatype`, the JSON body is:

   * Decoded with `codec.JSONStrict`.
   * Re-encoded canonically.
   * Bound to the registered Go type.

### 2️⃣ Route Handling

* **`inproc`**: Hermes runs a Go function in-process (see `app/handlers/inproc.go`).
* **`relay.publish`**: Hermes sends the typed payload to one or more Electrician receiving relays.

### 3️⃣ Downstream Security

* **Transport**: TLS 1.3, optional mTLS (`ELECTRICIAN_TLS_CLIENT_CRT/KEY`).
* **Content**: AES-256-GCM encryption (`ELECTRICIAN_AES256_KEY_HEX`), optional Snappy compression.
* **Service Auth**: optional OAuth2 CC bearer token attached to relay calls.
* **Policy-based Headers**: `passthrough-cookie`, `static-bearer`, or future `token-exchange`.

### 4️⃣ Receivers

* Terminate TLS/mTLS.
* Decrypt AES-GCM payload.
* Authorize bearer (JWT/JWKS or introspection).
* Decode to typed struct and hand to processing pipelines.

---

## 📝 Example `manifest.toml`

```toml
# Auth-required publish (passthrough cookie)
[[route]]
path   = "/orders"
method = "POST"
codec  = "json"
  [route.guard]
  require_auth = true
  roles = ["developer","admin"]
  [route.policy]
  timeout_ms = 5000
  [route.policy.downstream_auth]
  type = "passthrough-cookie"
  [route.handler]
  type = "relay.publish"
    [route.handler.relay]
    topic        = "orders.create"
    expect_reply = false
    deadline_ms  = 4000
    datatype     = "feedback.v1"

# Open publish (no auth)
[[route]]
path   = "/orders/open"
method = "POST"
codec  = "json"
  [route.policy]
  timeout_ms = 3000
  [route.handler]
  type = "relay.publish"
    [route.handler.relay]
    topic        = "orders.events"
    expect_reply = false
    deadline_ms  = 1000
    datatype     = "feedback.v1"

# Auth-required publish (static bearer)
[[route]]
path   = "/billing"
method = "POST"
codec  = "json"
  [route.guard]
  require_auth = true
  roles = ["developer","admin"]
  [route.policy]
  timeout_ms = 5000
  [route.policy.downstream_auth]
  type = "static-bearer"
  [route.handler]
  type = "relay.publish"
    [route.handler.relay]
    topic        = "billing.charge"
    expect_reply = false
    deadline_ms  = 4000
    datatype     = "feedback.v1"
```

---

## 🧩 Type Registration (`app/types/register.go`)

```go
package types

import (
	"github.com/joeydtaylor/hermes/hermes"
	"github.com/joeydtaylor/hermes/hermes/codec"
	"github.com/joeydtaylor/hermes/pkg/electrician"
)

type Feedback struct {
	CustomerID string   `json:"customerId"`
	Content    string   `json:"content"`
	Category   string   `json:"category,omitempty"`
	IsNegative bool     `json:"isNegative"`
	Tags       []string `json:"tags,omitempty"`
}

func RegisterAll() {
	hermes.MustRegisterType[Feedback]("feedback.v1", codec.JSONStrict)
	electrician.EnableBuilderType[Feedback]("feedback.v1")
}
```

---

## 🖇 In-Process Handlers (`app/handlers/inproc.go`)

```go
package handlers

import (
	"context"
	"net/http"

	"github.com/joeydtaylor/hermes/hermes"
)

func Register() {
	hermes.Register("health.ok", func(ctx context.Context, _ []byte) ([]byte, int, error) {
		return []byte(`{"status":"ok"}`), http.StatusOK, nil
	})

	hermes.Register("echo.body", func(ctx context.Context, in []byte) ([]byte, int, error) {
		if len(in) == 0 { in = []byte(`{}`) }
		return in, http.StatusOK, nil
	})
}
```

---

## ⚙️ Configuration (`.env`)

```bash
# TLS for frontend (browser → Hermes)
SSL_SERVER_CERTIFICATE="keys/tls/server.crt"
SSL_SERVER_KEY="keys/tls/server.key"
SERVER_LISTEN_ADDRESS="localhost:4000"

# Auth/session
SESSION_STATE_API="https://localhost:3000/api/auth/session"
SESSION_COOKIE_NAME="s"
ADMIN_ROLE_NAME="admin"
DEVELOPER_ROLE_NAME="developer"

# Electrician relay targets
ELECTRICIAN_TARGET="localhost:50051,localhost:50052"
ELECTRICIAN_TLS_ENABLE="true"
ELECTRICIAN_TLS_CLIENT_CRT="keys/tls/client.crt"
ELECTRICIAN_TLS_CLIENT_KEY="keys/tls/client.key"
ELECTRICIAN_TLS_CA="keys/tls/ca.crt"
ELECTRICIAN_ENCRYPT="aesgcm"
ELECTRICIAN_AES256_KEY_HEX="<64-hex-bytes>"
ELECTRICIAN_COMPRESS="snappy"
ELECTRICIAN_STATIC_HEADERS="x-tenant=local,x-env=dev"

# OAuth2 CC (optional)
OAUTH_ISSUER_BASE="https://localhost:3000"
OAUTH_JWKS_URL="https://localhost:3000/api/auth/.well-known/jwks.json"
OAUTH_CLIENT_ID="hermes"
OAUTH_CLIENT_SECRET="local-secret"
OAUTH_SCOPES="write:data"
OAUTH_REFRESH_LEEWAY="20s"

# Manifest
HERMES_MANIFEST="manifest.toml"
```

---

## ▶️ Running

```bash
go run server.go
```

Hermes will load `.env` and the `manifest.toml`, start HTTPS, validate/guard requests, and forward typed, encrypted payloads to your Electrician relays.

---

## 💡 Why Hermes

* **Security-first**: TLS/mTLS, AES-GCM, OAuth2, guards, schema-at-the-edge.
* **Type safety across the wire**: 202 means the receiver gets a validated type.
* **Composable**: chain Electrician receivers and front them with Hermes.
* **Low-friction**: new route/type via manifest + one Go file.
* **Observable**: logs, metrics, request IDs.
