package hermes

import (
	"context"
	"net/http"
)

type DownstreamCredentials struct {
	HeaderName  string
	HeaderValue string
	Extra       map[string]string
}

type CredentialsProvider interface {
	Issue(ctx context.Context, r *http.Request, route Route) (DownstreamCredentials, error)
}
