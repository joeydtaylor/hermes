package httpx

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// Router is the minimal HTTP router contract Hermes depends on.
// transport/httpx.NewChi implements this.
type Router interface {
	Handle(method, path string, h http.Handler)
	Get(path string, h http.Handler)
	Post(path string, h http.Handler)
	Put(path string, h http.Handler)
	Delete(path string, h http.Handler)
	Mux() http.Handler
	Use(mw ...func(http.Handler) http.Handler)
}

// chiRouter is our default Router backed by github.com/go-chi/chi.
type chiRouter struct{ r *chi.Mux }

// NewChi returns a Chi-backed Router.
func NewChi() Router { return &chiRouter{r: chi.NewRouter()} }

func (c *chiRouter) Handle(method, path string, h http.Handler) { c.r.Method(method, path, h) }
func (c *chiRouter) Get(path string, h http.Handler)            { c.r.Method(http.MethodGet, path, h) }
func (c *chiRouter) Post(path string, h http.Handler)           { c.r.Method(http.MethodPost, path, h) }
func (c *chiRouter) Put(path string, h http.Handler)            { c.r.Method(http.MethodPut, path, h) }
func (c *chiRouter) Delete(path string, h http.Handler)         { c.r.Method(http.MethodDelete, path, h) }
func (c *chiRouter) Mux() http.Handler                          { return c.r }
func (c *chiRouter) Use(mw ...func(http.Handler) http.Handler)  { c.r.Use(mw...) }
