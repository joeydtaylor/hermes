package main

import (
	"github.com/joeydtaylor/hermes/app/handlers"
	"github.com/joeydtaylor/hermes/app/types"
	"github.com/joeydtaylor/steeze-core/pkg/serverfx"
	"github.com/joho/godotenv"
	"go.uber.org/fx"
)

func main() {
	_ = godotenv.Load()

	fx.New(
		// App-specific registrations
		fx.Invoke(types.RegisterAll),
		fx.Invoke(handlers.Register),

		// Shared server
		serverfx.Module(serverfx.Options{
			Service:         "hermes",
			ManifestEnv:     "HERMES_MANIFEST",
			DefaultManifest: "manifest.toml",
			ListenAddrEnv:   "SERVER_LISTEN_ADDRESS",
			DefaultListen:   ":4000",
			TLSCertEnv:      "SSL_SERVER_CERTIFICATE",
			TLSKeyEnv:       "SSL_SERVER_KEY",
		}),
	).Run()
}
