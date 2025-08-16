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
		serverfx.Module(
			serverfx.WithService("hermes"),
			serverfx.WithManifestEnv("HERMES_MANIFEST"), // exodus: "EXODUS_MANIFEST"
		),
		// App-specific registrations:
		fx.Invoke(types.RegisterAll),
		fx.Invoke(handlers.Register),
	).Run()
}
