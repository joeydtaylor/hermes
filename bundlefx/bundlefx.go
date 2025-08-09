// bundlefx/bundlefx.go
package bundlefx

import (
	"github.com/joeydtaylor/hermes/middleware/auth"
	"github.com/joeydtaylor/hermes/middleware/logger"
	"github.com/joeydtaylor/hermes/middleware/metrics"
	"go.uber.org/fx"
)

// Module provided to fx
var Module = fx.Options(
	auth.Module,
	logger.Module,
	metrics.Module,
)
