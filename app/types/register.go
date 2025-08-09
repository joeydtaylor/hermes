package types

import (
	"github.com/joeydtaylor/hermes/hermes"
	"github.com/joeydtaylor/hermes/hermes/codec"

	// Correct package: our typed-pub hook lives here
	"github.com/joeydtaylor/hermes/pkg/electrician"
)

// Domain types registered for strict relay enforcement.

type Feedback struct {
	CustomerID string   `json:"customerId"`
	Content    string   `json:"content"`
	Category   string   `json:"category,omitempty"`
	IsNegative bool     `json:"isNegative"`
	Tags       []string `json:"tags,omitempty"`
}

func RegisterAll() {
	// Strict JSON + canonicalization
	hermes.MustRegisterType[Feedback]("feedback.v1", codec.JSONStrict)

	// Enable typed Electrician publishing for this type name
	electrician.EnableBuilderType[Feedback]("feedback.v1")
}
