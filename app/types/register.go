package types

import (
	"strings"

	"github.com/joeydtaylor/hermes/hermes"
	"github.com/joeydtaylor/hermes/hermes/codec"
	"github.com/joeydtaylor/hermes/hermes/transform"
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

	// Manifest-visible transformers for feedback.v1
	transform.Register[Feedback]("feedback.v1", "sentiment", func(f Feedback) (Feedback, error) {
		low := strings.ToLower(f.Content)
		if strings.Contains(low, "love") || strings.Contains(low, "great") || strings.Contains(low, "happy") {
			f.Tags = append(f.Tags, "Positive Sentiment")
		} else {
			f.Tags = append(f.Tags, "Needs Attention")
		}
		return f, nil
	})
	transform.Register[Feedback]("feedback.v1", "tagger", func(f Feedback) (Feedback, error) {
		if f.IsNegative {
			f.Tags = append(f.Tags, "neg")
		}
		return f, nil
	})
	transform.Register[Feedback]("feedback.v1", "audit-only", func(f Feedback) (Feedback, error) {
		// no-op
		return f, nil
	})
}
