package audit

import (
	"encoding/json"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/representation"
)

func cloneRepresentation(in *model.Representation) *model.Representation {
	if in == nil {
		return nil
	}
	b, err := json.Marshal(in)
	if err != nil {
		return representation.Build(model.RepresentationSnapshot{Limitations: []string{"invalid-retained-representation"}})
	}
	var out model.Representation
	if err = json.Unmarshal(b, &out); err != nil {
		return representation.Build(model.RepresentationSnapshot{Limitations: []string{"invalid-retained-representation"}})
	}
	return &out
}

// RepresentationForRead never borrows today's config, weights, build or states.
// The projection is a copy; a nil historical field stays absent when persisted.
func RepresentationForRead(rec Record) *model.Representation {
	if rec.Representation != nil {
		return cloneRepresentation(rec.Representation)
	}
	return representation.Build(model.RepresentationSnapshot{Limitations: []string{"historical-metadata-unavailable"}})
}
