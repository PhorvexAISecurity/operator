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
	out, err := model.OwnedRedactedRepresentation(in)
	if err != nil {
		return representation.Build(model.RepresentationSnapshot{Limitations: []string{"invalid-retained-representation"}})
	}
	return out
}

func prepareRepresentation(in *model.Representation) (*model.Representation, json.RawMessage) {
	if in == nil {
		return nil, nil
	}
	out, raw, err := model.MarshalOwnedRedactedRepresentation(in)
	if err != nil {
		out = representation.Build(model.RepresentationSnapshot{Limitations: []string{"invalid-retained-representation"}})
		_, raw, _ = model.MarshalOwnedRedactedRepresentation(out)
	}
	return out, raw
}

// RepresentationForRead never borrows today's config, weights, build or states.
// The projection is a copy; a nil historical field stays absent when persisted.
func RepresentationForRead(rec Record) *model.Representation {
	if rec.Representation != nil {
		return cloneRepresentation(rec.Representation)
	}
	return representation.Build(model.RepresentationSnapshot{Limitations: []string{"historical-metadata-unavailable"}})
}
