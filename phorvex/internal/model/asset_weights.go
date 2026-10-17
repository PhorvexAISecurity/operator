package model

import "maps"

// AssetLabelWeights values an asset from its labels: the largest weight among the
// label values it carries, or Default when it carries none of them. It is data,
// not a function, so a policy crosses the brain service boundary intact
// (ADR-0001) and fingerprints by content.
type AssetLabelWeights struct {
	// ByLabel maps a label key to the weight of each of its values.
	ByLabel map[string]map[string]float64
	// Default is the weight of an asset that carries none of the weighted labels.
	Default float64
}

// Weight returns the asset weight of labels.
func (w AssetLabelWeights) Weight(labels map[string]string) float64 {
	best, matched := 0.0, false
	for key, values := range w.ByLabel {
		value, ok := labels[key]
		if !ok {
			continue
		}
		weight, ok := values[value]
		if !ok {
			continue
		}
		if !matched || weight > best {
			best, matched = weight, true
		}
	}
	if !matched {
		return w.Default
	}
	return best
}

// Clone returns a copy that shares no maps with w.
func (w AssetLabelWeights) Clone() AssetLabelWeights {
	if w.ByLabel == nil {
		return w
	}
	out := AssetLabelWeights{ByLabel: make(map[string]map[string]float64, len(w.ByLabel)), Default: w.Default}
	for key, values := range w.ByLabel {
		out.ByLabel[key] = maps.Clone(values)
	}
	return out
}
