/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package ingest

import (
	"context"
	"math"
	"strconv"
	"strings"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// collectEvents reads the cluster's SecurityEvent stream (the SAME feed Phoenix
// ingests) and projects it to per-pod belief evidence. Phorvex's OWN controller
// events (Source=PhorvexController) are EXCLUDED so Phorvex never treats its own
// actuation as threat evidence (no feedback loop).
func collectEvents(ctx context.Context, c client.Client, now time.Time) ([]model.SecurityEventInfo, map[string][]model.SecurityEventInfo, error) {
	var seList amtdv1beta1.SecurityEventList
	if err := c.List(ctx, &seList); err != nil {
		return nil, nil, err
	}
	all := make([]model.SecurityEventInfo, 0, len(seList.Items))
	byPod := map[string][]model.SecurityEventInfo{}
	for i := range seList.Items {
		se := &seList.Items[i]
		if se.Spec.Rule.Source == actuator.RuleSource {
			continue // skip Phorvex's own emitted events
		}
		score := -1.0
		if se.Spec.AnomalyScore != nil {
			// ParseFloat accepts the literal strings "NaN"/"Inf" WITHOUT error, and a detector can
			// emit either. Admitting one would carry NaN into the decision path, so an unusable
			// score stays honest-absent (-1) rather than poisoning the view.
			if f, err := strconv.ParseFloat(strings.TrimSpace(*se.Spec.AnomalyScore), 64); err == nil &&
				!math.IsNaN(f) && !math.IsInf(f, 0) {
				score = f
			}
		}
		// M-27: age per event. A CR with no usable CreationTimestamp is NOT a fresh event —
		// its age is untrusted, so it is recorded present=false and carries weight 0.
		missing := se.CreationTimestamp.IsZero()
		age := time.Duration(0)
		if !missing {
			age = now.Sub(se.CreationTimestamp.Time)
			if age < 0 {
				age = 0
			}
		}
		base := model.SecurityEventInfo{
			Name:             se.Name,
			TimestampMissing: missing,
			Type:             se.Spec.Rule.Type,
			ThreatLevel:      se.Spec.Rule.ThreatLevel,
			Source:           se.Spec.Rule.Source,
			Description:      se.Spec.Description,
			AnomalyScore:     score,
			Age:              age,
		}
		all = append(all, base)
		for _, target := range se.Spec.Targets {
			key := normalizeTarget(target)
			ev := base
			ev.TargetsPod = true
			byPod[key] = append(byPod[key], ev)
		}
	}
	return all, byPod, nil
}

// normalizeTarget canonicalizes a SecurityEvent target ("namespace/name" or
// "/name") to a "namespace/name" key.
func normalizeTarget(target string) string {
	target = strings.TrimSpace(target)
	if strings.HasPrefix(target, "/") {
		return target[1:] // "/name" -> bare name (cluster-scoped pod ref is uncommon)
	}
	return target
}
