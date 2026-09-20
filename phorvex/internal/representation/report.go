// Package representation implements the M100 reporting partial function. It has
// no solver dependencies and cannot change selection, weights or actuation.
package representation

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

const Version = "m100-representation-v1"

// Key preserves the original recon key with unambiguous tenant qualification.
func Key(tenant, fact string) string         { b, _ := json.Marshal([]string{tenant, fact}); return string(b) }
func scopeKey(s model.ProtectedScope) string { b, _ := json.Marshal(s); return string(b) }
func lossID(s model.ProtectedScope) string {
	return fmt.Sprintf("m100-loss-%x", sha256.Sum256([]byte(scopeKey(s))))
}
func complete(s model.ProtectedScope) bool {
	return s.Tenant != "" && s.Asset != "" && s.Version != "" && s.Property != ""
}
func inScope(s, requested model.ProtectedScope) bool {
	return (requested.Tenant == "*" || s.Tenant == requested.Tenant) && (requested.Asset == "" || s.Asset == requested.Asset) && (requested.Version == "" || s.Version == requested.Version) && (requested.Property == "" || s.Property == requested.Property)
}
func unavailable(reason string) model.RepresentationAmount {
	return model.RepresentationAmount{Reason: reason}
}
func amount(v float64) model.RepresentationAmount {
	return model.RepresentationAmount{Present: true, Value: &v}
}
func canonical[T any](xs []T) []T {
	// Serialize each sort key once. The former comparator serialized both
	// operands on every comparison, creating quadratic allocation pressure.
	type keyed struct {
		value T
		key   string
	}
	items := make([]keyed, len(xs))
	for i := range xs {
		b, _ := json.Marshal(xs[i])
		items[i] = keyed{value: xs[i], key: string(b)}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].key < items[j].key })
	out := make([]T, 0, len(items))
	prev := ""
	for _, item := range items {
		if item.key != prev {
			out = append(out, item.value)
			prev = item.key
		}
	}
	return out
}

// Freeze copies all mutable reporting inputs. Invalid numbers remain present as
// missing/invalid evidence rather than causing JSON cloning to discard a snapshot.
func Freeze(in model.RepresentationSnapshot) model.RepresentationSnapshot {
	return model.CloneRepresentationSnapshot(in)
}

func validWitness(w model.LossWitness) bool {
	if !complete(w.Scope) || w.EventRef == "" || w.AuthenticatedIdentity == "" || w.TrustAtIngestionRef == "" || w.RuleVersion == "" || w.PayloadPredicateRef == "" || w.CompletedUnauthorizedOutcomeRef == "" || w.IrreversibilitySemantics == "" || w.ClassificationRef == "" {
		return false
	}
	event, e := time.Parse(time.RFC3339Nano, w.EventTime)
	ingest, i := time.Parse(time.RFC3339Nano, w.IngestionTime)
	return e == nil && i == nil && !ingest.Before(event)
}

// Build consumes a trusted source adapter's frozen bindings, NOT detector payloads.
// Current mappings/trust are never consulted to revalidate retained old witnesses.
// Corrections are deliberately not inferred: corrected evidence requires a new,
// explicitly provenance-reviewed history input from its external custodian.
func Build(input model.RepresentationSnapshot) *model.Representation {
	s := Freeze(input)
	if s.Weights.InvalidValues == nil {
		s.Weights.InvalidValues = map[string]string{}
	}
	for k, v := range s.Weights.Values {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			s.Weights.InvalidValues[k] = fmt.Sprint(v)
			delete(s.Weights.Values, k)
		}
	}
	s = s.Redacted()
	s.Facts = canonical(s.Facts)
	s.UnresolvedEntries = canonical(s.UnresolvedEntries)
	s.UnknownKinds = canonical(s.UnknownKinds)
	s.Limitations = canonical(s.Limitations)
	for i := range s.Facts {
		s.Facts[i].Actionability = canonical(s.Facts[i].Actionability)
	}
	s.Facts = canonical(s.Facts)
	for i := range s.History {
		s.History[i].Witnesses = canonical(s.History[i].Witnesses)
	}
	s.History = canonical(s.History)
	s.Witnesses = canonical(s.Witnesses)
	s.Covers.Sets = normalizeSets(s.Covers.Sets)
	s.Candidates.Sets = normalizeSets(s.Candidates.Sets)
	if s.Claim != nil {
		c := *s.Claim
		c.DetectorSet = canonical(c.DetectorSet)
		s.Claim = &c
	}
	r := &model.Representation{Version: Version, Snapshot: s, LossHistoryStatus: status(s.HistoryStatus), LossAssessment: status(s.LossAssessment), OutOfBand: "unmeasured", EffectEvidence: "unconfirmed", Note: "Modeled reporting only; no containment authorization. Known counts describe recorded evidence, not loss magnitude or unknown attacks."}
	if s.LossMappingVersion == "" {
		r.LossAssessment = "unavailable"
	}
	if s.DispatchEvidence == "dispatch-only-unconfirmed" {
		r.EffectEvidence = s.DispatchEvidence
	}
	r.UnknownEntries = append([]model.RepresentationGap{}, s.UnresolvedEntries...)
	r.UnknownKinds = append([]model.RepresentationGap{}, s.UnknownKinds...)
	losses := map[string]model.RetainedLoss{}
	addWitness := func(w model.LossWitness) {
		if !inScope(w.Scope, s.Scope) {
			return
		}
		if !validWitness(w) {
			r.UnknownEntries = append(r.UnknownEntries, model.RepresentationGap{Scope: w.Scope, Reason: "inadmissible-loss-evidence"})
			return
		}
		id := lossID(w.Scope)
		l := losses[id]
		l.ID = id
		l.Scope = w.Scope
		l.Witnesses = append(l.Witnesses, w)
		losses[id] = l
	}
	for _, l := range s.History {
		if l.ID != lossID(l.Scope) {
			r.LossHistoryStatus = "partial"
			r.UnknownEntries = append(r.UnknownEntries, model.RepresentationGap{Scope: l.Scope, Reason: "invalid-history-identity"})
			continue
		}
		if len(l.Witnesses) == 0 {
			r.LossHistoryStatus = "partial"
		}
		for _, w := range l.Witnesses {
			if w.Scope == l.Scope && validWitness(w) {
				addWitness(w)
			} else {
				r.LossHistoryStatus = "partial"
				r.UnknownEntries = append(r.UnknownEntries, model.RepresentationGap{Scope: l.Scope, Reason: "inadmissible-retained-loss-evidence"})
			}
		}
	}
	for _, w := range s.Witnesses {
		if r.LossAssessment == "unavailable" {
			r.UnknownEntries = append(r.UnknownEntries, model.RepresentationGap{Scope: w.Scope, Reason: "current-loss-rule-unavailable"})
			continue
		}
		addWitness(w)
	}
	for _, l := range losses {
		l.Witnesses = canonical(l.Witnesses)
		r.AlreadyLost = append(r.AlreadyLost, l)
	}
	r.AlreadyLost = canonical(r.AlreadyLost)
	r.KnownLossCount = len(r.AlreadyLost)
	facts := map[string]model.RepresentationFact{}
	population := map[string]model.RepresentationFact{}
	ambiguous := map[string]bool{}
	// Detect ambiguous original keys across the supplied tenant population BEFORE
	// narrowing by property/asset/version. Narrow scope cannot manufacture weights.
	for _, f := range s.Facts {
		if s.Scope.Tenant != "*" && f.Scope.Tenant != s.Scope.Tenant {
			continue
		}
		k := Key(f.Scope.Tenant, f.Key)
		if prev, ok := population[k]; ok {
			a, _ := json.Marshal(prev)
			b, _ := json.Marshal(f)
			if string(a) != string(b) {
				ambiguous[k] = true
			}
		} else {
			population[k] = f
		}
		if inScope(f.Scope, s.Scope) {
			if _, ok := facts[k]; !ok {
				facts[k] = f
			}
		}
	}
	keys := make([]string, 0, len(facts))
	for k := range facts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	risk := []string{}
	scopedAmbiguity := false
	for _, k := range keys {
		f := facts[k]
		x := model.ReportedFact{RepresentationFact: f, State: model.RepresentationUnknown, LossRefs: []string{}}
		if ambiguous[k] {
			scopedAmbiguity = true
			x.Reason = "ambiguous-assertion-binding"
		} else if l, ok := losses[lossID(f.Scope)]; ok {
			x.State = model.RepresentationAlreadyLost
			x.LossRefs = append(x.LossRefs, l.ID)
		} else if complete(f.Scope) && f.Key != "" && f.RuleVersion != "" && f.ObservationRef != "" && f.ReversibleCondition != "" && f.Reason == "" {
			x.State = model.RepresentationAtRisk
		} else if x.Reason == "" {
			x.Reason = "assertion-binding-unavailable"
		}
		switch x.State {
		case model.RepresentationAtRisk:
			risk = append(risk, k)
			r.CoverageShare.KnownAtRisk++
			if len(x.Actionability) == 0 {
				x.Actionability = []string{"actionability-unavailable"}
			}
			if !contains(x.Actionability, "coverable-now") {
				r.UncoverableEntries = append(r.UncoverableEntries, k)
			}
		case model.RepresentationAlreadyLost:
			r.CoverageShare.KnownLostEntries++
		default:
			r.CoverageShare.KnownUnknown++
			r.UnknownEntries = append(r.UnknownEntries, model.RepresentationGap{Scope: f.Scope, Kind: f.Kind, Reason: x.Reason})
		}
		r.FactStates = append(r.FactStates, x)
	}
	r.UnknownEntries = canonical(r.UnknownEntries)
	baseReason := ""
	switch {
	case s.Ref == "" || s.Scope.Tenant == "" || s.PopulationVersion == "" || (s.Aggregation != "per-decision" && s.Aggregation != "fleet-union"):
		baseReason = "scope-or-snapshot-unavailable"
	case !s.InventoryComplete:
		baseReason = "inventory-incomplete"
	case !s.ClassificationComplete || scopedAmbiguity:
		baseReason = "classification-incomplete"
	}
	c := &r.CoverageShare
	c.Unit = "engine-final-weight"
	c.Representable = measure(s, risk, baseReason)
	covered := intersection(risk, s.Covers)
	candidates := intersection(risk, s.Candidates)
	coverReason := coverStatus(s, s.Covers, baseReason)
	if s.ActionBasis != "selected-modeled" && s.ActionBasis != "actuated-modeled" {
		coverReason = "action-basis-unavailable"
	}
	c.Covered = measure(s, covered, coverReason)
	candidateReason := coverStatus(s, s.Candidates, baseReason)
	c.Coverable = measure(s, candidates, candidateReason)
	// A claimed matching candidate context must actually contain the action basis.
	if coverReason == "" && candidateReason == "" && !subset(covered, candidates) {
		c.Coverable = unavailable("candidate-basis-mismatch")
		c.Covered = unavailable("candidate-basis-mismatch")
	}
	switch {
	case !c.Representable.Present:
		c.Share = unavailable(c.Representable.Reason)
	case !c.Covered.Present:
		c.Share = unavailable(c.Covered.Reason)
	case s.Claim == nil:
		c.Share = unavailable("historical-metadata-unavailable")
	case len(risk) == 0:
		c.Share = unavailable("no-at-risk-facts")
	case *c.Representable.Value == 0:
		c.Share = unavailable("zero-weight-denominator")
	default:
		c.Share = amount(*c.Covered.Value / *c.Representable.Value)
	}
	if baseReason == "" && coverReason == "" && c.Covered.Reason != "candidate-basis-mismatch" {
		full := subset(risk, covered)
		c.RequiredSetCovered = &full
	}
	r.AssetState = assets(s, r)

	return r
}
func status(s string) string {
	if s == "available" || s == "partial" {
		return s
	}
	return "unavailable"
}
func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
func normalizeSets(sets [][]string) [][]string {
	for i := range sets {
		sets[i] = canonical(sets[i])
	}
	return canonical(sets)
}
func intersection(risk []string, covers model.RepresentationCovers) []string {
	set := map[string]bool{}
	for _, xs := range covers.Sets {
		for _, x := range xs {
			set[x] = true
		}
	}
	out := []string{}
	for _, x := range risk {
		if set[x] {
			out = append(out, x)
		}
	}
	return out
}
func subset(a, b []string) bool {
	for _, x := range a {
		if !contains(b, x) {
			return false
		}
	}
	return true
}
func coverStatus(s model.RepresentationSnapshot, c model.RepresentationCovers, reason string) string {
	if reason != "" {
		return reason
	}
	if !c.Available {
		return "cover-set-unavailable"
	}
	if c.SnapshotRef != s.Ref {
		return "snapshot-mismatch"
	}
	return ""
}
func measure(s model.RepresentationSnapshot, keys []string, reason string) model.RepresentationAmount {
	if reason != "" {
		return unavailable(reason)
	}
	if len(keys) == 0 {
		return amount(0)
	}
	if contains(s.Limitations, "credential-bearing-weight-key-removed") {
		return unavailable("weight-key-binding-unavailable")
	}
	if s.Weights.SnapshotRef != s.Ref {
		return unavailable("snapshot-mismatch")
	}
	if s.Weights.Basis == "" || s.Weights.ProvenanceRef == "" {
		return unavailable("missing-final-weights")
	}
	total := 0.0
	// keys are qualified-key sorted, regardless of map/action input iteration order.
	for _, k := range keys {
		if _, bad := s.Weights.InvalidValues[k]; bad {
			return unavailable("invalid-weight")
		}
		w, ok := s.Weights.Values[k]
		if !ok {
			return unavailable("missing-final-weights")
		}
		if w < 0 || math.IsNaN(w) || math.IsInf(w, 0) {
			return unavailable("invalid-weight")
		}
		total += w
		if math.IsInf(total, 0) {
			return unavailable("invalid-weight")
		}
	}
	return amount(total)
}
func assets(s model.RepresentationSnapshot, r *model.Representation) []model.RepresentationAsset {
	by := map[string]model.RepresentationAsset{}
	get := func(scope model.ProtectedScope) (string, model.RepresentationAsset) {
		scope.Property = s.Scope.Property
		k := scopeKey(scope)
		a := by[k]
		a.Scope = scope
		return k, a
	}
	root := model.RepresentationAsset{Scope: s.Scope}
	for _, f := range r.FactStates {
		k, a := get(f.Scope)
		if f.State == model.RepresentationAtRisk {
			a.AtRiskKeys = append(a.AtRiskKeys, Key(f.Scope.Tenant, f.Key))
		}
		if f.State == model.RepresentationUnknown {
			a.Unresolved = append(a.Unresolved, f.Reason)
		}
		by[k] = a
		if f.State == model.RepresentationAtRisk {
			root.AtRiskKeys = append(root.AtRiskKeys, Key(f.Scope.Tenant, f.Key))
		}
		if f.State == model.RepresentationUnknown {
			root.Unresolved = append(root.Unresolved, f.Reason)
		}
	}
	for _, l := range r.AlreadyLost {
		k, a := get(l.Scope)
		root.LossRefs = append(root.LossRefs, l.ID)
		a.LossRefs = append(a.LossRefs, l.ID)
		by[k] = a
	}
	for _, g := range append(append([]model.RepresentationGap{}, r.UnknownEntries...), r.UnknownKinds...) {
		if !scopesOverlap(g.Scope, s.Scope) {
			continue
		}
		k, a := get(g.Scope)
		root.Unresolved = append(root.Unresolved, g.Reason)
		a.Unresolved = append(a.Unresolved, g.Reason)
		by[k] = a
	}
	by[scopeKey(s.Scope)] = root
	out := []model.RepresentationAsset{}
	for _, a := range by {
		if !s.ClassificationComplete {
			a.Unresolved = append(a.Unresolved, "classification-incomplete")
		}
		for _, g := range append(append([]model.RepresentationGap{}, r.UnknownEntries...), r.UnknownKinds...) {
			if scopesOverlap(g.Scope, a.Scope) {
				a.Unresolved = append(a.Unresolved, g.Reason)
			}
		}
		if !s.InventoryComplete {
			a.Unresolved = append(a.Unresolved, "inventory-incomplete")
		}
		if s.CapabilityStatus != "available" {
			a.Unresolved = append(a.Unresolved, "capability-map-unavailable")
		}
		if s.Claim == nil || !s.Claim.DetectorSetKnown || len(s.Claim.DetectorSet) == 0 {
			a.Unresolved = append(a.Unresolved, "recall-unknown")
		}
		a.Primary = model.RepresentationUnknown
		if len(a.LossRefs) > 0 {
			a.Primary = model.RepresentationAlreadyLost
		} else if len(a.Unresolved) == 0 && len(a.AtRiskKeys) > 0 {
			a.Primary = model.RepresentationAtRisk
		}
		a.AtRiskKeys = canonical(a.AtRiskKeys)
		a.LossRefs = canonical(a.LossRefs)
		a.Unresolved = canonical(a.Unresolved)
		out = append(out, a)
	}
	return canonical(out)
}

// Empty fields on a gap are broad unresolved scope, never a separate asset
// capable of leaving its more-specific versions falsely at-risk.
func scopesOverlap(a, b model.ProtectedScope) bool {
	match := func(x, y string) bool { return x == "" || y == "" || x == "*" || y == "*" || x == y }
	return match(a.Tenant, b.Tenant) && match(a.Asset, b.Asset) && match(a.Version, b.Version) && match(a.Property, b.Property)
}
