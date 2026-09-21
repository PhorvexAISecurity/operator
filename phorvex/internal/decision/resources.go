package decision

import (
	"sort"

	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/model"
)

// resourceState is the integer hard-capacity accumulator shared by production
// selection, fallbacks and comparison solvers. Empty legacy/test sets retain the
// historical unconstrained behavior; a set that declares capacities requires
// every consumed scope to be present and valid.
type resourceState struct {
	limits  map[string]int
	used    map[string]int
	scopes  map[string]model.ResourceScope
	invalid bool
}

func newResourceState(set actionset.ActionSet) *resourceState {
	if len(set.Resources) == 0 {
		return nil
	}
	r := &resourceState{limits: map[string]int{}, used: map[string]int{}, scopes: map[string]model.ResourceScope{}}
	for _, capacity := range set.Resources {
		key := capacity.Scope.Key()
		if !capacity.Scope.Valid() || capacity.Limit < 0 || capacity.Outstanding < 0 {
			r.invalid = true
			continue
		}
		if _, exists := r.limits[key]; exists {
			r.invalid = true
			continue
		}
		r.limits[key] = capacity.Limit
		if capacity.Outstanding > r.used[key] {
			r.used[key] = capacity.Outstanding
		}
		r.scopes[key] = capacity.Scope
	}
	return r
}

func (r *resourceState) clone() *resourceState {
	if r == nil {
		return nil
	}
	out := &resourceState{limits: map[string]int{}, used: map[string]int{}, scopes: map[string]model.ResourceScope{}, invalid: r.invalid}
	for key, value := range r.limits {
		out.limits[key] = value
	}
	for key, value := range r.used {
		out.used[key] = value
	}
	for key, value := range r.scopes {
		out.scopes[key] = value
	}
	return out
}

func (r *resourceState) baseFeasible() bool {
	if r == nil {
		return true
	}
	if r.invalid {
		return false
	}
	for key, used := range r.used {
		limit, known := r.limits[key]
		if !known || used > limit {
			return false
		}
	}
	return true
}

func (r *resourceState) canAdd(candidate actionset.Candidate) (bool, string) {
	if r == nil {
		return true, ""
	}
	if len(candidate.Resources) == 0 {
		return false, "candidate-resource-vector-missing"
	}
	seen := map[string]bool{}
	for _, demand := range candidate.Resources {
		key := demand.Scope.Key()
		if demand.Units <= 0 || !demand.Scope.Valid() {
			return false, "candidate-resource-consumption-invalid"
		}
		if seen[key] {
			return false, "candidate-resource-consumption-duplicate"
		}
		seen[key] = true
		limit, known := r.limits[key]
		if !known {
			return false, "candidate-resource-capacity-unknown"
		}
		if r.used[key]+demand.Units > limit {
			return false, key
		}
	}
	return true, ""
}

func (r *resourceState) add(candidate actionset.Candidate) bool {
	if ok, _ := r.canAdd(candidate); !ok {
		return false
	}
	if r == nil {
		return true
	}
	for _, demand := range candidate.Resources {
		r.used[demand.Scope.Key()] += demand.Units
	}
	return true
}

func resourcesForPicks(set actionset.ActionSet, picks []actionset.Candidate) (*resourceState, bool) {
	resources := newResourceState(set)
	if !resources.baseFeasible() {
		return resources, false
	}
	for _, candidate := range picks {
		if !resources.add(candidate) {
			return resources, false
		}
	}
	return resources, true
}

func resourceFeasible(set actionset.ActionSet, picks []actionset.Candidate) bool {
	_, ok := resourcesForPicks(set, picks)
	return ok
}

func resourceKeys(candidate actionset.Candidate) []string {
	keys := make([]string, 0, len(candidate.Resources))
	for _, demand := range candidate.Resources {
		keys = append(keys, demand.Scope.Key())
	}
	sort.Strings(keys)
	return keys
}

func blockingResource(set actionset.ActionSet, candidate actionset.Candidate, selected map[string]model.Action) string {
	picks := make([]actionset.Candidate, 0, len(selected))
	for key, action := range selected {
		if key == candidate.Key {
			continue
		}
		for _, current := range set.Candidates {
			if current.Key == key && current.Action == action {
				picks = append(picks, current)
				break
			}
		}
	}
	resources, ok := resourcesForPicks(set, picks)
	if !ok {
		return "resource-capacity-invalid"
	}
	allowed, blocked := resources.canAdd(candidate)
	if allowed {
		return ""
	}
	return blocked
}
