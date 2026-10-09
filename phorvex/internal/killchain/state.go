/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P1)
 */

package killchain

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// state.go exports and restores one owner's kill-chain state for the Math Lab snapshot
// replay. Exports are pure copies taken under the owning mutex; restores only write into
// a tracker that holds nothing for that owner yet, so a replay engine can never merge a
// recorded owner into live production state.

// StageClockEntry is one slot of the stage-dwell tracker.
type StageClockEntry struct {
	Namespace   string
	Name        string
	UID         string
	Stage       Stage
	EntryExpSec float64
}

// OwnerEntries returns this owner's slots sorted by (namespace, name).
func (c *StageClock) OwnerEntries(owner string) []StageClockEntry {
	if c == nil {
		return nil
	}
	prefix := owner + "\x00"
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]StageClockEntry, 0)
	for k, e := range c.state {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		ns, name, ok := strings.Cut(k[len(prefix):], "\x00")
		if !ok {
			continue
		}
		out = append(out, StageClockEntry{Namespace: ns, Name: name, UID: e.uid, Stage: e.stage, EntryExpSec: e.entryExpSec})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// RestoreOwnerEntries installs exported slots. It refuses to overwrite a tracker that
// already holds state for the owner.
func (c *StageClock) RestoreOwnerEntries(owner string, entries []StageClockEntry) error {
	if c == nil {
		return fmt.Errorf("stage clock is nil")
	}
	prefix := owner + "\x00"
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.state {
		if strings.HasPrefix(k, prefix) {
			return fmt.Errorf("stage clock already holds state for owner %q", owner)
		}
	}
	for _, e := range entries {
		if math.IsNaN(e.EntryExpSec) || math.IsInf(e.EntryExpSec, 0) || e.EntryExpSec < 0 {
			return fmt.Errorf("stage clock entry %s/%s has invalid entry reading %v", e.Namespace, e.Name, e.EntryExpSec)
		}
		if strings.Contains(e.Namespace, "\x00") || strings.Contains(e.Name, "\x00") {
			return fmt.Errorf("stage clock entry key contains a separator")
		}
	}
	for _, e := range entries {
		c.state[prefix+e.Namespace+"\x00"+e.Name] = stageEntry{uid: e.UID, stage: e.Stage, entryExpSec: e.EntryExpSec}
	}
	return nil
}

// ConjugateState is one owner's Beta prior plus the memory-wide configuration that a
// restored memory must share to seed and update identically.
type ConjugateState struct {
	Tracked          bool
	Alpha            float64
	Beta             float64
	DefAlpha         float64
	DefBeta          float64
	MaxMass          float64
	GAlpha           float64
	GBeta            float64
	CrossTenantPrior bool
}

// OwnerState returns a copy of one owner's belief state without seeding an untracked owner.
func (m *ConjugateMemory) OwnerState(owner string) ConjugateState {
	if m == nil {
		return ConjugateState{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := ConjugateState{DefAlpha: m.defAlpha, DefBeta: m.defBeta, MaxMass: m.maxMass,
		GAlpha: m.gAlpha, GBeta: m.gBeta, CrossTenantPrior: m.crossTenantPrior}
	if s := m.tenants[owner]; s != nil {
		out.Tracked, out.Alpha, out.Beta = true, s.alpha, s.beta
	}
	return out
}

// RestoreConjugateMemory builds a new memory that holds exactly one owner's exported state.
func RestoreConjugateMemory(owner string, s ConjugateState) (*ConjugateMemory, error) {
	for name, v := range map[string]float64{"defAlpha": s.DefAlpha, "defBeta": s.DefBeta, "maxMass": s.MaxMass, "gAlpha": s.GAlpha, "gBeta": s.GBeta} {
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
			return nil, fmt.Errorf("conjugate %s=%v is not a finite non-negative value", name, v)
		}
	}
	m := &ConjugateMemory{tenants: map[string]*tenantState{}, defAlpha: s.DefAlpha, defBeta: s.DefBeta,
		maxMass: s.MaxMass, gAlpha: s.GAlpha, gBeta: s.GBeta, crossTenantPrior: s.CrossTenantPrior}
	if s.Tracked {
		if math.IsNaN(s.Alpha) || math.IsNaN(s.Beta) || math.IsInf(s.Alpha, 0) || math.IsInf(s.Beta, 0) || s.Alpha < 0 || s.Beta < 0 {
			return nil, fmt.Errorf("conjugate owner prior (%v,%v) is invalid", s.Alpha, s.Beta)
		}
		m.tenants[owner] = &tenantState{alpha: s.Alpha, beta: s.Beta}
	}
	return m, nil
}
