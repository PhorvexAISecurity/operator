package endpointv3

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
)

type State struct {
	Lambda float64 `json:"lambda_s"`
	At     float64 `json:"at"`
	Tick   string  `json:"tick"`
}
type StateStore interface {
	Load(string) (State, bool, error)
	Save(string, State) error
}
type FileStore struct{ Dir string }

func (s FileStore) path(key string) string {
	h := sha256.Sum256([]byte(key))
	return filepath.Join(s.Dir, hex.EncodeToString(h[:])+".json")
}
func (s FileStore) Load(key string) (State, bool, error) {
	var st State
	raw, err := os.ReadFile(s.path(key))
	if os.IsNotExist(err) {
		return st, false, nil
	}
	if err != nil {
		return st, false, err
	}
	err = json.Unmarshal(raw, &st)
	return st, true, err
}
func (s FileStore) Save(key string, st State) error {
	if err := os.MkdirAll(s.Dir, 0700); err != nil {
		return err
	}
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(s.Dir, ".lambda-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(name, s.path(key)); err != nil {
		return err
	}
	d, err := os.Open(s.Dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

type Lambda struct {
	Previous  *float64 `json:"lambda_prev"`
	Next      *float64 `json:"lambda_next"`
	Effective float64  `json:"lambda_eff"`
	B         *float64 `json:"b"`
	G         *float64 `json:"g"`
	DT        float64  `json:"dt"`
	S         *float64 `json:"S"`
	R         *float64 `json:"R"`
	Write     string   `json:"state_write"`
	Reason    string   `json:"reason"`
	AtFloor   bool     `json:"at_floor"`
	AtCeiling bool     `json:"at_ceiling"`
}
type Controller struct {
	Config   Config
	Store    StateStore
	states   map[string]State
	restarts map[string]bool
	poison   map[string]bool
}

func NewController(c Config, s StateStore) *Controller {
	return &Controller{Config: c, Store: s, states: map[string]State{}, restarts: map[string]bool{}, poison: map[string]bool{}}
}

func (c *Controller) Update(t Tick, b Budget) Lambda {
	out := Lambda{S: b.Spend, R: b.R, Write: "SKIPPED"}
	key := t.WorkloadUID + "\x00" + t.PolicyUID
	disable := func(reason string) Lambda { out.Reason = reason; out.Effective = 0; return out }
	if t.WorkloadUID == "" || t.PolicyUID == "" || !finite(t.At) || t.At < 0 {
		return disable("TICK_IDENTITY_OR_TIME_INVALID")
	}
	if c.poison[key] {
		return disable("STATE_WRITE_FAILED")
	}
	if c.Store == nil {
		return disable("DURABLE_STATE_UNAVAILABLE")
	}
	st, exists := c.states[key]
	if !exists {
		loaded, found, err := c.Store.Load(key)
		if err != nil {
			return disable("STATE_READ_FAILED")
		}
		if found {
			st = loaded
			c.restarts[key] = true
			c.states[key] = st
			exists = true
		} else {
			st = State{Lambda: c.Config.Min, At: t.At}
		}
	}
	if !finite(st.Lambda) || st.Lambda < c.Config.Min || st.Lambda > c.Config.Max || !finite(st.At) {
		return disable("STATE_INVALID")
	}
	out.Previous = ptr(st.Lambda)
	out.Next = ptr(st.Lambda)
	if t.At < st.At {
		return disable("CLOCK_BACKWARDS")
	}
	if exists && (t.ID == st.Tick || t.At == st.At) {
		return disable("DUPLICATE_TICK")
	}
	if b.R == nil || !finite(*b.R) || *b.R <= 0 {
		return disable("BUDGET_R_UNAVAILABLE")
	}
	if b.Spend == nil || !finite(*b.Spend) || *b.Spend < 0 {
		reason := b.TelemetryReason
		if reason == "" {
			reason = "MEASURED_MOVE_SPEND_MISSING"
		}
		return disable(reason)
	}
	if t.SLO == nil || !finite(t.SLO.Window) || t.SLO.Window <= 0 {
		return disable("SLO_WINDOW_UNAVAILABLE")
	}
	burn := *b.Spend * t.SLO.Window / (c.Config.Lookback * *b.R)
	if !finite(burn) {
		return disable("NONFINITE_BURN_RATE")
	}
	g := clamp(burn-1, -1, c.Config.GMax)
	dt := clamp(t.At-st.At, 0, c.Config.MaxDT)
	out.B = ptr(burn)
	out.G = ptr(g)
	out.DT = dt
	next := st.Lambda
	if c.restarts[key] {
		next = c.Config.Min
		out.DT = 0
		out.Reason = "RESTART_RESET_INACTIVE"
	} else {
		// Clamp in log space before exponentiation; overflow is never hidden
		// by serializing an infinity or substituting a fabricated number.
		next = math.Exp(clamp(math.Log(st.Lambda)+c.Config.Eta*dt*g, math.Log(c.Config.Min), math.Log(c.Config.Max)))
		if next <= c.Config.Min*(1+1e-12) {
			next = c.Config.Min
		}
		if next >= c.Config.Max*(1-1e-12) {
			next = c.Config.Max
		}
	}
	ns := State{Lambda: next, At: t.At, Tick: t.ID}
	if err := c.Store.Save(key, ns); err != nil {
		c.poison[key] = true
		out.Write = "FAILED"
		return disable("STATE_WRITE_FAILED")
	}
	c.states[key] = ns
	delete(c.restarts, key)
	out.Next = ptr(next)
	out.Write = "COMMITTED"
	out.AtFloor = next == c.Config.Min
	out.AtCeiling = next == c.Config.Max
	if !out.AtFloor && out.Reason == "" {
		out.Effective = next / *b.R
	}
	if out.AtFloor && out.Reason == "" {
		out.Reason = "AT_FLOOR_UNPRICED"
	}
	return out
}

func (c Config) Validate() error {
	for _, v := range []float64{c.Lookback, c.Min, c.Max, c.Eta, c.GMax, c.MaxDT, c.Delta} {
		if !finite(v) || v <= 0 {
			return fmt.Errorf("controller constants must be positive and finite")
		}
	}
	if c.Min >= c.Max || c.MaxDT > 30 || c.Lookback > 30*86400 || c.Max > 1e9 || c.Min < 1e-12 || c.Eta > 1 || c.GMax > 100 || c.Delta > 3600 {
		return fmt.Errorf("controller constants outside experiment limits")
	}
	return nil
}
