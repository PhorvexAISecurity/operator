package endpointv3

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
)

type memoryStore struct {
	data map[string]State
	fail bool
}

func (s *memoryStore) Load(k string) (State, bool, error) { v, ok := s.data[k]; return v, ok, nil }
func (s *memoryStore) Save(k string, v State) error {
	if s.fail {
		return fmt.Errorf("injected write failure")
	}
	s.data[k] = v
	return nil
}
func memory() *memoryStore { return &memoryStore{data: map[string]State{}} }
func iptr(v int) *int      { return &v }
func near(t *testing.T, got, want float64) {
	t.Helper()
	if math.Abs(got-want) > 1e-8*math.Max(1, math.Abs(want)) {
		t.Fatalf("got %.12g want %.12g", got, want)
	}
}
func tick() Tick {
	return Tick{ID: "t1", At: 3000000, WorkloadUID: "workload", PolicyUID: "policy", SpecReplicas: iptr(4), SLO: &SLO{Target: .999, Window: 2592000, StudyAssumption: true}, Ledger: &Ledger{At: 3000000, CompleteFrom: ptr(0), Measurement: "measured-endpoint-intervals", Moves: []Move{}}, CandidateSetComplete: true}
}
func candidate(id, action string, value float64) Candidate {
	return Candidate{ID: id, PodUID: id, Action: action, Facts: []Fact{{ID: id, Weight: value}}, FactsKnown: true, GatesKnown: true, WorthThreshold: ptr(0), K: iptr(1), Class: "stateless", HistoryKnown: true}
}
func move(at float64) Move {
	return Move{ID: "move", Revision: 1, WorkloadUID: "workload", PolicyUID: "policy", Action: "rotate", State: "open", ObservedAt: at, Attributed: true, Measured: true, Reservation: ptr(40), Overdue: true, Intervals: []Interval{{EndpointUID: "endpoint", Start: at - 100, End: at}}}
}

func TestBudgetAndColdCost(t *testing.T) {
	in := tick()
	b := Account(in, Defaults())
	if b.Refusal != "" {
		t.Fatal(b)
	}
	near(t, *b.R, 10368)
	c := Price(in, candidate("a", "rotate", 10), b, Defaults())
	near(t, *c.Rho, 159)
	near(t, *c.E, 159)
	near(t, *c.FailureUpper, 1)
	d := candidate("a", "documented", 10)
	d.DocumentedBound = &Bound{Source: "explicit unit fixture", Approved: true, Mid: 43, Upper: 43, FailureUpper: 0}
	c = Price(in, d, b, Defaults())
	near(t, *c.Rho, 159)
	near(t, *c.E, 43)
}
func TestOrderStatisticAndClopperPearson(t *testing.T) {
	if ConfidenceRank(28) != 0 || ConfidenceRank(29) != 29 {
		t.Fatal("wrong 90/95 tolerance rank")
	}
	near(t, FailureUpper(29, 0), 1-math.Pow(.05, 1.0/29))
	near(t, FailureUpper(200, 0), 1-math.Pow(.05, 1.0/200))
	near(t, FailureUpper(9, 9), 1)
	for _, pair := range [][2]int{{30, 3}, {100, 15}, {200, 199}} {
		p := FailureUpper(pair[0], pair[1])
		near(t, BinomialCDF(pair[0], pair[1], p), .05)
	}
	samples := []Sample{}
	for i := 1; i <= 98; i++ {
		samples = append(samples, Sample{Duration: ptr(float64(i))})
	}
	samples = append(samples, Sample{Censored: true}, Sample{Censored: true})
	mid, upper, _ := Duration(samples, 43)
	near(t, mid, 49.5)
	if !finite(upper) || upper < mid {
		t.Fatal(mid, upper)
	}
}
func TestCensoringAndUnknownHistory(t *testing.T) {
	in := tick()
	c := candidate("a", "rotate", 10)
	c.Samples = []Sample{{ID: "x", WorkloadUID: in.WorkloadUID, Action: "rotate", At: in.At - 1, Censored: true}}
	price := Price(in, c, Account(in, Defaults()), Defaults())
	if !strings.HasPrefix(price.Refusal, "BOUND_MISSING") || price.E != nil {
		t.Fatal(price)
	}
	c.K = iptr(0)
	price = Price(in, c, Account(in, Defaults()), Defaults())
	near(t, *price.E, 0)
	c.K = iptr(1)
	c.Samples = nil
	c.HistoryKnown = false
	price = Price(in, c, Account(in, Defaults()), Defaults())
	if price.E != nil {
		t.Fatal("unknown history was treated as cold n=0")
	}
	c = candidate("a", "kv-reset", 10)
	price = Price(in, c, Account(in, Defaults()), Defaults())
	if price.E != nil {
		t.Fatal("invented kv-reset prior")
	}
}
func TestQuarantineBudgetFormula(t *testing.T) {
	in := tick()
	c := candidate("q", "quarantine", 10)
	c.HoldCap = ptr(100)
	p := Price(in, c, Account(in, Defaults()), Defaults())
	near(t, *p.Rho, 259)
	near(t, *p.E, 259)
	near(t, *p.Hold, 100)
	b := Account(in, Defaults())
	b.Left = ptr(158)
	p = Price(in, c, b, Defaults())
	if !strings.HasPrefix(p.Refusal, "BUDGET") {
		t.Fatal(p)
	}
}
func TestNewest200Filtering(t *testing.T) {
	in := tick()
	c := candidate("a", "rotate", 10)
	for i := 0; i < 201; i++ {
		d := 50.0
		if i == 0 {
			d = 10000
		}
		c.Samples = append(c.Samples, Sample{ID: fmt.Sprint(i), WorkloadUID: in.WorkloadUID, Action: "rotate", At: in.At - 201 + float64(i), Duration: ptr(d)})
	}
	c.Samples = append(c.Samples, Sample{ID: "wrong", WorkloadUID: "other", Action: "rotate", At: in.At, Duration: ptr(1e6)})
	p := Price(in, c, Account(in, Defaults()), Defaults())
	if p.SampleCount != 200 {
		t.Fatal(p.SampleCount)
	}
	near(t, *p.Upper, 50)
}
func TestOpenToSettledReplacementAndClipping(t *testing.T) {
	in := tick()
	m := move(in.At)
	m.Intervals = append(m.Intervals, m.Intervals[0])
	in.Ledger.Moves = []Move{m}
	b := Account(in, Defaults())
	near(t, *b.Used, 0)
	near(t, *b.Held, 100)
	near(t, *b.Spend, 100)
	settled := m
	settled.State = "settled"
	settled.Revision = 2
	settled.Reservation = nil
	in.Ledger.Moves = append(in.Ledger.Moves, settled)
	b = Account(in, Defaults())
	near(t, *b.Used, 100)
	near(t, *b.Held, 0)
	near(t, *b.Spend, 100)
	in.Ledger.Moves = []Move{settled, m}
	b = Account(in, Defaults())
	near(t, *b.Spend, 100)
	near(t, intervalLoss(m.Intervals, in.At-50, in.At), 50)
}

func TestLedgerRevisionFreshnessAndRegressions(t *testing.T) {
	in := tick()
	old := move(in.At - 30)
	settled := old
	settled.State, settled.Revision, settled.ObservedAt = "settled", 2, in.At
	for _, rows := range [][]Move{{old, settled}, {settled, old}} {
		in.Ledger.Moves = rows
		b := Account(in, Defaults())
		if b.Refusal != "" {
			t.Fatal("superseded open row must not fail freshness", b)
		}
		near(t, *b.Spend, 100)
	}
	in.Ledger.Moves = []Move{old}
	if Account(in, Defaults()).Refusal != "OPEN_MOVE_OBSERVATION_STALE" {
		t.Fatal("stale latest open accepted")
	}
	reopened := settled
	reopened.State, reopened.Revision = "open", 3
	for _, rows := range [][]Move{{settled, reopened}, {reopened, settled}} {
		in.Ledger.Moves = rows
		if Account(in, Defaults()).Refusal != "MOVE_REVISION_REGRESSED" {
			t.Fatal("settled move reopened")
		}
	}
}
func TestContainmentExcludedFromLambdaNotBudget(t *testing.T) {
	in := tick()
	m := move(in.At)
	m.Containment = true
	m.State = "settled"
	in.Ledger.Moves = []Move{m}
	b := Account(in, Defaults())
	near(t, *b.Used, 100)
	near(t, *b.Spend, 0)
}
func TestUnknownTelemetryNeverBecomesZero(t *testing.T) {
	for _, change := range []func(*Tick){func(t *Tick) { t.Ledger = nil }, func(t *Tick) { t.Ledger.Measurement = "replica-readiness" }, func(t *Tick) { t.Ledger.CompleteFrom = nil }, func(t *Tick) { t.Ledger.At-- }, func(t *Tick) { m := move(t.At); m.Measured = false; t.Ledger.Moves = []Move{m} }, func(t *Tick) { m := move(t.At); m.Attributed = false; t.Ledger.Moves = []Move{m} }} {
		in := tick()
		change(&in)
		b := Account(in, Defaults())
		if b.Spend != nil || b.Refusal == "" {
			t.Fatal(b)
		}
	}
}
func TestLambdaBurnCasesAndClock(t *testing.T) {
	cfg := Defaults()
	for _, burn := range []float64{0, 1, 2} {
		in := tick()
		b := Account(in, cfg)
		b.Spend = ptr(burn * cfg.Lookback * *b.R / in.SLO.Window)
		ctl := NewController(cfg, memory())
		ctl.states[in.WorkloadUID+"\x00"+in.PolicyUID] = State{Lambda: 1, At: in.At - 100, Tick: "prior"}
		l := ctl.Update(in, b)
		near(t, *l.B, burn)
		near(t, *l.G, burn-1)
		near(t, l.DT, 30)
		near(t, *l.Next, math.Exp(cfg.Eta*30*(burn-1)))
		dup := ctl.Update(in, b)
		if dup.Effective != 0 || dup.Reason != "DUPLICATE_TICK" {
			t.Fatal(dup)
		}
		in.At--
		in.ID = "back"
		back := ctl.Update(in, b)
		if back.Effective != 0 || back.Reason != "CLOCK_BACKWARDS" {
			t.Fatal(back)
		}
	}
}
func TestFloorWriteFailureRestartAndZeroCost(t *testing.T) {
	in := tick()
	b := Account(in, Defaults())
	store := memory()
	ctl := NewController(Defaults(), store)
	l := ctl.Update(in, b)
	if l.Effective != 0 || !l.AtFloor {
		t.Fatal(l)
	}
	in.At += 10
	in.ID = "t2"
	store.fail = true
	l = ctl.Update(in, b)
	if l.Effective != 0 || l.Write != "FAILED" {
		t.Fatal(l)
	}
	store.fail = false
	in.At += 10
	in.ID = "t3"
	l = ctl.Update(in, b)
	if l.Effective != 0 || l.Reason != "STATE_WRITE_FAILED" {
		t.Fatal(l)
	}
	restarted := NewController(Defaults(), store)
	l = restarted.Update(in, b)
	if l.Effective != 0 || l.Reason != "RESTART_RESET_INACTIVE" {
		t.Fatal(l)
	}
	c := candidate("zero", "rotate", 2)
	c.K = iptr(0)
	in.Candidates = []Candidate{c}
	a := score(in, b, 100, Defaults(), "v3")
	near(t, *a.Rows[0].J, 2)
}
func TestScaledOrderingWorthAndHardGates(t *testing.T) {
	in := tick()
	in.SpecReplicas = iptr(1)
	in.SLO = &SLO{Target: .5, Window: 2000, StudyAssumption: true}
	a, b := candidate("A", "doc-a", 10), candidate("B", "doc-b", 9)
	a.DocumentedBound = &Bound{Source: "controlled example", Approved: true, Mid: 100, Upper: 100, FailureUpper: 0}
	b.DocumentedBound = &Bound{Source: "controlled example", Approved: true, Mid: 1, Upper: 1, FailureUpper: 0}
	in.Candidates = []Candidate{a, b}
	budget := Account(in, Defaults())
	v2 := score(in, budget, 0, Defaults(), "v2")
	v3 := score(in, budget, 100/1000.0, Defaults(), "v3")
	if *v2.Pick != "A" || *v3.Pick != "B" {
		t.Fatal(v2.Pick, v3.Pick)
	}
	near(t, *v3.Rows[0].J, 0)
	near(t, *v3.Rows[1].J, 8.9)
	// Negative J is still eligible if V passes theta: no priced-worth gate.
	negative := score(in, budget, 1000, Defaults(), "v3")
	if negative.Pick == nil {
		t.Fatal("invented priced-worth rejection")
	}
	in.Candidates[1].Gates = []string{"PDB"}
	v3 = score(in, budget, .1, Defaults(), "v3")
	if *v3.Pick != "A" {
		t.Fatal("gate bypass")
	}
	in.MandatoryID = "A"
	in.Candidates[0].Containment = true
	v3 = score(in, budget, 100, Defaults(), "v3")
	if *v3.Pick != "A" || *v3.Rows[0].J != 10 {
		t.Fatal("containment priced")
	}
	in.Candidates[0].Gates = []string{"CAPACITY"}
	v3 = score(in, budget, 100, Defaults(), "v3")
	if v3.Pick != nil || v3.Noop != "NO_SAFE_CONTAINMENT_ACTION" {
		t.Fatal("unsafe containment")
	}
}
func TestFactDedupAndStableTie(t *testing.T) {
	in := tick()
	a := candidate("A", "rotate", 10)
	a.Facts = append(a.Facts, a.Facts[0])
	v, err := Value(a)
	if err != "" {
		t.Fatal(err)
	}
	near(t, *v, 10)
	b := candidate("B", "rotate", 10)
	in.Candidates = []Candidate{b, a}
	r := score(in, Account(in, Defaults()), 0, Defaults(), "v2")
	if *r.Pick != "A" {
		t.Fatal("unstable tie")
	}
}
func TestPairedRunChronologyIndependenceAndMissingStatus(t *testing.T) {
	a := tick()
	a.Candidates = []Candidate{candidate("a", "rotate", 10)}
	b := a
	b.At += 30
	b.ID = "t2"
	bl := *a.Ledger
	bl.At = b.At
	b.Ledger = &bl
	trace := Trace{Schema: TraceSchema, Evidence: "synthetic", SourceRevision: "fixture", Ticks: []Tick{b, a}}
	before, _ := json.Marshal(trace)
	r, err := Run(trace, Defaults(), memory())
	if err != nil {
		t.Fatal(err)
	}
	if r.State != "COMPLETE" || r.Comparable != 2 || *r.Changed != 0 || r.Ticks[0].ID != "t1" {
		t.Fatal(r.State, r.Comparable)
	}
	for _, tick := range r.Ticks {
		if !tick.V2.Executed || !tick.V3.Executed || !reflect.DeepEqual(tick.V2.Rows[0].Cost, tick.V3.Rows[0].Cost) {
			t.Fatal("arms not matched")
		}
	}
	after, _ := json.Marshal(trace)
	if string(before) != string(after) {
		t.Fatal("trace mutated")
	}
	trace.Ticks[0].Ledger = nil
	r, err = Run(trace, Defaults(), memory())
	if err != nil {
		t.Fatal(err)
	}
	if r.State != "PARTIAL" || r.Ticks[1].Changed != nil {
		t.Fatal("missing data became zero effect")
	}
	trace.Ticks[1].Ledger = nil
	r, err = Run(trace, Defaults(), memory())
	if err != nil {
		t.Fatal(err)
	}
	if r.State != "BLOCKED" || r.Changed != nil {
		t.Fatal("blocked comparison marked complete")
	}
}
func TestDurableStoreRoundTrip(t *testing.T) {
	s := FileStore{Dir: t.TempDir()}
	st := State{Lambda: 2, At: 123, Tick: "tick"}
	if err := s.Save("workload/policy", st); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.Load("workload/policy")
	if err != nil || !ok || got != st {
		t.Fatal(got, ok, err)
	}
}
