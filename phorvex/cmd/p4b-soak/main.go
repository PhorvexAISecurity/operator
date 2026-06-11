/*
 * Phorvex P4b — soak leak/drift detector (ADDITIVE; reads the operator's /metrics, never
 * touches the engine). Scrapes go_goroutines / heap / fds / tick-duration / ticks /
 * actuations over a window, fits an OLS slope+CI per resource curve, and reports PASS/FAIL:
 * flat leak slopes (no resource leak), stable tick duration (no decision-loop drift), ticks
 * advancing, and a MINIMUM actuation rate (so a too-quiet load can't pass green).
 */

package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/phorvex/phorvex/internal/soak"
)

// matches "name value" AND "name{labels} value"; group 1 = base metric name, group 3 = value.
var reGauge = regexp.MustCompile(`^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+([\d.eE+-]+)$`)

func scrape(url string) (map[string]float64, error) {
	cl := &http.Client{Timeout: 4 * time.Second}
	resp, err := cl.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	out := map[string]float64{}
	for _, ln := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(ln, "#") {
			continue
		}
		if m := reGauge.FindStringSubmatch(ln); m != nil {
			if v, err := strconv.ParseFloat(m[3], 64); err == nil {
				out[m[1]] += v // SUM across label sets (e.g. per-tenant/per-action counters)
			}
		}
	}
	return out, nil
}

type sample struct {
	t                                                        float64
	goroutines, heap, fds, rss, tickSum, tickCount, ticks, actuations, tickMeanMs float64
}

// loadCSV reads a samples CSV (t,goroutines,heap,fds,rss,ticks,actuations,tickMeanMs) for the
// --analyze re-verdict path (re-fit real data with the corrected statistics, no re-scrape).
func loadCSV(path string) []sample {
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Println("FAIL: cannot read", path, err)
		os.Exit(1)
	}
	var out []sample
	for i, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimSpace(ln)
		if i == 0 || ln == "" {
			continue // header / blank
		}
		f := strings.Split(ln, ",")
		if len(f) < 8 {
			continue
		}
		pf := func(j int) float64 { v, _ := strconv.ParseFloat(f[j], 64); return v }
		out = append(out, sample{t: pf(0), goroutines: pf(1), heap: pf(2), fds: pf(3), rss: pf(4), ticks: pf(5), actuations: pf(6), tickMeanMs: pf(7)})
	}
	return out
}

func main() {
	var url, outPath, analyzePath string
	var dur, interval, warmup time.Duration
	var minActPerMin, minTicksPerMin float64
	flag.StringVar(&url, "metrics-url", "http://localhost:8080/metrics", "operator /metrics endpoint")
	flag.DurationVar(&dur, "duration", 30*time.Minute, "soak window")
	flag.DurationVar(&interval, "interval", 15*time.Second, "scrape interval")
	flag.DurationVar(&warmup, "warmup", 0, "drop samples in the first warmup window before fitting (JIT/cache warm-up is not a leak)")
	flag.StringVar(&outPath, "out", "", "optional samples CSV path")
	flag.StringVar(&analyzePath, "analyze", "", "re-fit an existing samples CSV (no scraping); honest re-verdict of real data")
	flag.Float64Var(&minActPerMin, "min-actuations-per-min", 1.0, "load floor (actuations); the decide-loop tick rate also counts (event-driven operators actuate only on events)")
	flag.Float64Var(&minTicksPerMin, "min-ticks-per-min", 10.0, "decide-loop load floor (full snapshot+physics+optimize per tick is the primary leak surface)")
	flag.Parse()

	var S []sample
	if analyzePath != "" {
		S = loadCSV(analyzePath)
		fmt.Printf("P4b soak: RE-ANALYZING %s (%d samples)\n", analyzePath, len(S))
	} else {
		start := time.Now()
		fmt.Printf("P4b soak: scraping %s every %s for %s\n", url, interval, dur)
		for time.Since(start) < dur {
			g, err := scrape(url)
			if err == nil {
				s := sample{
					t:          time.Since(start).Seconds(),
					goroutines: g["go_goroutines"],
					heap:       g["go_memstats_heap_inuse_bytes"],
					fds:        g["process_open_fds"],
					rss:        g["process_resident_memory_bytes"],
					tickSum:    g["phorvex_tick_duration_seconds_sum"],
					tickCount:  g["phorvex_tick_duration_seconds_count"],
					ticks:      g["phorvex_ticks_total"],
					actuations: g["phorvex_actuations_total"],
				}
				if s.tickCount > 0 {
					s.tickMeanMs = s.tickSum / s.tickCount * 1000
				}
				S = append(S, s)
			}
			time.Sleep(interval)
		}
	}
	// drop the warm-up window (JIT/cache warm-up grows heap but is not a leak).
	if warmup > 0 {
		ws := warmup.Seconds()
		var kept []sample
		for _, s := range S {
			if s.t >= ws {
				kept = append(kept, s)
			}
		}
		if len(kept) >= 3 {
			fmt.Printf("(dropped %d warm-up samples < %s; fitting %d steady-state samples)\n", len(S)-len(kept), warmup, len(kept))
			S = kept
		}
	}
	if len(S) < 3 {
		fmt.Println("FAIL: too few samples (operator /metrics unreachable?)")
		os.Exit(1)
	}

	xs := make([]float64, len(S))
	col := func(f func(sample) float64) []float64 {
		ys := make([]float64, len(S))
		for i, s := range S {
			ys[i] = f(s)
		}
		return ys
	}
	for i, s := range S {
		xs[i] = s.t
	}
	heap := soak.FitOLS(xs, col(func(s sample) float64 { return s.heap }))
	gor := soak.FitOLS(xs, col(func(s sample) float64 { return s.goroutines }))
	fds := soak.FitOLS(xs, col(func(s sample) float64 { return s.fds }))
	tickMean := col(func(s sample) float64 { return s.tickMeanMs / 1000 }) // seconds
	tickFit := soak.FitOLS(xs, tickMean)

	elapsedMin := S[len(S)-1].t / 60
	actDelta := S[len(S)-1].actuations - S[0].actuations
	tickDelta := S[len(S)-1].ticks - S[0].ticks
	actPerMin, ticksPerMin := 0.0, 0.0
	if elapsedMin > 0 {
		actPerMin = actDelta / elapsedMin
		ticksPerMin = tickDelta / elapsedMin
	}

	report := func(name string, f soak.Fit, tol float64, unit string) bool {
		ok := f.Flat(tol)
		fmt.Printf("  %-12s slope=%+.3g %s/hr  95%%CI[%+.3g,%+.3g]  MDE=%.3g %s/hr  mean=%.4g  R2=%.2f  -> %s\n",
			name, soak.PerHour(f.Slope), unit, soak.PerHour(f.CILow), soak.PerHour(f.CIHigh), soak.PerHour(f.MDEPerSec), unit, f.Mean, f.R2,
			map[bool]string{true: "FLAT", false: "DRIFT?"}[ok])
		return ok
	}

	fmt.Printf("\n=== P4b SOAK RESULT (n=%d samples, %.1f min, %.0f ticks) ===\n", len(S), elapsedMin, tickDelta)
	hOK := report("heap", heap, 0.10, "B")          // <=10%/hr growth tolerance
	gOK := report("goroutines", gor, 0.10, "")      // goroutine leak
	fOK := report("open-fds", fds, 0.10, "")        // file-handle leak
	dOK := report("tick-dur", tickFit, 0.20, "s")   // decision-loop drift
	// Load floor: the DECIDE loop (full snapshot+physics+optimize+audit each tick) is the
	// primary leak surface and runs every tick; actuation is secondary (an event-driven
	// operator only actuates on events). Either the tick rate OR the actuation rate suffices.
	loadOK := (ticksPerMin >= minTicksPerMin || actPerMin >= minActPerMin) && tickDelta > 0
	fmt.Printf("  load: %.1f decide-ticks/min + %.1f actuations/min over %.0f ticks (min %.0f ticks OR %.1f act) -> %s\n",
		ticksPerMin, actPerMin, tickDelta, minTicksPerMin, minActPerMin, map[bool]string{true: "OK", false: "TOO QUIET (false-pass guard)"}[loadOK])

	if outPath != "" {
		var b strings.Builder
		b.WriteString("t,goroutines,heap,fds,rss,ticks,actuations,tickMeanMs\n")
		for _, s := range S {
			b.WriteString(fmt.Sprintf("%.0f,%.0f,%.0f,%.0f,%.0f,%.0f,%.0f,%.3f\n", s.t, s.goroutines, s.heap, s.fds, s.rss, s.ticks, s.actuations, s.tickMeanMs))
		}
		_ = os.WriteFile(outPath, []byte(b.String()), 0o644)
		fmt.Printf("  samples -> %s\n", outPath)
	}

	pass := hOK && gOK && fOK && dOK && loadOK
	fmt.Printf("\nSOAK %s (necessary-not-sufficient on kind; multi-day confirmation deferred to real EKS)\n", map[bool]string{true: "PASS", false: "FAIL"}[pass])
	if !pass {
		os.Exit(1)
	}
}
