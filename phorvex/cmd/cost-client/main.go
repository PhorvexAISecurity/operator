// cost-client provides bounded public-path calibration and independent client evidence.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"time"
)

func main() {
	qps := flag.Float64("qps", 20, "bounded requests/second (0<qps<=100)")
	duration := flag.Duration("duration", 10*time.Minute, "bounded duration (<=20m)")
	url := flag.String("url", "http://cost-target.costbench-opus.svc/", "public admission URL")
	flag.Parse()
	if *qps <= 0 || *qps > 100 || *duration <= 0 || *duration > 20*time.Minute {
		os.Exit(2)
	}
	hc := &http.Client{Timeout: 2 * time.Second}
	tick := time.NewTicker(time.Duration(float64(time.Second) / *qps))
	defer tick.Stop()
	deadline := time.NewTimer(*duration)
	defer deadline.Stop()
	report := time.NewTicker(time.Second)
	defer report.Stop()
	attempted, ok := 0, 0
	latencies := []float64{}
	emit := func() {
		sort.Float64s(latencies)
		p99 := 0.0
		if len(latencies) > 0 {
			p99 = latencies[(len(latencies)-1)*99/100]
		}
		b, _ := json.Marshal(map[string]any{"at": time.Now().UTC(), "attempted": attempted, "ok": ok, "failed": attempted - ok, "p99Ms": p99})
		fmt.Println(string(b))
	}
	for {
		select {
		case <-deadline.C:
			emit()
			return
		case <-report.C:
			emit()
		case <-tick.C:
			attempted++
			start := time.Now()
			r, e := hc.Get(*url)
			if e == nil {
				body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
				r.Body.Close()
				if err == nil && r.StatusCode == 200 && string(body) == "ok\n" {
					ok++
				}
			}
			latencies = append(latencies, float64(time.Since(start))/float64(time.Millisecond))
		}
	}
}
