package calib

import (
 "encoding/json"
 "fmt"
 "os"
 "path/filepath"
 "runtime"
 "runtime/pprof"
 "testing"
 "time"

 "github.com/go-logr/logr"
 "github.com/phorvex/phorvex/internal/ingest"
 "github.com/phorvex/phorvex/internal/model"
)

// Synthetic cardinality experiment through the real calibration runtime.
// This does not invoke the production optimizer or model a complete manager.
func TestCheckpointCalibrationRetentionExperiment(t *testing.T) {
 for _, scores := range []int{0, 4, 12} {
  t.Run(fmt.Sprintf("scores_%d", scores), func(t *testing.T) {
   base := time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC)
   snap := &ingest.Snapshot{Now: base}
   witnesses := map[string]model.PhysicsWitness{}
   for n := 0; n < 8; n++ { snap.Nodes = append(snap.Nodes, ingest.NodeInfo{Name: fmt.Sprintf("node-%d", n), Schedulable:true}) }
   for n := 0; n < 100; n++ {
    p := model.Pod{Namespace:fmt.Sprintf("tenant-%d",n%9), Name:fmt.Sprintf("workload-%03d",n), Node:fmt.Sprintf("node-%d",n%8), Phase:"Running"}
    snap.Pods = append(snap.Pods, p)
    witnesses[p.Namespace+"/"+p.Name] = model.PhysicsWitness{Scanned:true,ImageRarity:1,EPSSMultiplier:1,ModelRarity:1}
   }
   r := NewRuntime(RuntimeConfig{}, logr.Discard())
   if _, _, err := r.ObserveSnapshot(snap, witnesses); err != nil {t.Fatal(err)}
   runtime.GC()
   var baseline runtime.MemStats
   runtime.ReadMemStats(&baseline)
   total := 0
   emit := func(label string, elapsed time.Duration) {
    runtime.GC()
    var m runtime.MemStats
    runtime.ReadMemStats(&m)
    comparisons := len(r.pending)
    for _, s := range r.samples {comparisons += len(s.OptimizerComparisons)}
    row := map[string]any{"label":label,"scores_per_comparison_side":scores,"elapsed_seconds":int(elapsed.Seconds()),"total_comparisons_admitted":total,"sample_count":len(r.samples),"sample_capacity":cap(r.samples),"retained_comparisons":comparisons,"latest_comparisons":len(r.latest.Comparisons),"heap_alloc_delta_bytes":int64(m.HeapAlloc)-int64(baseline.HeapAlloc),"heap_objects_delta":int64(m.HeapObjects)-int64(baseline.HeapObjects),"heap_alloc_bytes":m.HeapAlloc}
    b,err:=json.Marshal(row);if err!=nil {t.Fatal(err)};t.Log(string(b))
    runtime.KeepAlive(r)
   }
   for tick:=1; tick<=2340; tick++ {
    now:=base.Add(time.Duration(tick)*10*time.Second)
    for tenant:=0;tenant<9;tenant++ {
     c:=SelectionComparison{At:now,Tenant:fmt.Sprintf("tenant-%d",tenant),ProductionScores:make([]DecisionScore,scores),ShadowScores:make([]DecisionScore,scores)}
     for i:=0;i<scores;i++ {
      c.ProductionScores[i]=DecisionScore{Key:fmt.Sprintf("tenant-%d/workload-%03d",tenant,i),Action:"rotate",CoverageValue:1,Cost:1}
      c.ShadowScores[i]=DecisionScore{Key:fmt.Sprintf("tenant-%d/workload-%03d",tenant,i),Action:"rotate",CoverageValue:1,Cost:1}
     }
     r.ObserveValidation(c,0,0);total++
    }
    if tick%30==0 {snap.Now=now;if _,_,err:=r.ObserveSnapshot(snap,witnesses);err!=nil{t.Fatal(err)}}
    if tick==360 || tick==1080 || tick==2340 {emit("active_history",now.Sub(base))}
   }
   comparisons:=0;for _,s:=range r.samples {comparisons+=len(s.OptimizerComparisons)}
   if comparisons!=21060 || len(r.latest.Comparisons)!=21060 {t.Fatalf("real runtime did not retain expected comparisons: samples=%d latest=%d",comparisons,len(r.latest.Comparisons))}
   if dir:=os.Getenv("CHECKPOINT_PROFILE_DIR");dir!="" {
    f,err:=os.Create(filepath.Join(dir,fmt.Sprintf("scores-%d.heap",scores)));if err!=nil{t.Fatal(err)}
    if err:=pprof.WriteHeapProfile(f);err!=nil{t.Fatal(err)};if err:=f.Close();err!=nil{t.Fatal(err)}
   }
   // Expiry positive control: both public history and latest must drop old rows.
   // Also inspect backing-array references, which remain GC-reachable beyond len.
   snap.Now=base.Add(8*24*time.Hour)
   if _,_,err:=r.ObserveSnapshot(snap,witnesses);err!=nil{t.Fatal(err)}
   if len(r.samples)!=1 || len(r.latest.Comparisons)!=0 {t.Fatal("logical expiry failed")}
   emit("after_eight_day_gap",8*24*time.Hour)
   hidden:=0;for _,s:=range r.samples[len(r.samples):cap(r.samples)] {hidden+=len(s.OptimizerComparisons)}
   t.Logf("backing_array_expired_comparisons=%d scores=%d",hidden,scores)
   // Diagnostic contrast only: no production changes. Clearing unused capacity
   // isolates reachable references from global runtime/Prometheus noise.
   clear(r.samples[len(r.samples):cap(r.samples)])
   emit("after_diagnostic_tail_clear",8*24*time.Hour)
   runtime.KeepAlive(r)
  })
 }
}

// An expected-RED source counterexample, independent of memory-stat thresholds.
func TestCheckpointExpiredCalibrationReferencesAreReleased(t *testing.T) {
 base:=time.Date(2026,9,19,0,0,0,0,time.UTC)
 r:=NewRuntime(RuntimeConfig{},logr.Discard())
 snap:=&ingest.Snapshot{Now:base}
 if _,_,err:=r.ObserveSnapshot(snap,nil);err!=nil{t.Fatal(err)}
 for i:=0;i<100;i++ {r.ObserveValidation(SelectionComparison{At:base.Add(time.Minute),Tenant:"expiry-control",ProductionScores:[]DecisionScore{{Key:fmt.Sprintf("fixture/pod-%d",i)}}},0,0)}
 snap.Now=base.Add(5*time.Minute)
 if _,_,err:=r.ObserveSnapshot(snap,nil);err!=nil{t.Fatal(err)}
 if len(r.samples)!=2 || len(r.samples[1].OptimizerComparisons)!=100 {t.Fatal("positive control failed to retain observations")}
 snap.Now=base.Add(8*24*time.Hour)
 if _,_,err:=r.ObserveSnapshot(snap,nil);err!=nil{t.Fatal(err)}
 if len(r.samples)!=1 || len(r.latest.Comparisons)!=0 {t.Fatal("logical age expiry did not run")}
 hidden:=0
 for _,s:=range r.samples[len(r.samples):cap(r.samples)] {hidden+=len(s.OptimizerComparisons)}
 if hidden!=0 {t.Fatalf("expired comparison references remain reachable in Runtime.samples backing array: got %d want 0",hidden)}
}
