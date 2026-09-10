# PHORVEXSEC-209 / M100 — independent implementation review

- Review date: 2026-09-09 UTC.
- Worktree: `/tmp/phvx209-representation`.
- Base HEAD at review: `345c0ade12ac5b0d6ec71fe96c70cb9bc1d9cbac`; findings concern the uncommitted/untracked implementation, not that commit alone.
- Contract read in full: `/tmp/current-209.md`.
- Final verified status (2026-09-09 06:06 UTC): **all seven findings resolved; no open findings from this scoped automated review**. Original and follow-up findings were forwarded by coordinator.
- Review identity: **automated separate-agent code review**, not Hami review, Math approval, human independent approval, or ticket acceptance/conformance sign-off.
- Scope: model/representation, internal/representation, runner, audit and owner-console integration. Production empty loss mappings and incomplete-inventory unavailability are permitted. No invented source predicates were required. M14 legacy booleans / PR139 were excluded.
- Initial verification: source review and seven focused in-memory Go probes. Follow-up verification is recorded below. No repository files were edited; no full build/test suites, Plane tools, commits or pushes were run. Probe source existed only in Linux memfd descriptors through Go overlays.

## Final verification — all findings resolved

The five original defect cases pass after two explicit fixture/API adaptations: dispatch evidence now enters the retained snapshot, and the synthetic owner witness declares the new loss-mapping metadata. The literal old commands were also rerun: five cases passed unchanged; the old post-Build dispatch mutation and metadata-free witness failed for these superseded setup reasons. Those two failures are not counted as current defects.

Current reproduction commands below contain those two adaptations. All seven original semantic cases then passed. The actual runner dispatch regression also passed, verifying the production append path rather than only direct Build inputs.

### F6 — disjoint gaps contaminate the requested summary (RESOLVED)

Request `{tenant:t, asset:ns/p, version:v1, property:access}` with a complete positive fixture. Add a gap identical except for **one** of tenant, asset, version (`v0`), or property. Before the fix, all four non-overlapping cases incorrectly set the requested primary to unknown with `unrelated-observation-gap`. The requested summary should remain at-risk; a broad overlapping gap must still produce unknown.

Original cause: `assets()` unconditionally appended every gap to `root.Unresolved` before the later overlap check. The fix now checks overlap with the requested scope before adding the gap (current source: `phorvex/internal/representation/report.go:413`). All four independent disjoint-gap cases now return at-risk with no unresolved reasons; broad overlapping gaps still return unknown. The named regression also passes for both unknown kinds and unresolved entries. Contract: §3.6 requested-scope semantics, T05/T12 scope separation.

### F7 — an unrelated ambiguous key invalidates a complete scoped share (RESOLVED)

Keep the same complete requested fixture with one unique covered key of weight 3. Add two conflicting annotations for a **different** key, `other-fact`, both belonging to excluded asset `ns/other`. Before the fix, the requested fact remained at-risk, but its share became unavailable (`classification-incomplete`) instead of 1.

Original cause: availability used `len(ambiguous)>0` across the whole supplied population, including keys absent from the requested inventory. The fix retains pre-filter ambiguity detection but sets `scopedAmbiguity` only for keys in the requested inventory (current source: `phorvex/internal/representation/report.go:207–213`, availability at `:247`). The independent excluded-key case now returns share 1, while the original same-key cross-property ambiguity probe still returns unknown/unavailable. Contract: §4.1–4.2, T07/T09 scoped population.

### Verification results

- Original seven independent semantic cases: **PASS**, with the two documented setup adaptations.
- Implementer regressions plus targeted existing tests: **PASS** in representation, runner, audit, and console. Exact command:

```bash
cd /tmp/phvx209-representation/phorvex
go test ./internal/representation ./internal/runner ./internal/audit ./internal/console -run '^(TestReview|TestT03T06|TestT04T05T16|TestT07T10|TestT16|TestM100)' -count=1 -v
```

- Passing checks include R/X/L exclusion, historical loss retention, negative/NaN/Inf replay, partial inventory and mismatched snapshots, immutable inputs, source-adapter unavailability, actual runner dispatch replay, absent historical metadata, audit copy isolation, and owner allowlist/version/property behavior.
- Additional independent guards: retained loss survives both empty mapping and empty current trust (**PASS**); externally decoded report redaction strips credential keys, disables numeric claims and does not mutate the caller map, with deterministic replay (**PASS**).
- Final direct follow-up probes: four disjoint-gap subcases and one unrelated-key ambiguity case **PASS**, resolving F6/F7. Their earlier failing results are retained in the historical descriptions above.
- Both requested implementer regressions **PASS**: `TestReviewDisjointGapsDoNotChangeRequestedSummary` and `TestReviewUnrelatedAmbiguousKeyDoesNotInvalidateScopedShare`.
- All four verification commands recorded here were rerun against the final source. The selected package command and all three in-memory probe commands completed successfully; every reported `probe_exit` and shell exit was 0.
- No remaining concrete contract violations were found in the requested recheck. This does not assert universal correctness, full T01–T16 acceptance, Hami review or Math approval.
- No production or repository test files were edited by the reviewer; only this artifact was updated. Full suites/TS builds, Plane, commits and pushes were not run.

### Source identity at final check

Base HEAD remains `345c0ade12ac5b0d6ec71fe96c70cb9bc1d9cbac`. These implementation hashes were unchanged across the final rerun and final source check. This identifies the reviewed uncommitted tree, not a newly committed implementation SHA.

```text
6e43ab0bba8dbd7481ec4855ecbd255037a87fa649c9a37448d7155a8df8d460  phorvex/internal/representation/report.go
2d4894a14aa2a800d87e9943bfbbe86ddbd1c5f69ce845d107dfebad2c3a53e5  phorvex/internal/model/representation.go
ff76fab981bcc38fcf32d8f8256f4f0b2cb5c33c7f9babd33f5fae93b11e8cfb  phorvex/internal/console/representation.go
2baa83c94c0a6f54093ebb6c8b13ec68b33e85f86ac33b33fc349007f46b9296  phorvex/internal/runner/representation.go
3667cdec67bf26fe70abff717cd19a1d803381d573042042b5c900d2ea85e78b  phorvex/internal/runner/manager.go
```

## Original findings — all resolved

The descriptions and line references in this section record the initial failures; they are historical, not claims that those five defects remain present.

### 1. Property filtering hides ambiguous weighted bindings

Two annotations have the same original fact key but different protected properties. Requesting only the first property filters the second annotation out before ambiguity detection. The remaining entry becomes at-risk and receives a present coverage share of 1, rather than retaining ambiguous binding / unavailable coverage.

Contract: §4.1, T06/T07.
Source: `phorvex/internal/representation/report.go:166` (scope filtering before key ambiguity detection).
Probe: `TestReviewNarrow` below.

### 2. Asset summaries can report at-risk despite unresolved classification or observation

Two separate cases:

- Set `ClassificationComplete=false` on an otherwise positive fixture. Share becomes unavailable with `classification-incomplete`, but the v1 asset remains at-risk with no unresolved reasons.
- Add `UnknownKinds` for `{Tenant:t, Asset:ns/p, Version:""}` with `no-applicable-observer`; request v1. The unversioned summary is unknown, while v1 stays at-risk. The owner exact-version filter skips the broader gap.

Contract: §3.6, T12.
Sources: `phorvex/internal/representation/report.go:381` (gap bucketing), `:388` (summary limitations omit classification completeness); `phorvex/internal/console/representation.go:41` (exact scope filter).
Probes: `TestReviewProbe/classification-incomplete-primary`, `TestReviewProbe/asset-wide-observer-gap`.

### 3. Owner projection hides a matching property-scoped loss

For `{Tenant:t, Asset:ns/p, Version:v1, Property:confidentiality}`, a qualifying synthetic fixture witness produces one known loss and an already-lost summary. `assets()` clears the summary property; owner projection requires it to equal the requested property and returns unknown.

Contract: §3.6, T14.
Sources: `phorvex/internal/representation/report.go:358`, `phorvex/internal/console/representation.go:41`.
Probes: `TestReviewProbe/property-scope-summary`, plus direct projection `TestReviewOwnerFromBuild`.
Observed direct result: `knownLossCount=1`, summary primary already-lost, `owner=unknown`.

### 4. Actuated reports do not replay identically

The runner sets `EffectEvidence="dispatch-only-unconfirmed"` after `Build`, without retaining a corresponding snapshot input. Rebuilding from that snapshot returns `EffectEvidence="unconfirmed"`.

Contract: T16.
Sources: `phorvex/internal/runner/representation.go:45`, `phorvex/internal/representation/report.go:119`.
Probe: `TestReviewProbe/dispatch-replay` reproduces the runner's exact post-Build assignment and compares the rebuilt report. It does not execute an actuator.

### 5. Audit redaction leaks credentials in weight-map keys

Set `Weights.Values[Key("t", "token=REVIEW_SENTINEL")]=1`. The synthetic sentinel survives Build and JSON serialization. The reused redactor cleans map values but not dictionary keys. This is an audit payload defect; the owner allowlist excludes weight maps.

Sources: `phorvex/internal/model/representation.go:180` and `:209`; reused helper `phorvex/internal/model/existential.go:133`.
Probe: `TestReviewProbe/credential-in-weight-key`.

## Previously flagged changes inspected

Source inspection confirmed invalid-weight replay markers, ordinary unknown/R partition exclusion, and replacement of the O(DV) version search with a lookup map. Owner unknown precedence and version matching were present for exact-scope cases; original findings 2 and 3 are now resolved. F6/F7 are also resolved by the final recheck. This is not approval of the implementation or a claim that the full acceptance suite passed.

## Current reproduction commands for the original cases

These are the initial reproduction commands with only the documented dispatch-input and synthetic-loss-mapping setup changes. Run on the reviewed worktree. These commands use the implementer's existing `fixture`, `witness`, and `wire` test helpers in `internal/representation/report_test.go`. They add virtual test files via memory-backed overlays, write no repository files, and select only the review probes. Go may update its normal build cache. If helpers change later, adapt the probe setup explicitly; failures to compile are not confirmation or resolution of a finding.

All witnesses and credential markers below are synthetic test fixtures, not production evidence or real secrets.

### Command 1 — five core probes

```bash
python3 - <<'PY'
import os, json, subprocess
src = r'''package representation
import (
 "testing"
 "bytes"
 "github.com/phorvex/phorvex/internal/model"
)
func TestReviewProbe(t *testing.T) {
 t.Run("classification-incomplete-primary",func(t *testing.T){
  s:=fixture(); s.ClassificationComplete=false
  r:=Build(s)
  for _,a:=range r.AssetState { if a.Scope.Version=="v1" { t.Logf("share=%s primary=%v unresolved=%v",r.CoverageShare.Share.Reason,a.Primary,a.Unresolved); if a.Primary!=model.RepresentationUnknown {t.Error("unresolved classification labeled at-risk")} } }
 })
 t.Run("asset-wide-observer-gap",func(t *testing.T){
  s:=fixture(); s.Scope.Version="v1"
  s.UnknownKinds=[]model.RepresentationGap{{Scope:model.ProtectedScope{Tenant:"t",Asset:"ns/p"},Kind:"credential",Reason:"no-applicable-observer"}}
  for _,a:=range Build(s).AssetState { t.Logf("scope=%+v primary=%v unresolved=%v",a.Scope,a.Primary,a.Unresolved); if a.Scope.Version=="v1" && a.Primary!=model.RepresentationUnknown {t.Error("asset-wide gap does not reach current version")} }
 })
 t.Run("property-scope-summary",func(t *testing.T){
  s:=fixture(); s.Scope=s.Facts[0].Scope; s.Witnesses=[]model.LossWitness{witness(s.Scope)}
  r:=Build(s); matched:=false
  for _,a:=range r.AssetState {t.Logf("request=%+v summary=%+v primary=%v losses=%v",s.Scope,a.Scope,a.Primary,a.LossRefs); if a.Scope==s.Scope { matched=true } }
  if !matched {t.Error("owner exact-scope filter has no matching summary")}
 })
 t.Run("credential-in-weight-key",func(t *testing.T){
  s:=fixture(); s.Weights.Values[Key("t","token=REVIEW_SENTINEL")]=1
  b:=wire(t,Build(s)); if bytes.Contains(b,[]byte("REVIEW_SENTINEL")) {t.Error("credential survives redaction in weight-map key")}
 })
 t.Run("dispatch-replay",func(t *testing.T){
  s:=fixture(); s.DispatchEvidence="dispatch-only-unconfirmed"; r:=Build(s)
  replayed:=Build(r.Snapshot)
  t.Logf("record=%s replay=%s",r.EffectEvidence,replayed.EffectEvidence)
  if !bytes.Equal(wire(t,r),wire(t,replayed)) {t.Error("runner dispatch annotation cannot replay from retained snapshot")}
 })
}
'''
f=os.memfd_create('review-probe'); os.write(f,src.encode())
overlay=os.memfd_create('review-overlay')
path='/tmp/phvx209-representation/phorvex/internal/representation/review_probe_test.go'
os.write(overlay,json.dumps({'Replace':{path:f'/proc/{os.getpid()}/fd/{f}'}}).encode())
p=subprocess.run(['go','test','-vet=off',f'-overlay=/proc/{os.getpid()}/fd/{overlay}','./internal/representation','-run','^TestReviewProbe$','-count=1','-v'],cwd='/tmp/phvx209-representation/phorvex',text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
print(p.stdout)
print('probe_exit=',p.returncode)
PY
```

Initial result before fixes: all five subtests failed. Final adapted follow-up result: all five PASS; `probe_exit=0`.

### Command 2 — ambiguous binding and actual owner projection

```bash
python3 - <<'PY'
import os,json,subprocess
sources={
'internal/representation/review_narrow_test.go':r'''package representation
import("testing";"github.com/phorvex/phorvex/internal/model")
func TestReviewNarrow(t *testing.T){
 s:=fixture(); s.Scope=s.Facts[0].Scope; f:=s.Facts[0]; f.Scope.Property="other-property"; s.Facts=append(s.Facts,f)
 r:=Build(s); t.Logf("state=%v share=%+v",r.FactStates[0].State,r.CoverageShare.Share)
 if r.FactStates[0].State!=model.RepresentationUnknown || r.CoverageShare.Share.Present {t.Error("property filter hides ambiguous binding of original weighted key")}
}''',
'internal/console/review_owner_test.go':r'''package console
import("testing";"github.com/phorvex/phorvex/internal/model";"github.com/phorvex/phorvex/internal/audit";"github.com/phorvex/phorvex/internal/representation")
func TestReviewOwnerFromBuild(t *testing.T){
 scope:=model.ProtectedScope{Tenant:"t",Asset:"ns/p",Version:"v1",Property:"confidentiality"}
 w:=model.LossWitness{Scope:scope,EventRef:"synthetic-event",EventTime:"2026-09-08T00:00:00Z",IngestionTime:"2026-09-08T00:00:01Z",AuthenticatedIdentity:"synthetic-creator",TrustAtIngestionRef:"synthetic-stamp",RuleVersion:"synthetic-v1",PayloadPredicateRef:"synthetic-predicate",CompletedUnauthorizedOutcomeRef:"synthetic-occurrence",IrreversibilitySemantics:"synthetic-semantics",ClassificationRef:"synthetic-classification"}
 r:=representation.Build(model.RepresentationSnapshot{Scope:scope,LossAssessment:"available",LossMappingVersion:"synthetic-v1",Witnesses:[]model.LossWitness{w}})
 out:=ownerRepresentation(audit.Record{Tenant:"t",Namespace:"ns",Pod:"p",Representation:r})
 t.Logf("knownLossCount=%d summary=%v owner=%s",r.KnownLossCount,r.AssetState,out.State)
 if out.State!="already-lost"{t.Error("matching property-scoped loss hidden by owner projection")}
}'''}
fds=[]; mapping={}
for path,src in sources.items():
 f=os.memfd_create('review-probe');fds.append(f);os.write(f,src.encode());mapping['/tmp/phvx209-representation/phorvex/'+path]=f'/proc/{os.getpid()}/fd/{f}'
o=os.memfd_create('review-overlay');os.write(o,json.dumps({'Replace':mapping}).encode())
p=subprocess.run(['go','test','-vet=off',f'-overlay=/proc/{os.getpid()}/fd/{o}','./internal/representation','./internal/console','-run','^TestReview(Narrow|OwnerFromBuild)$','-count=1','-v'],cwd='/tmp/phvx209-representation/phorvex',text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
print(p.stdout);print('probe_exit=',p.returncode)
PY
```

Initial result before fixes: both tests failed. Final adapted follow-up result: both PASS; `probe_exit=0`.

The two setup adaptations preserve the original semantic cases: dispatch evidence must replay and an admissible property-scoped loss must remain visible to the owner. No production event predicates or real loss evidence are invented.

## Exact direct follow-up probe command

This is the independently executed follow-up probe, including the two passing guards. Final observed result on the source identified above: F6/F7 and the history/external-redaction guards all PASS; `probe_exit=0`. Before the final two fixes, only the F6/F7 cases failed.

```bash
python3 - <<'PY'
import os,json,subprocess
src=r'''package representation
import("testing";"github.com/phorvex/phorvex/internal/model";"encoding/json";"bytes")
func TestIndependentFollowup(t *testing.T){
 t.Run("disjoint-gaps-do-not-poison-request",func(t *testing.T){
  for _,field:=range []string{"tenant","asset","version","property"}{t.Run(field,func(t *testing.T){
   s:=fixture();s.Scope=s.Facts[0].Scope;other:=s.Scope
   switch field{case "tenant":other.Tenant="other-tenant";case "asset":other.Asset="ns/other";case "version":other.Version="v0";case "property":other.Property="other-property"}
   s.UnknownKinds=[]model.RepresentationGap{{Scope:other,Reason:"unrelated-observation-gap"}}
   r:=Build(s); found:=false
   for _,a:=range r.AssetState{if a.Scope==s.Scope{found=true;t.Logf("requested=%+v unrelated=%+v primary=%v unresolved=%v",s.Scope,other,a.Primary,a.Unresolved);if a.Primary!=model.RepresentationAtRisk||len(a.Unresolved)!=0{t.Error("disjoint gap contaminated requested summary")}}}
   if !found{t.Fatal("no requested summary")}
  })}
 })
 t.Run("out-of-scope-ambiguous-key",func(t *testing.T){
  s:=fixture();s.Scope=s.Facts[0].Scope
  other:=s.Facts[0];other.Key="other-fact";other.Scope.Asset="ns/other"
  conflict:=other;conflict.Scope.Property="different-property"
  s.Facts=append(s.Facts,other,conflict)
  r:=Build(s);t.Logf("requested fact=%v share=%+v",r.FactStates,r.CoverageShare.Share)
  if !r.CoverageShare.Share.Present||r.CoverageShare.Share.Value==nil||*r.CoverageShare.Share.Value!=1{t.Error("unrelated ambiguous key invalidates scoped share")}
 })
 t.Run("history-survives-empty-map-and-trust",func(t *testing.T){
  s:=fixture();s.Witnesses=[]model.LossWitness{witness(s.Facts[0].Scope)};r:=Build(s)
  s.History=r.AlreadyLost;s.Witnesses=nil;s.Facts=nil;s.LossMappingVersion="";s.LossAssessment="unavailable";c:=model.NewClaimScope(nil,true,"b","sha");s.Claim=&c
  r=Build(s);if r.KnownLossCount!=1||r.LossAssessment!="unavailable"{t.Fatalf("lost retained evidence: %+v",r)};replay(t,r)
 })
 t.Run("external-report-redaction-and-copy",func(t *testing.T){
  r:=Build(fixture());r.Snapshot.Weights.Values[Key("t","password=FOLLOWUP_SENTINEL")]=7
  b,e:=json.Marshal(r);if e!=nil{t.Fatal(e)};if bytes.Contains(b,[]byte("FOLLOWUP_SENTINEL")){t.Fatal("external report leaked key")}
  if _,ok:=r.Snapshot.Weights.Values[Key("t","password=FOLLOWUP_SENTINEL")];!ok{t.Fatal("marshal mutated caller map")}
  var decoded model.Representation;if e=json.Unmarshal(b,&decoded);e!=nil{t.Fatal(e)}
  if decoded.CoverageShare.Share.Present{t.Fatal("redacted binding retained numeric claim")};replay(t,&decoded)
 })
}
'''
f=os.memfd_create('followup-probe');os.write(f,src.encode())
o=os.memfd_create('followup-overlay');os.write(o,json.dumps({'Replace':{'/tmp/phvx209-representation/phorvex/internal/representation/independent_followup_test.go':f'/proc/{os.getpid()}/fd/{f}'}}).encode())
p=subprocess.run(['go','test','-vet=off',f'-overlay=/proc/{os.getpid()}/fd/{o}','./internal/representation','-run','^TestIndependentFollowup$','-count=1','-v'],cwd='/tmp/phvx209-representation/phorvex',text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
print(p.stdout);print('probe_exit=',p.returncode)
PY
```
