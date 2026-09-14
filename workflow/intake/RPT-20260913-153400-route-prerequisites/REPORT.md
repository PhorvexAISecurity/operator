# Route prerequisite candidate from Tier 1 live observation

Reporter/investigator: codex-lead. Independent assessment reviewer:
claude-tier1-auth-review (Opus 5, high). This is an OBSERVATION, not a filed
M-issue or a confirmed M21 regression. Pins and scope are in STATUS.yaml.

The retained live window contains 38 route-rotate decision selections and 39
route refusal handler events on vllm. The corresponding active selected metric
increased by 37 across a different window. The vllm-defense support condition
lists other missing prerequisites, including endpoint-rotate's route-service,
but does not list route-rotate.

Source at 6ed7d31/58363a1 has two relevant facts:
- `phorvex/internal/actuator/handlers_k8s.go`, routeRotateHandler.Enact, refuses
  without `phorvex.ai/route-service` and returns Emitted=false/MutationKind=none.
- `phorvex/internal/capability/gate.go`, Witness.Capable, evaluates configWhy only
  for AICapabilityActions. RouteRotate is not in that set and has no configWhy
  arm. Backend support is consulted, but it is not proof of target prerequisites.

The actual live handler reason and per-attempt selection/response join remain
unavailable in this packet. Counts are not a one-to-one denominator: no claim
of a 100% failure rate is justified. A selected=true metric describes an actual
selection; the counts alone do not show incorrect metric accounting or impact
credit. Missing route configuration is a source-backed hypothesis, not yet a
complete reproduction of this deployed target.

Evidence:
- ../../assessments/20260913-tier1-live/evidence/passive-analysis.json
- ../../assessments/20260913-tier1-live/evidence/policy-support.json
- ../../assessments/20260913-tier1-live/REPORT.md

Next: correlate exact target/configuration and handler output, and run a real
witness/native-handler local fixture with and without the required route setup.
Compare the root cause with M21, M33, M35 and M147 before filing or assignment.
No workload or admission mutation is authorized by this observation.
