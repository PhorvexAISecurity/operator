# GP13 — serving cost-harvest and throttle

Provision a strictly-capped serving target (Deployment + Service + HPA) and a
reviewed cost-defense policy in a controlled namespace. Use bounded, authorized
load through the admission proxy with an approved request/time ceiling and two
reference clients — one abusive, one legitimate. Never use an unbounded
vendor-spend workload, and separate the abusive load from the benign control.

A trusted cost-load observer (serving-rate budget) must observe the load before any
move; calibrate then arm it. Trigger the authorized flood, trace the candidate and
dispatch, and capture the effective cap: Action, a strict positive gain, cap
applied while active, and cap released when traffic goes quiet. Measure the benign
client's continued service, not only the abusive client's rejections.

PASS is the brain selecting and actuating throttle with a strict positive gain, the
cap applied and then released, and the legitimate client served within budget. A
proxy's HTTP 429/500 alone does not prove the cap was applied. Abort at ceilings.
Cleanup deletes the load jobs, target and policy and CAS-restores the budget and
journal to their quiet baseline.

PREREQS (operator-refactored): `throttle` is not in the action vocabulary
(`model.Action` + the PhorvexPolicy CRD `actions.enabled` enum) and the trusted
cost-load observer is not wired. Without both the brain cannot select the action.
Historical: cap apply/release proven on the old operator harness only.
