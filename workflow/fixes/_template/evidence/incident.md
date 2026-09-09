# Incident-to-fix evidence

Start the reproduction after the independent seal. Either participant may supply
the fixture and sign its executed baseline RED; skeptic independently runs and signs
`record-check <fix> incident --by <skeptic> --artifact evidence/incident.md ...`
before P3. Keep this artifact immutable after signing; corrections require new
attestations. Inline results or reference retained raw evidence by path/hash.
For a small local fix, one input/output case can fill this entire record.

## Trigger and production path

- Incident/request, baseline and implementation SHAs:
- Reproduction command and realistic inputs; substitutions and coverage limits:
- Input → producer/classifier → decisive condition → changed behavior:

## Decisive values and outcomes

| Case | Derived values / reached branch | Baseline outcome | Fixed outcome | Evidence |
|---|---|---|---|---|
| Original failure | | | | |
| Legitimate behavior preserved | | | | |
| Bypass / boundary / missing or stale input (where applicable) | | | | |

Assert the fixture actually produces the bug-triggering values. Do not inject
the final boolean or mock away the producer being challenged. For compound
conditions, enumerate every arm and fallback; name justified omissions.

## Independent review

- Skeptic's reproduction, counterexample attempt and result:
- Regression test names; remaining deployment-only assumptions and live controls:
- Verdict: PASS / FAIL / UNAVAILABLE / NON_DISCRIMINATING
