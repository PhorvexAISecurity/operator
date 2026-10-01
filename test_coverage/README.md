# Live attack coverage

End-to-end benchmark of every armed **Live attack** fired once through the Console
against its own stack on `phorvex-dev-eks`, followed to a terminal result. Open
[`index.html`](index.html) for the rendered report: a per-stack coverage table, a
findings/gaps list, and a per-attack pipeline (fire → attack executed → SecurityEvent
→ brain decision → actuation → post-action check → verdict).

## Contents

- `index.html` — the rendered report (self-contained; light/dark).
- `make_report.py` — regenerates `index.html` from `runs/`: `python3 make_report.py runs index.html`.
- `run_one.sh` — the runner used to fire one attack and capture its exact result record.
  Runs on the cluster jump host; fires through the Console E2E identity and prints one JSON
  line per run. It records intent → exact result, prints no secrets.
- `runs/*.json` — the raw captured records, one per attack (`{ns,attackId,route,firedResultId,fireResp,record}`).

## How the runs were produced

For each attack: `bash run_one.sh <namespace> <attack_id> <route> <budget_seconds>` on the
jump host. Attacks on the **same** app are run one at a time (the Console rejects concurrent
runs with HTTP 409); different apps run in parallel. Voice/LiteLLM live runs use a disclosed
test-injected SecurityEvent; the mode is shown in each pipeline.

## Verdicts (per the live-catalogue runbook)

| Verdict | Meaning |
| --- | --- |
| DEFENDED | Threat reproduced, the brain's action ran, and the post-action check proved containment while legitimate service kept working. |
| PROTECTED (existing) | A prior brain action still holds; the check re-verified it, no new action needed. |
| Mechanism only / Inconclusive | An effect or a steered actuation was observed, but the attack-specific oracle did not confirm the threat was contained. |
| Attack did not land | The model/target never produced the forbidden behaviour, so no event was raised — nothing to defend. |
| Did not fire | The Console rejected the run before firing (stale profile or ambiguous target). |
| No live record | The workload foothold route emits a manager disposition, not a behavioural live verdict. |

This is a snapshot benchmark with honest, traceable results, not a claim that every
attack must earn DEFENDED. See the findings section in `index.html` for the current
gaps and follow-up work.
