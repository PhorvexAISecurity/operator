# WS-2 (Rev 5) — Generator = library select-and-fit (replaces "attack author")

## 0. The invariant this serves
The generator produces **nothing new about how to attack**. It selects reviewed entries from the WS-8 library and fits their parameters to the scanned stack. Every REAL promotion still requires the deterministic C1–C6 gate; agent agreement is never evidence. (Rev 4 §6 gate is unchanged.)

## 1. What changed from Rev 4 WS-2
| Rev 4 | Rev 5 |
|---|---|
| Persona agents *emit hypothesised attack fragments* | Persona agents *select applicable library entries* and *bind* them to real workloads |
| Novelty came from the agents | Novelty comes only from new **human/partner-reviewed** library entries |
| Fragment schema invented per run | Fragment = a library entry instance: `{entry_id, bound_workload, fitted_params, preconditions_checked}` |

## 2. Select-and-fit algorithm
```
for entry in library.where(bucket in {1,2,3}):
    if entry.preconditions ⊆ scan.facts(workload):      # entry APPLIES
        inst = bind(entry, workload)                     # pick pod/ns/identity/route from the scan
        inst.fitted_params = fit(entry, workload)        # e.g. which adapter label, which SA, which route
        emit HYPOTHESIZED inst                            # still must pass C1..C6 to become REAL
```
Fitting is parameter substitution from scan facts only (names, labels, digests, routes). It never adds a step the library entry did not already contain.

## 3. Roster (unchanged shape, new job)
T0 orchestrator owns the scan snapshot + the applied-entry queue. T1 are per-tactic selectors (they know which library entries live under each ATLAS/ATT&CK tactic). T2 are per-domain fitters (k8s / ai-serving / agentic-MCP) that bind parameters. T3 chains applied entries into multi-stage instances over confirmed edges (respecting the library's own `leads-to` where present). No tier authors attack content.

## 4. The gate is unchanged
C1 reachability · C2 RBAC · C3 precondition facts · C4 CVE/EPSS · C5 kill-chain evidence · C6 source trust. A fitted library instance is REAL only when every precondition it carries is confirmed against scanned facts. Scanned text stays UNTRUSTED data (Rev 4 §6.1).

## 5. Growing the library (the only source of new coverage)
A new entry is added by a human or a contracted testing partner, keyed to a public framework ID, with: preconditions, attacker_end_state, confirmation_probe, bucket, surface. It enters the same way as the seed entries and is then selectable. Agents may *propose* a gap ("no entry covers ATLAS AML.Txxxx on this stack") as text for human review; they do not write the entry.
