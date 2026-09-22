# Verification

## Pre-registered test

- Claim: exact-target unresolved or unreadable protected serving slots are excluded before scoring under the existing capability taxonomy.
- Falsifier: the KV candidate survives, another effect domain is blocked, the capability read mutates the receipt, or a post-read race reaches the serving POST.
- Baseline: retained boss incident plus exact source path where protection existed only inside dispatch.
- Positive control: absent/terminal slots remain eligible and a non-serving alternative remains in the generated action set.
- Source/deployment pins: deployed `94093894`; source base `30a1cea4`; repair head recorded by the fix evidence.
- Safety boundary: source/local tests only; no cluster call, serving request, replay, deletion, or receipt rewrite.

## Execution

Run the affected `actuator`, `capability`, `actionset`, `runner`, and `cmd` tests and vet on Go 1.26.3 with serialized package work. Root independently repeats the controls before publication.

## Result

`PASS` independently reproduced by codex-lead: exact baseline production-file overlay30a1 returned true and retained blocked KV in actionset; absent/terminal/differentUID positives passed. Finalb1fec8c7 passes actuator/capability/actionset/runner suites. Exact independent logs and incident are retained in fix evidence/baseline/lead-baseline.log, evidence/p3/lead-affected-tests.log and evidence/incident.md. No deployed repair result is claimed.
