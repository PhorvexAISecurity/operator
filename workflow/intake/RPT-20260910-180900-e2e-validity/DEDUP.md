# Root-cause deduplication

## Search terms and anatomy locus

Record symptom, component, invariant, source anchors, and commands used.

## Candidate comparison

For every plausible M-issue, compare mechanism, trigger, affected path, and
required correction. Similar symptoms are not sufficient to merge causes.

## Determination

Use exactly `NEW`, `DUPLICATE`, or `AMBIGUOUS`.

- Existing issue, if duplicate:
- Human ruling reference, if ambiguous:
- Rationale:

## Lead root-cause comparison

NEW, codex-lead. M155 is the Phoenix injection race and A05 identity attribution; this issue concerns independent E2E probes/check aggregation even with no injection. They share files and will be repaired in one coordinated PR, with distinct acceptance cases. M9 is product emission-versus-effect feedback; M14 is product owner narrative built from that emission. Here the purported independent groundtruth falsely validates a failed API read and historical log, so repairing product Emitted cannot repair these consumers. M161 is the Go benchmark lifecycle/metrics/report engine; none of these Python E2E functions pass through it. M146 is audit serialization of zero/presence; C03/C07 can PASS entirely absent data and PH02 ignores nested actual values, independent of serializer changes. M140 owner state, M144 dual arithmetic and M2 CRD enums have unrelated causes despite boilerplate search overlap. No canonical closure changed.
