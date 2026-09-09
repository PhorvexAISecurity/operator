# Triage an unclassified request

Use this runbook when a request does not map unambiguously to another
operation.

1. Restate the desired outcome and identify which project truths might change.
2. Inspect relevant state read-only and list candidate operations.
3. If one existing operation safely covers the request, classify and hand off
   to it.
4. If the request would require a new kind of mutation, ask the human owner
   for the smallest material decision before changing files, GitHub, a shared
   environment, or canonical records.
5. Record a framework extension separately from the production change; do not
   improvise an undocumented state edge.

Terminal results are `CLASSIFIED` or `NEEDS_HUMAN_DECISION`. Triage is not a
permission bypass.
