# Report status or audit the workflow

This operation is read-only unless the human explicitly asks to reconcile or
repair state.

1. Run `doctor`; use `--deep-evidence` only when local-original artifacts are
   available and hashing cost is acceptable.
2. Use `brief <id>` for bounded issue, fix, or intake context.
3. Read `releases/CURRENT.yaml` for the main/deployment divergence and Anatomy
   currency.
4. State the exact source of each claim and distinguish current state,
   historical evidence, warnings, and unknowns.
5. If drift is found, report the responsible operation and safe next command.
   Do not turn an audit request into an unrequested repair.

The terminal result is an evidence-backed report. “Green” means the checks
actually executed; known unavailable capabilities and pre-existing failures
remain explicit.
