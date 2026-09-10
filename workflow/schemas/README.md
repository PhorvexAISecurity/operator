# Structured artifact schemas

- `fix-status.schema.json` — per-fix lifecycle, role, pin and next-action state
- `intake-status.schema.json` — pre-issue verification and dedup lifecycle
- `campaign-status.schema.json` — forward-looking campaign lifecycle
- `release-sync.schema.json` — main/deployment reconciliation records
- `operations-policy.schema.json` — request classes, authorities, and gates
- `evidence-manifest.schema.json` — v1 fix and v2 typed-subject evidence indexes
- `issue-entry.schema.json` — YAML front matter on issue source files

JSON Schema is used even though the instances are YAML; YAML is parsed into
the same data model. `tools/workflow.py doctor` validates schemas and then
applies cross-record invariants that JSON Schema cannot express.
