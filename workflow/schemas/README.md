# Structured artifact schemas

- `fix-status.schema.json` — per-fix lifecycle, role, pin and next-action state
- `evidence-manifest.schema.json` — immutable evidence index
- `issue-entry.schema.json` — YAML front matter on issue source files

JSON Schema is used even though the instances are YAML; YAML is parsed into
the same data model. `tools/workflow.py doctor` enforces the critical subset
without adding a runtime dependency on `jsonschema`.
