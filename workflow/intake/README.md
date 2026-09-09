# Intake records

Intake holds reported claims before they become canonical M-issues. Use
`operations/INTAKE.md`; do not edit `INDEX.yaml` directly.

IDs use `RPT-YYYYMMDD-HHMMSS-<slug>`. Each directory contains an authoritative
`STATUS.yaml`, the original report, verification and dedup analyses, and an
evidence manifest. Promotion records the resulting M-number without erasing
the report's provenance.
