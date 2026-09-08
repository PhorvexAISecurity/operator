# Fix-record reconciliation — 2026-09-08

Imported external updates from /home/mehrdad/operator/fixes into the canonical workflow. Original files remain untouched. All replacement versions are retained under before/; receipt.json records paths and hashes. New current-protocol signatures, test executions, closure approvals and missing verifiers were not fabricated.

| Fix | Reconciled disposition |
|---|---|
| T1-E | Historical cycle completion imported: M160 resolved the recorded reopen; M79 wiring and M158 discovery remain separate. |
| T1-M020 | External CLOSED outcome imported with 0.4.95 L3 PASS; rebased head and patch corrected. |
| T1-M023 | DEPLOYED, L3 NON_DISCRIMINATING; not closed. |
| T1-M028 | Existing reported CLOSED retained with explicit core-only live scope; reactive and physics-pinned AI criteria remain NON_DISCRIMINATING. Missing proposal/critique/P3/L3 artifacts imported. |
| T1-M160 | Existing CLOSED retained; current rebased patch and recorded L3 linked; missing historical full digest remains unknown. |

M-25, T1-A/B/C/D source copies already matched. T0-C's three large raw files were already hash-indexed as local-original; they are not missing evidence and were not duplicated into Git. Four source 06-verdict files are P3 reviews: they map to evidence/p3/verdict.md, not final closure.

M6 and M79 active role/state/evidence records were not overwritten. Global main/release/anatomy synchronization remains separate and visibly stale; this import does not claim a refreshed anatomy or certify all historical evidence under the new protocol.

Validation and exact copy counts are appended after verification.

## Validation

- 20 source artifacts copied; 48 imported/derived files recorded; 17 previous versions archived and hash-verified.
- All 11 legacy source directories compared. Three T0-C large artifacts were already indexed; their original hashes verified without duplicating 187 MB into Git.
- Every affected implementation and merge SHA exists on current main and in its recorded deployed source. Rebased M20/M23/M160 patches are equivalent; canonical patches match their pinned Git diffs.
- `doctor --deep-evidence`: 0 errors, 13 existing warnings (10 missing legacy verify.sh files, stale main-release pin, unreviewed anatomy joins, stale anatomy).
- Fix index and generated master-register checks pass; `git diff --check` passes.
- Active M6 and M79 records retain their state/roles. Original /home/mehrdad/operator/fixes files were hash-checked unchanged.
- This was evidence/state reconciliation, not a new product test run or a new live verification.
