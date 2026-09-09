# Evidence retention

Normal Git history keeps compact, review-relevant evidence. Large raw streams
remain in approved artifact storage or in the explicitly documented original
local tree.

`legacy-manifest.yaml` records every migrated omission with its logical path,
original local path, byte count and SHA-256. The omission is therefore
visible; it is not evidence deletion.

New evidence manifests use one of:

- `git`
- `artifact-store` with a durable URI
- `local-original` only for the initial migration

Future fix closure may not depend solely on `local-original` evidence because
it is not available to a fresh clone.

`workflow.py doctor` validates metadata and byte sizes for available local
originals and warns when they are absent. Use
`workflow.py doctor --deep-evidence` to recompute their SHA-256 values.
