# Signed lead plan: PR163 conflict resolution, round 2

User requests resolving conflicts of remaining PRs, not merging them. Lead root;
implementer deploy_worker. Main pinned f0348b36e12d751a84ffdac1414c6ff6952d2ee1;
PR head pinned 60709c3046e3ccfb35a550347989c9330bec9639. PR targets main and now
includes merged M037, so preserve both M035 endpoint and M037 fingerprint
withholding. Preserve all incoming audit-volume guard/system placement and
console-history fixes from main, including exact current release image tags.

Read-only merge-tree confirms only workflow/fixes/INDEX.yaml conflicts. Merge
the exact main pin normally, regenerate the index from the union of underlying
records with the workflow tool; do not choose one whole index or rewrite signed
historical evidence. No manual production edits are expected. If a semantic
production conflict or new branch change appears, stop and report it to lead.

Validate both-parent ancestry, regenerated index, whitespace/conflict markers,
unchanged PR-specific files/records against their parent and main-origin files
against theirs. Run relevant recon/decision/actuator withholding tests and audit
guard/chart parity/render controls for new main. Use isolated KUBECONFIG=/dev/null,
USE_EXISTING_CLUSTER=false, no envtest existing cluster. Retain exact commands,
pins/results/limitations in this new round folder; never replace prior reports.

Commit a normal merge with configured Git author and no AI trailers. Do not push,
change Draft/base state, merge GitHub PR, deploy or invoke live E2E manually. Lead
independently reviews and publishes the existing PR branch after acceptance.
GitHub-triggered checks on normal publication retain existing user authorization;
no broader infrastructure mutation. Signed root, 2026-09-10.
