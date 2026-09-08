# Implement and verify: AGREED → PR_READY

Read status, agreed decision, and the necessary source. The implementer owns
code and offline evidence; the skeptic owns P3 and must not silently repair
the patch they are reviewing.

1. Implement in an isolated code worktree at the reviewed baseline. Record
   branch/base/head using implementer-owned `configure` inputs. If base changed,
   skeptic signs `base_review` against the new base and original analysis before
   implementation acceptance; keep the original seal. Regenerate `04-diff.patch` with
   `git diff --binary <base> <head>`; no unrelated edits.
2. Prove RED at the intended assertion on the baseline, then GREEN at head.
   Run L0 build/unit/static checks, L1 invariants, and L2 multi-tick comparisons.
   Record exact commands, results and positive controls in immutable raw files;
   summarize criterion→artifact in `05-evidence.md`.
   Fill `evidence/incident.md`: use realistic inputs through the production
   producer and changed path; assert the fixture produces the decisive values.
   Compare baseline/head outcomes and preserve a legitimate positive control.
   Test relevant bypasses, compound-predicate arms, stale/missing inputs and
   boundaries. Manually setting the final flag proves only the local branch.
3. Sign `implementation`, `red`, `l0`, `l1`, `l2`, `positive_control` using
   `record-check`. Missing layers are unavailable or explicitly waived; a
   pending field cannot pass a transition.
4. Skeptic independently compares the complete diff to the agreed scope,
   challenges RED/test fidelity and behavioral predictions, and attempts at
   least one adversarial case. Independently reproduce the incident trace,
   sign `incident`, then write `evidence/p3/verdict.md` and sign `p3`. Missing or
   non-discriminating incident evidence blocks P3 even with green unit tests.
   Changing the signal, scope or incident evidence requires renewed review.
5. Pass → `DIFF_REVIEW_PASSED` → `PR_READY` → push/open PR under recorded scope;
   failure returns to implementation with counter-evidence. Do not create the
   final verdict at P3. Required live verification remains explicit in the PR.

Rebase changes the pins: regenerate the patch and revalidate affected checks.
A signed `patch_equivalence` is required when PR reviewed head differs from
implementation head. It does not turn stale test evidence into current evidence.

Handoff: reviewed head, P3 artifact, test results, unresolved risk, PR scope.
Default named-fix delivery includes `pr_open`; do not ask again or stop at PR_READY.
