# PR163 conflict resolution and PR164 compatibility

Date: 2026-09-10. Executor: deploy-worker. Scope: local conflict resolution and
isolated verification only; independent lead review is separate. No published PR
merge, branch retarget, force-push, cluster change or live E2E was performed here.

## Exact source anchors

- PR163 original: `33ab1b0b7d1dc4092b3954a8aef09f13f2497248`.
- Main merged into PR163: `0db24b0b61f45d07c4650af99e8e480c5fe4f86d`.
- PR163 merge commit: `9f070b1a41adb9a70085fb0cc3099b717462eaea`.
- PR163 tested merge tree: `f575993c552b910f614d975cf10eb9921de98bd8`.
- PR164 unchanged original: `d1cf3aca8a774de8c8f29314e11d908b37777df5`.
- PR164 plus updated PR163 tested tree: `a2ae3e632c0b1efd6ee60ac92f83089567f1270f`.

PR164 continues to target `parallel/knowledge-m035-withhold-endpoint-cover`.
It was not retargeted to main. This report is an evidence-only follow-up to the
tested PR163 merge; it changes none of those tested production files.

## Conflict and preservation checks

`git merge --no-ff --no-commit 0db24b0b61f45d07c4650af99e8e480c5fe4f86d`
in the clean PR163 worktree produced exactly one conflicted file:
`workflow/fixes/INDEX.yaml`. M-035 and DEPLOY-AUTOSYNC entries were both retained,
then the index was regenerated with the repository's `sync-index` command.
There was no production source conflict or manual production edit.

The following read-only comparisons produced no differences:

```sh
git diff --name-only 33ab1b0b7d1dc4092b3954a8aef09f13f2497248 9f070b1a41adb9a70085fb0cc3099b717462eaea -- workflow/fixes/M-035
git diff --name-only 0db24b0b61f45d07c4650af99e8e480c5fe4f86d 9f070b1a41adb9a70085fb0cc3099b717462eaea -- workflow/fixes/DEPLOY-AUTOSYNC
```

Signed historical evidence, source pins and fix status files were not rewritten.
`sync-index --check` passed, and a set-equality check between indexed fix IDs and
all non-template `*/STATUS.yaml` directories passed: 16 in PR163, 17 in the PR164
merged candidate. `git diff --cached --check` passed for both candidates.

## PR163 package tests

Toolchain: Go 1.26.1 darwin/arm64; no cluster credentials used.

```sh
env GOPATH=/private/tmp/phorvex-review-go GOCACHE=/private/tmp/phorvex-review-go-cache GOPROXY=off GOSUMDB=off KUBECONFIG=/dev/null GOMAXPROCS=2 /private/tmp/phorvex-go-toolchain.3MV9Wy/go/bin/go -C phorvex test -p 2 ./internal/recon ./internal/decision ./internal/actuator ./internal/audit -count=1
```

Exit 0. Output:

```text
ok  github.com/phorvex/phorvex/internal/recon     0.571s
ok  github.com/phorvex/phorvex/internal/decision  7.746s
ok  github.com/phorvex/phorvex/internal/actuator  0.956s
ok  github.com/phorvex/phorvex/internal/audit     1.986s
```

These full package runs include the M-035 producer, downstream selection and
preserved locator controls, plus the audit persistence changes imported from main.

## Workflow packaging, both candidates

Run separately in each candidate worktree with Python 3.11.10 and Helm 3.16.4:

```sh
TMPDIR=/private/tmp PATH=/private/tmp/phorvex-pr144-venv/bin:/private/tmp/phorvex-console-preflight-tools.7fZ5vK:/opt/homebrew/bin:/usr/bin:/bin bash workflow/tools/check.sh
```

Both exited 0. Retained result summaries:

```text
PR163: Ran 113 tests in 37.120s
OK (skipped=5)
fix index: PASS
issues render: PASS
doctor: 0 error(s), 17 warning(s)

PR164 merged candidate: Ran 113 tests in 41.020s
OK (skipped=5)
fix index: PASS
issues render: PASS
doctor: 0 error(s), 17 warning(s)
```

The five skips and 17 historical warnings were not waived or newly repaired.
Warnings concern previously unavailable local evidence, legacy missing verify
scripts, pending main/release synchronization and historical anatomy reviews.
An initial PR163 invocation used a Python PATH without `jsonschema` and stopped
before tests; the explicit Python 3.11 environment above corrected that environment
setup. No source change was needed to obtain the passing executions.

## PR164 updated-target simulation

`git merge-tree --write-tree d1cf3aca8a774de8c8f29314e11d908b37777df5 9f070b1a41adb9a70085fb0cc3099b717462eaea`
exited 0 with tree `a2ae3e632c0b1efd6ee60ac92f83089567f1270f`: no conflict.
The same clean merge was performed with `--no-commit` in the isolated PR164
worktree for actual package and workflow execution. Both M-035 and M-037 fix
directories remained byte-identical to the original PR164 tip.

```sh
env GOPATH=/private/tmp/phorvex-review-go GOCACHE=/private/tmp/phorvex-review-go-cache GOPROXY=off GOSUMDB=off KUBECONFIG=/dev/null GOMAXPROCS=2 /private/tmp/phorvex-go-toolchain.3MV9Wy/go/bin/go -C phorvex test -p 2 ./internal/recon ./internal/capability ./internal/decision ./internal/actuator ./internal/audit -count=1
```

Exit 0. Output:

```text
ok  github.com/phorvex/phorvex/internal/recon       0.373s
ok  github.com/phorvex/phorvex/internal/capability  0.635s
ok  github.com/phorvex/phorvex/internal/decision    8.181s
ok  github.com/phorvex/phorvex/internal/actuator    0.698s
ok  github.com/phorvex/phorvex/internal/audit       3.002s
```

These full package runs include both M-035 endpoint withholding and M-037
fingerprint withholding tests and legitimate action controls.

After successful tests, only that worker-created uncommitted merge was aborted
with `git merge --abort`. `git status --short` was empty, and both HEAD and local
`review/pr164-conflicts` still resolved to the unchanged original
`d1cf3aca8a774de8c8f29314e11d908b37777df5`. No child branch update is necessary
to make PR164 mergeable against the updated parent.

## Limits

This verifies conflict integration and the affected isolated packages, not all
remote CI, deployment, live mitigation or a new signature of historical M-035/M-037
fix evidence. Independent lead review and published SHA checks precede pushing
the PR163 update. PR164 needs no push while its base remains this parent branch.
