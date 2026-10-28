# Benchmark lab

The self-service PHORVEXSEC-281 benchmark: one throwaway EKS lab per run, Old
brain against New brain (shadow-only), deleted by tag afterwards. The ticket is
`A-TICKET-benchmark-self-service.md`. Delivery order (DR-48): Part 3 (this
directory's `build-image.sh`), then Part 2 `run.sh`, then Part 1 fixtures.

## Part 3: `build-image.sh`, the brain under test as a pinned image

```sh
benchmark/lab/build-image.sh --run-dir D --run-id 1a2b3c --ledger D/CREATED.json \
  --src-repo <working repo> --tag manager-v0.11.0 \
  --commit 8acb43ad7ce088460a457e3055d74c53df5e67a5 --account 753556437180
```

The ledger must already exist as `{"runId":"<id>","entries":[]}`. A tag that
is not in the local repository comes through `--src-remote URL`, with
`--git-askpass HELPER` printing the token from a 0600 file; a URL with embedded
credentials is refused.

Steps:

1. The tag is cloned into `D/src` and checked out detached at `--commit`. The
   working repository is only read. Global and system Git configuration are
   off, so no hook, URL rewrite or credential helper runs.
2. The whole `deploy/docker/operator.Dockerfile` must have a sha256 that
   `images.lock` lists. Any other sha256 is drift (exit 18).
3. `pendingcheck` runs, then the Dockerfile's two build sets are built with
   `go build` (go1.26.1, linux/amd64, `-mod=readonly`). Build set one carries
   `linkedGitSHA` and build set two never does; both are asserted. A second build
   with an empty build cache records `reproducible`.
4. The binaries become one root-owned layer on the pinned distroless base
   (`crane mutate`). It is pushed to the new IMMUTABLE repository
   `phorvex-281-temp-<id>`, tagged `phorvex.ai/lab-run`, `phorvex.ai/benchmark`
   and `phorvex.ai/lab-expires`.
5. The pushed image is checked: user 65532:65532, entrypoint `/manager`,
   workdir `/`, and exactly the base's layers plus one. The registry login lives
   only in `D/dockercfg`, which is deleted immediately afterwards.
6. `D/IMAGE.json` is written (schema in ticket Part 3 §12). `D/build/rootfs`
   keeps `brain-replay` for the tick-0 replay.

Chart mapping: `phorvex.image.repository` ← `repository`; `.tag` ←
`commit[0:8]`; `.releaseDigest` ← `digest`; `.releaseSourceSHA` ← `commit`.

The only ECR writes are the create and the push. In a `run.sh` run,
`teardown-by-tag.sh` deletes the repository. `build-image.sh --delete --run-id
ID --ledger L --account A` exists for standalone tests only: it deletes the
repository only if it is tagged with this run and not recorded as a collision,
and it proves `RepositoryNotFoundException`.

Exit codes: 10 bad arguments, ledger or AWS account; 11 clone or ref mismatch;
13 pendingcheck; 14 build; 15 registry create or push; 16 name collision;
17 delete not proven; 18 Dockerfile drift.

Tools: git, jq, GNU tar, sha256sum, go (any version that can fetch go1.26.1),
crane 0.20.2, AWS CLI v2.

### `images.lock`

- **Base:** the distroless base, pinned by digest. It cites the repo line it comes from.
- **Go toolchain:** go1.26.1.
- **Dockerfiles:** each reviewed `operator.Dockerfile` sha256 with its two build
  sets.

When the Dockerfile changes, a tag built from it exits 18 until someone adds its
sha256 and build sets in a reviewed change. `tests/test_build_image.py` parses
every listed Dockerfile from the manager tags and fails if a build set, rename
or `COPY` differs.

### Deviations from the ticket, for the field-19 reviews

1. **Two Dockerfile revisions, not one.** The ticket hashes HEAD at `59b8cc74`,
   whose Dockerfile equals `manager-v0.11.0`'s (`658cccfa…`, six binaries).
   Since `c1e9d5f0` (manager-v0.12.0), main's Dockerfile is `b5f2276a…`, which
   adds `persistence-observer` and `cost-budget-admin`. A New tag from
   today's main would otherwise always exit 18, so both are listed.
2. **Base `gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872…`**, from
   `build/integrations/epss-ecr-auth-runtime/Dockerfile:9`. The ticket names
   `static:nonroot@<run-2 digest>`. The floating `static:nonroot` now resolves
   to `sha256:18f4cc26…`, and the repo-pinned digest exists only under
   `static-debian12`. Compare it with the run-2 digest (E-B-18) once
   `B-VERIFICATION-REPORT.md` is available.
3. **`-buildvcs=false`** is added to `GOFLAGS`. The Docker build has no `.git`
   in its workspace, so its binaries carry no VCS stamp. A clone does have
   `.git`, and without this flag every binary, including build set two, would
   embed the commit.
4. **The layer tarball** also uses `--sort=name --mtime=@0`, so the layer is
   reproducible. The rootfs directory is created with mode 0755: under
   umask 077 the layer's `./` would otherwise be 0700, and the nonroot user
   could not reach `/manager`.
5. **Order of steps:** the reproducibility rebuild runs before the ECR create,
   with a fresh `GOCACHE`, so a failed rebuild creates nothing. The image
   checks run after the push but before `dockercfg` is deleted, because they
   need the registry login.
6. **Unspecified details:** the AWS account is checked
   (`sts get-caller-identity`) before anything else, and a mismatch exits 10.
   `--expires` (default: now + 6 h) sets `phorvex.ai/lab-expires`. The ledger
   entry is `{kind, name, region, account, expires, at, status}`, where status
   is creating, created, collision or failed; DR-40's own schema is in the
   unavailable `C-DECISION-REGISTER.md`. The stamp check uses `grep -a`, not
   `strings`, so binutils is not needed.

### Tests

```sh
python3 -m unittest discover -s benchmark/lab/tests -v
```

Offline: `tests/stubs` replaces aws, crane and go. Covered: TP-1, TP-2, TP-4,
TP-6, TP-7, TP-8 and TP-9; TP-3 and TP-5 through stubs. The tests also check
images.lock against the repository's own Dockerfiles.

These need a real registry or the lab:

- TP-3 and TP-5 against ECR;
- TP-10 (the startup `linkedGitSHA`), which runs in Part 2.
