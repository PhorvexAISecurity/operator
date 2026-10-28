# Benchmark bot

A Telegram bot for benchmarking brain changes before they are merged. You
describe a change in words, or name a parameter and values. The bot replays the
**recorded production ticks** with the changed brain and with the deployed brain,
and returns the comparison as a summary, `report.html` and `metrics.csv`.

Everything is replay on recorded states. No cluster is created or touched, no
action is dispatched, nothing is merged or pushed, and the repository and the
dashboard's data are only read. Replay measures how the decision engine
responds to recorded states. It does not measure defense rates or SLO effects;
those need the live lab (`benchmark/run.sh`, still being built).

## Commands

| Command | What happens |
|---|---|
| `/bench [policy=ns/name] [ticks=N] [nosync] <change in words>` | The steps below. |
| `/param <P-XXX-000> <value> [value...] [policy=...] [ticks=N] [nosync]` | A Math Lab parameter experiment, run by the dashboard: the deployed brain replayed with each value. Comparison status `MATCHED_REPLAY`. |
| `/status`, `/runs`, `/cancel`, `/check`, `/help` | The running job and queue, the last results, stop after the current step, dependency checks, usage. |
| `/invite` | Owner only, in private chat: a one-use member invitation valid for 24 hours. |

`/bench` runs these steps:
1. An LLM writes the change against the **deployed** commit (`planner.py`).
2. The change lands on a throwaway branch (`candidate.py`).
3. Uncached Go unit tests run on both commits: `internal/decision`,
   `cmd/brain-replay`, and each changed package. A failure stops the job and
   returns its full test log. These are targeted unit tests, not the full CI suite.
4. `brain-replay` is built twice: from the deployed commit and from the
   candidate (`replay_build.py`).
5. Three arms are replayed on the same ticks (`code_experiment.py`).

Defaults: `policy=vllm/vllm-defense`, `ticks=500`, chosen evenly across the
corpus. Each command first syncs fresh ticks through the dashboard, unless you
say `nosync`. One job runs at a time, and up to 5 wait in a queue.
Code experiments filter snapshots by the deployed source commit **before**
sampling and freeze the selected digests. Parameter experiments use the latest
contiguous window from that revision through the dashboard's time filters.

## Reading a `/bench` result

| Arm | What it is | Expected |
|---|---|---|
| `control` | The deployed `brain-replay`. A tick counts only if it reproduces production byte for byte. | — |
| `base-local` | The deployed commit, built on the host. | **M-P21 = 0** and fidelity `EXACT`. If it shows `DIVERGED`, the local build does not stand for the deployed one, and neither does the candidate. |
| `candidate` | The LLM's commit, replayed with `-allow-cross-version`. | Its numbers are the answer. Status `OBSERVATIONAL`, because it is another revision. |

**M-P21** (changed-decision share) is the share of ticks on which the candidate
selects differently from production. The report also shows M-P26 (moves per
tick), M-P19 (no-op under attack), M-P22, M-P25 and M-P28, each with its
interval. A missing value is shown as missing, never as 0. `/bench` also returns
the candidate diff and `tests.json` with both commits, test packages and counts.
When the local base reproduces control and candidate coverage is complete,
the report also shows the observed metric deltas. A changed-decision percentage
is not an improvement score; fewer moves may be helpful or harmful depending
on the hypothesis and safety metrics.

## Safety

- **Only authorized users are served.** Configured/paired owners and users who
  consumed a valid owner invitation can use the commands. Everyone else gets
  no reply; their id is logged for the operator.
- **No replay of old commands.** The first start skips any waiting backlog,
  and the offset is persisted, so a restart never re-runs a command.
- **Candidate scope** (`candidate.py`): only `phorvex/**/*.go`, never
  `phorvex/tools/` or `_test.go`. No deletes, merges or pushes. The diff
  applies to a clone, never to `BOT_REPO`.
- **The deployed binary is checked** against its recorded sha256 before it
  is trusted. That binary's `git_sha` is the base's provenance, so the base
  commit needs no tag.
- **Disk guard:** `/bench` refuses to start while free disk is below
  `BOT_MIN_FREE_GB` (default 4). It needs two checkouts and a Go build, and it
  must never fill the host. Clones use `--shared`, so objects are borrowed
  from `BOT_REPO` rather than copied.
- **Isolated replay.** `brain-replay` runs with no credentials (Math Lab's
  `run_isolated`), and it has no network or Kubernetes client.
- **Unit-test environment.** Builds and tests use a separate home directory,
  no inherited service/cloud secrets, `KUBECONFIG=/dev/null` and
  `USE_EXISTING_CLUSTER=false`. Builds use at most two workers; test packages
  run one at a time so deadline checks do not compete with another test package.
- **Secrets stay out of output.** The Telegram token, the dashboard password
  and the OpenAI key are never logged or sent. The tests check this.
- **Job directories** (`BOT_STATE_DIR/jobs/<id>`, mode 700) keep the prompt,
  the diff, `PLAN.json`, `CANDIDATE.json`, the build logs and the full Math Lab
  evidence (`experiment/evidence.zip`). The clones are deleted after each job.

## Launching it on the jump host

Run these as `hami`, after the dashboard is installed (`benchmark/deploy`). The
bot can live in its own release directory, so installing it neither moves the
dashboard's `current` nor restarts the dashboard.

1. **Rotate the leaked secrets first.** The bot token, the SSH password, the
   GitHub token and the OpenAI key were all shared in plain text in chat:
   - in BotFather, run `/revoke`, then `/token`, to get a new bot token;
   - make a new OpenAI key;
   - change the SSH password;
   - revoke the GitHub token.
2. **Unpack a release that contains `benchmark/bot`** into
   `~/phorvex-benchmark/releases/<name>`. That is all; do not run the
   dashboard's `install.sh`.
3. **Set `BOT_REPO` for `/bench`.** It must be an operator clone that holds the
   deployed brain's commit, the `git_sha` in `data/mathlab/bin/current.json`.
   The bot only reads it, by commit. After each deploy, fetch there so the new
   commit is present.
4. **Make sure Go works.** `go version` must succeed, and the host needs egress
   to `proxy.golang.org`. The bot reads the exact Go release from the verified
   deployed binary with `go version -m` and pins `GOTOOLCHAIN` to it for both
   tests and both builds. `--check` shows the installed SDK and replay toolchain;
   the test artifact retains the selected release.
5. **Configure.** Copy the example and fill in every value:
   ```sh
   cp benchmark/bot/deploy/bot.env.example ~/phorvex-benchmark/config/bot.env
   chmod 600 ~/phorvex-benchmark/config/bot.env
   ```
   For `BOT_ALLOWED_USER_IDS`, use your numeric Telegram id. If you don't know
   it, install with any number, message the bot once, and read the "ignored a
   message from Telegram user id N" line in the log.
6. **Install and start:**
   ```sh
   bash ~/phorvex-benchmark/releases/<name>/benchmark/bot/deploy/install.sh ~/phorvex-benchmark/releases/<name>
   ```
   This runs `service.py --check` under systemd, with the service's own
   environment. The check prints PASS, WARN or FAIL for the token, the
   allowlist, the state directory, the dashboard login, the deployed brain and
   its recorded ticks, whether the operator clone holds the deployed commit,
   free disk, go and OpenAI. It prints no secrets.
   The script then enables and starts `phorvex-benchmark-bot`, which survives
   logout and reboot through lingering.
7. **In Telegram,** send `/help`, then for example:
   ```
   /param P-FEA-006 1.2 1.5 1.8
   /bench raise the rotate threshold for vllm so fewer ticks rotate
   ```
   Logs: `journalctl --user -u phorvex-benchmark-bot -f`.

For one-time owner setup without manually editing the allowlist, an operator
may leave `BOT_ALLOWED_USER_IDS=0` and create `BOT_STATE_DIR/pairing.json`
(mode 600) with `sha256` of a cryptographically random Telegram `/start`
payload and an `expires_at` Unix timestamp. Share the corresponding start link
privately with the owner. The bot accepts it only in a private chat, consumes
it once, and stores the owner id in mode-600 `owner.json`. Expired, invalid or
reused links cannot authorize another account. An explicit nonzero env allowlist
takes precedence over the stored owner.

After pairing, use `/invite` in the owner's private chat to add another
account. Each link grants benchmark-command access to one new member, expires
after 24 hours, and works only in a private chat. It preserves the current
owner. Invited members cannot create invitations. Membership is stored in
mode-600 `members.json`, bound to the inviter's current owner status, and
survives a service restart. Invite files contain only token hashes, expiration
and inviter metadata; raw links are returned only to the owner.

The existing dashboard gateway uses `OPENAI_BASE_URL=https://codex.algoty.com/v1`
and `OPENAI_API=responses`; it is not the public OpenAI endpoint. The planner
also supports the public Chat Completions API with `OPENAI_API=chat` (default).
Responses uses `instructions`, `input` and structured reasoning options as
documented in [OpenAI text generation](https://developers.openai.com/api/docs/guides/text).

## Modules

| File | Role |
|---|---|
| `service.py` | The bot: config, allowlist, commands, job queue, `--check`. |
| `telegram.py` | Bot API client: long polling, messages, documents. |
| `dashboard.py` | Math Lab API client: login, sync, preflight, create, wait, metrics, artifacts. |
| `planner.py` | Prompt to unified diff with an OpenAI model. The model is set by env and never hard-coded. |
| `candidate.py` | Diff to a throwaway branch and tag, behind the scope guardrails. |
| `replay_build.py` | `brain-replay` from a commit, built as the Dockerfile builds it, for the host. |
| `code_experiment.py` | The three-arm code experiment, on the Math Lab worker's own analysis and exports. |
| `report.py` | Summary text, HTML page and CSV. |
| `deploy/` | The systemd user unit, `bot.env.example` and `install.sh`. |

## Tests

```sh
python3 -m unittest discover -s benchmark/bot -p 'test_*.py'
```

The tests run offline. They need the worker requirements (`openpyxl`), which
CI installs. Telegram and OpenAI are fake transports, and the dashboard client
runs against a local server that enforces the real cookie, Origin and status
rules. `testkit.py` provides a small operator repository whose brain decides by
a threshold, plus a fake `go` that compiles that threshold into a fake
`brain-replay` with the real CLI and output schema. So a `/bench` test really
changes decisions, end to end, from a Telegram message to the files sent back.

## What is not done yet

- **The live lab.** Attacks and actuators on fixture apps in a throwaway EKS
  cluster (ticket Parts 1–2: `run.sh` P2–P7, the fixtures, `harness281`) are
  not wired to the bot yet. That will be a separate `/lab` command once
  `run.sh` runs end to end.
- **Validation evidence.** See `VALIDATION.md` for executed checks,
  replay evidence, source access and remaining limitations. A healthy
  Telegram service or a successful archived smoke test does not establish that
  the currently deployed source and snapshots are available.
