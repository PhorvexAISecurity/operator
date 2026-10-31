# Benchmark bot

A Telegram bot for benchmarking brain changes before they are merged. You
describe a change in words, or name a parameter and values. The bot replays the
**recorded production ticks** with the changed brain and with the deployed brain,
and returns the comparison as a summary, `report.html` and `metrics.csv`. It also
accepts declarative JSON studies comparing configured Cost/History reference
algorithms on explicit recorded or synthetic trace inputs; see [STUDIES.md](STUDIES.md).

Experiments are offline replay or labelled reference studies. No cluster is created or touched, no
action is dispatched, nothing is merged or pushed, and the repository and the
dashboard's data are only read. Replay measures how the decision engine
responds to recorded states. It does not measure defense rates or SLO effects;
those need the live lab (`benchmark/run.sh`, still being built).

## Commands

| Command | What happens |
|---|---|
| `/bench [policy=ns/name] [ticks=N] [nosync] <change in words>` | The steps below. |
| `/param <P-XXX-000> <value> [value...] [policy=...] [ticks=N] [nosync]` | A Math Lab parameter experiment, run by the dashboard: the deployed brain replayed with each value. Comparison status `MATCHED_REPLAY`. |
| `/study` | Help for JSON studies: configurable reference algorithms, arms, seeds, history and trace evidence. |
| `/guide` | Sends the English step-by-step playbook to the requesting chat as HTML and PDF attachments. |
| `/upload` | File-submission instructions. Upload a JSON study or a `.md`, `.txt` or `.docx` code/parameter document to execute its valid experiments automatically. |
| `/validate` | Use as an uploaded document's caption to validate structure and values without queuing anything. |
| `/templates` | Download ten examples: five code/parameter files, three Cost/History studies and two paired endpoint V2/V3 requests. |
| `/status`, `/runs`, `/cancel`, `/check`, `/help` | The running job and queue, the last results, stop after the current step, dependency checks, usage. |
| `/invite` | Owner only, in private chat: a one-use member invitation valid for 24 hours. |

The bot's responses, command descriptions, name and profile text are in English.
Startup sets the default, English and Persian locale profiles to the same
English text so a previous Persian override cannot hide the new menu.

`/guide` is available to authorized owners and members. Uploads run separately
from the benchmark queue, with duplicate requests in the same chat suppressed
while a download is in progress. Upload failures are reported in English and
can be retried. Releases include [guide-en.html](guide-en.html) and
[guide-en.pdf](guide-en.pdf); the PDF is rendered from that HTML before release,
so serving the guide needs no browser or PDF generator on the host. Update both
English and Persian HTML/PDF files together after editing the guides. The HTML's Print / PDF button provides
the print layout, including expanded FAQ answers.

The complete playbooks cover all three workflows, file uploads, `/validate`
captions, `/templates`, study evidence/statuses, batch summaries and activity
cards in both languages. The offline HTML includes a command builder and a
JSON study file builder with the three bundled templates, editable policy,
seeds, epsilon and history window, and download-time input checks:

- English: [HTML](guide-en.html), [PDF](guide-en.pdf).
- Persian: [HTML](guide-fa.html), [PDF](guide-fa.pdf).

Keep the embedded study examples in both HTML files synchronized with
`templates/study-*.json`; validate downloaded files with the actual request
parser and render both PDFs again after HTML changes.

The bot's `/guide` command delivers the English pair. The Persian edition is a
separate reading aid; keep command names, document keys and numeric digits in
the examples as written.

## Uploading experiment files

For Cost/History studies, upload a complete JSON request using the three study
templates or the guide's file builder. `/study` displays help; the attachment
starts the experiment. `/validate` as the attachment caption checks structure
without running it. JSON may also be saved as UTF-8 `.txt`; do not mix JSON with
the legacy sections below. Recorded studies require a normalized dataset;
passing validation or `/check` does not prove that dataset is available. See
[STUDIES.md](STUDIES.md) for inputs, limits and result interpretation.

The rest of this section describes legacy code/parameter files.

Upload a document directly into the chat. An authorized account can use either
`[bench]` / `[params]` sections (also `## Bench` / `## Params` headings), or a
file containing one complete `/bench` or `/param` command per line. Each section
has its own `policy`, `ticks` and `sync` options. Put options before `change:`;
the brain change may continue over several lines. Parameter entries use a
registry ID followed by numeric trial values, separated by spaces or commas:

```text
[bench]
policy: vllm/vllm-defense
ticks: 64
sync: false
change:
In phorvex/internal/decision/ablation.go, add one explanatory comment before
the existing if base.Ratio > 0 branch. Preserve executable code and behavior.

[params]
policy: vllm/vllm-defense
ticks: 64
sync: false
P-FEA-006: 1.0 1.2 1.5
```

Either section can be omitted. A present empty/invalid section rejects the
whole upload: nothing is queued until every section, option and registry value
parses. This structural validation does not establish that proposed code
compiles or passes tests; Go tests and runtime replay preflight remain mandatory.
Use the `/validate` caption (forward slash) for structural validation only.
Unknown captions, including `\validate`, are rejected without downloading or
queuing the file. Use an empty caption or `/upload` to run. Google Docs should
be exported as `.docx` or text; legacy binary `.doc` is not supported.

An accepted file becomes one batch of up to five independent experiments,
executed in file order by the existing single worker. A parameter section with
two IDs creates two experiments. Each experiment has its own control and report;
parameters are not overlaid onto the code candidate. A runtime failure is
reported and independent remaining experiments continue. `/cancel` cancels the
current batch and skips its remaining experiments. The batch finishes with
JSON/CSV summaries and `DONE`, `PARTIAL`, `FAILED` or `CANCELLED` status.

Uploads and `.json` study text are capped at 2 MiB; text extracted from other
extensions, including JSON saved as `.txt`, is capped at 256 KiB. DOCX extraction reads
paragraphs from the main document only, without loading external links or
executing macros. ZIP expansion and XML declarations are bounded/rejected.
Originals and normalized `VALIDATION.json` records remain privately under
`BOT_STATE_DIR/uploads/<id>/`; each batch keeps `BATCH.json` in its job folder.
Completed examples are bundled in [templates/](templates/).

## Activity and progress

Queued jobs show a waiting card. Running jobs, file download/validation, guide
and example uploads, dependency checks and invitation creation show an editable
activity card with the current task and elapsed time. While a backend call or
build blocks, the card refreshes every eight seconds. The moving bar indicates
activity; it does not invent a completion percentage or ETA. Batch cards include
the experiment number and task. Cards end as done, partial, failed, cancelled or
interrupted. Telegram edit failures do not abort an experiment. Restart notices
mark in-flight cards interrupted so unfinished work can be resubmitted.

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
  `phorvex/tools/`. New `_test.go` files may be added; existing tests cannot be
  changed, deleted or renamed. No deletes, merges or pushes. The diff
  applies to a clone, never to `BOT_REPO`.
- **Planner context:** named Go paths prioritize their package, adjacent tests
  and read-only `go.mod`. Existing tests are reference context, not editable
  targets. A declined request records the model's bounded, redacted reason when
  supplied; structural validation still does not guarantee a feasible patch.
- **The deployed binary is checked** against its recorded sha256 before it
  is trusted. That binary's `git_sha` is the base's provenance, so the base
  commit needs no tag.
- **Disk guard:** `/bench` refuses to start while free disk is below
  `BOT_MIN_FREE_GB` (default 4). It needs two checkouts and a Go build, and it
  must never fill the host. Clones use `--shared`, so objects are borrowed
  from `BOT_REPO` rather than copied.
- **Build-cache retention:** bot builds use `BOT_STATE_DIR/go-build-cache`,
  separate from the account's global Go cache. Before and after a code job,
  the single worker removes oldest disposable cache entries to retain at most
  2 GiB and, when possible, recover the configured free-space minimum. This is
  a retention limit between jobs, not an in-progress filesystem quota. A cold
  build may use more space, and other services can still exhaust the disk.
  Reports, replay evidence, modules, SDKs and unrelated caches are retained.
  Cleanup counters are stored as `storage-before.json` and `storage-after.json`.
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
  evidence (`experiment/evidence.zip`). The clones and temporary Go home are
  deleted after each job. A model's recorded decline reason is also shown in
  the failure message; a missing implementation or input is not a successful
  benchmark merely because the file's structure passed validation.

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
## Dynamic Cost and History studies

The bot also accepts versioned JSON studies with configurable comparison arms,
seeds, explicit trace evidence and independent history. These run reference
algorithms without LLM code generation. Start with `/study` and the JSON examples
from `/templates`. See [the study contract and evidence requirements](STUDIES.md).
Synthetic examples are executable demonstrations, not production results; missing
recorded ledgers return `NEEDS_DATA` with an explanation.

## Paired endpoint-cost V2/V3

See [ENDPOINT-V3.md](ENDPOINT-V3.md). Upload `endpoint-v3-synthetic.json` for the labelled 64-tick Go reference test, or `endpoint-v3-recorded.json` for qualified recorded inputs. Missing recorded telemetry returns BLOCKED with artifacts before model/build work. A successful synthetic study does not establish readiness of historical production data. Build and include `benchmark/endpointv3/bin/endpoint-v3` and `BUILD.json` in each bot release.

The code planner can request bounded file, package and line-range reads plus literal source searches from the pinned baseline commit. Four read rounds are separate from patch retries. Missing source context is resolved from the repository when available; actual missing telemetry remains an explicit blocker.

Context reads preserve the prior assistant requests and complete Responses output items across turns, following the [OpenAI conversation-state guidance](https://developers.openai.com/api/docs/guides/conversation-state). Source is consolidated within the configured byte cap; a completed read is not restarted as a new stateless request.

Responses requests use `store: false` and explicitly request encrypted reasoning content so subsequent source reads carry their own state, without depending on stored response items at the configured gateway. This follows the [stateless reasoning guidance](https://developers.openai.com/api/docs/guides/reasoning). The returned output remains in memory and is excluded from `PLAN.json`.
