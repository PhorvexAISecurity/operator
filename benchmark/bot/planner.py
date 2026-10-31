#!/usr/bin/env python3
"""Turn a natural-language brain-change request into a unified diff, with an LLM.

This is the non-deterministic step of the benchmark bot's "LLM rewrites brain
source" path. It gathers relevant brain source from the base commit (read only,
through `git show`), asks an OpenAI chat model for a unified diff that changes
only files the candidate step would accept, and checks that boundary before the
diff ever reaches candidate.py. If the model answers with prose or an
out-of-scope diff, it is told why and asked again, up to --max-attempts.

The planner proposes; candidate.py applies with its own guardrails; a human
decides whether to keep the result. Nothing here edits the repository or calls
the cluster, and the API key is read from the environment and never logged.

Configuration (flags override environment):
  OPENAI_API_KEY        required; the bearer token, never written anywhere
  OPENAI_MODEL/--model  required; the chat model id (set to the model you have)
  OPENAI_BASE_URL       default https://api.openai.com/v1
  OPENAI_REASONING_EFFORT, OPENAI_TEMPERATURE   optional, passed through if set

Usage:
  planner.py --src-repo REPO --base-commit SHA --prompt-file P \
    --out-diff D/brain.diff --out D/PLAN.json \
    [--context phorvex/internal/decision/decision.go ...] \
    [--model M] [--max-attempts 2] [--max-context-bytes 200000]

Exit codes: 2 bad arguments or environment; 8 no in-scope diff after retries;
9 transport or API error.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from candidate import GIT_ENV, in_scope  # noqa: E402  (shared scope rule)

SCHEMA = "phorvex-bench/plan/v1"
DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_MAX_CONTEXT = 200_000
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")
DIFF_FENCE = re.compile(r"```(?:diff|patch)?\s*\n(.*?)\n```", re.DOTALL)
DIFF_PATH = re.compile(r"^(?:---|\+\+\+) (?:[ab]/)?(.+?)\s*$")
SOURCE_PATH = re.compile(r'(?<![\w/])phorvex/(?:[A-Za-z0-9_./-]+\.go|go\.mod)(?![\w/])')
SOURCE_BASENAME = re.compile(r'(?<![\w/])([A-Za-z0-9_-]+\.go)(?![\w/])')
MAX_CONTEXT_READS = 4

SYSTEM_PROMPT = """\
You modify the Go source of the Phorvex "brain" (its decision logic) to satisfy a change request.

Output rules, strictly:
- Reply with ONE unified diff, a repository context request, or a concrete refusal.
- Use git diff headers with a/ and b/ prefixes (--- a/PATH and +++ b/PATH).
  For a new file use --- /dev/null and +++ b/PATH, with correct hunk line counts.
- Change only files matching phorvex/**/*.go. You may ADD new *_test.go files for focused tests.
  Existing *_test.go files are read-only: never modify, delete, rename or replace them.
  Never touch phorvex/tools/**, go.mod, go.sum, Dockerfiles, charts, or anything outside phorvex/.
- Source context and existing tests below are read-only reference material, not editing permission.
  To inspect more source, reply only with REQUEST_CONTEXT: followed by JSON:
  {"paths":["phorvex/internal/actionset/generator.go"],"search":["type WorkloadView"]}.
  Paths may be in-scope Go files or directories. Search strings are literal Go identifiers/text.
  The harness reads the pinned commit only; it cannot run commands or tests for you.
  Up to four bounded context requests are allowed. Request only files needed for this change.
  Large files can be read as {"path":"phorvex/internal/runner/manager.go","start":100,"end":250}.
  Never infer an implementation or telemetry is absent merely because it was not initially supplied.
- Keep the change minimal and compilable. Do not reformat unrelated code.
- If the request cannot be met within these rules, reply with NO CHANGE POSSIBLE: followed by
  one short sentence identifying the concrete blocker. Do not claim tests or replay were run.
"""


class PlannerError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _git(repo, *args, check=True):
    result = subprocess.run(["git", "-C", str(repo), *args], text=True,
                            capture_output=True, env={**os.environ, **GIT_ENV})
    if check and result.returncode != 0:
        raise PlannerError(2, f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result


def read_at_commit(repo, commit, path):
    """File bytes at a commit, without touching the working tree. None if absent."""
    result = _git(repo, "show", f"{commit}:{path}", check=False)
    return result.stdout if result.returncode == 0 else None


def rank_context_files(repo, commit, prompt, limit=40):
    """In-scope .go files at the commit, ranked by how often the prompt's
    identifiers appear in them. One git grep call; no file is read yet."""
    tokens = sorted({t.lower() for t in IDENTIFIER.findall(prompt)})
    listed = _git(repo, "ls-tree", "-r", "--name-only", commit, "--", "phorvex").stdout.splitlines()
    scoped = [p for p in listed if in_scope(p, new_test=True)]
    mentioned = list(dict.fromkeys(p for p in SOURCE_PATH.findall(prompt) if context_scope(p)))
    # Users often name economics.go without its directory. Resolve an exact
    # basename against the pinned tree rather than letting generic prose win.
    for name in SOURCE_BASENAME.findall(prompt):
        mentioned.extend(p for p in scoped if Path(p).name == name and p not in mentioned)
    if mentioned:
        # A named file scopes context to its package, even if it is a new file.
        # Put adjacent tests before generic large files; never fill a focused
        # arithmetic request with unrelated runner/console/actuator sources.
        parents = {str(Path(p).parent) for p in mentioned}
        stems = {p.removesuffix('_test.go').removesuffix('.go') for p in mentioned}
        siblings = [p for p in scoped if str(Path(p).parent) in parents and p not in mentioned]
        siblings.sort(key=lambda p: (p.removesuffix('_test.go').removesuffix('.go') not in stems,
                                     not p.endswith('_test.go'), p))
        metadata = ['phorvex/go.mod'] if 'phorvex/go.mod' in listed else []
        return list(dict.fromkeys(mentioned + metadata + siblings))[:limit]
    if not tokens or not scoped:
        return []
    pattern = "|".join(re.escape(t) for t in tokens)
    counts = {}
    grep = _git(repo, "grep", "-c", "-i", "-I", "-E", "-e", pattern, commit, "--", "phorvex/*.go",
                ":(glob)phorvex/**/*.go", check=False)
    for line in grep.stdout.splitlines():
        # "<commit>:<path>:<count>"
        _, _, rest = line.partition(":")
        path, _, count = rest.rpartition(":")
        if path in set(scoped) and count.isdigit():
            counts[path] = int(count)
    # Density prevents a giant file winning solely because common words occur
    # on more lines. Tests are eligible reference context, not editable files.
    sizes = {}
    for line in _git(repo, 'ls-tree', '-rl', commit, '--', 'phorvex').stdout.splitlines():
        meta, _, path = line.partition('\t')
        if meta.split()[-1].isdigit():
            sizes[path] = int(meta.split()[-1])
    ranked = sorted(counts, key=lambda p: (-counts[p] / max(sizes.get(p, 0), 1024), p))
    metadata = ['phorvex/go.mod'] if 'phorvex/go.mod' in listed else []
    return (metadata + ranked)[:limit]


def context_scope(path):
    return path == 'phorvex/go.mod' or in_scope(path, new_test=True)


def gather_context(repo, commit, paths, max_bytes):
    """Read the given in-scope paths at the commit, within a byte budget."""
    context, used, skipped = [], 0, []
    for path in paths:
        if not context_scope(path):
            skipped.append({"path": path, "reason": "out of scope"})
            continue
        text = read_at_commit(repo, commit, path)
        if text is None:
            skipped.append({"path": path, "reason": "absent at base commit"})
            continue
        size = len(text.encode("utf-8"))
        if used + size > max_bytes:
            skipped.append({"path": path, "reason": "context budget exceeded"})
            continue
        context.append({"path": path, "text": text, "bytes": size})
        used += size
    return context, skipped


def source_inventory(repo, commit):
    return [p for p in _git(repo, 'ls-tree', '-r', '--name-only', commit, '--', 'phorvex').stdout.splitlines()
            if context_scope(p)]


def context_request(content, repo, commit, inventory, max_bytes):
    """An intentionally narrow read protocol; model text is never shell code."""
    raw = content.strip().removeprefix('REQUEST_CONTEXT:').strip()
    try:
        request = json.loads(raw)
    except (ValueError, RecursionError) as err:
        raise ValueError('context request must be a JSON object') from err
    if not isinstance(request, dict) or set(request) - {'paths', 'search'}:
        raise ValueError('context request accepts only paths and search')
    paths, queries = request.get('paths', []), request.get('search', [])
    if not isinstance(paths, list) or not isinstance(queries, list) or len(paths) > 8 or len(queries) > 4:
        raise ValueError('context request limit: 8 paths and 4 literal searches')
    blocks, diagnostics, used = [], [], 0
    wanted = []
    for item in paths:
        if isinstance(item, str):
            name, start, end = item, None, None
        elif isinstance(item, dict) and set(item) == {'path', 'start', 'end'}:
            name, start, end = item['path'], item['start'], item['end']
            if type(start) is not int or type(end) is not int or not 1 <= start <= end or end-start > 1200:
                raise ValueError('line range must be positive, ordered and at most 1201 lines')
        else:
            raise ValueError('invalid source path request')
        if not isinstance(name, str) or not name.startswith('phorvex/') or '..' in name.split('/'):
            raise ValueError('source paths must stay inside phorvex/')
        matches = [p for p in inventory if p == name or start is None and p.startswith(name.rstrip('/')+'/')]
        if not matches:
            diagnostics.append({'path': name, 'reason': 'absent or outside readable source scope'})
        for path in matches[:24]:
            wanted.append((path, start, end))
        if len(matches) > 24:
            diagnostics.append({'path': name, 'reason': 'directory truncated to 24 files; request specific paths'})
    search_hits = []
    for query in queries:
        if not isinstance(query, str) or not 1 <= len(query) <= 120 or '\x00' in query or '\n' in query:
            raise ValueError('search must be a single literal string of 1..120 characters')
        result = _git(repo, 'grep', '-n', '-F', '-e', query, commit, '--', 'phorvex', check=False)
        count = 0
        for line in result.stdout.splitlines():
            parts = line.split(':', 3)
            if len(parts) != 4 or parts[1] not in inventory or not parts[2].isdigit():
                continue
            search_hits.append('%s:%s: %s' % (parts[1], parts[2], parts[3][:300]))
            line_no = int(parts[2])
            wanted.append((parts[1], max(1, line_no-12), line_no+22))
            count += 1
            if count == 12:
                break
        diagnostics.append({'search': query, 'matches_returned': count})
    seen = set()
    for path, start, end in wanted:
        if (path, start, end) in seen:
            continue
        seen.add((path, start, end))
        content = read_at_commit(repo, commit, path)
        if content is None:
            continue
        if start is not None:
            content = '\n'.join('%d: %s' % (i, s) for i, s in enumerate(content.splitlines(), 1)
                                if start <= i <= end) + '\n'
        size = len(content.encode('utf-8'))
        if used + size > max_bytes:
            diagnostics.append({'path': path, 'reason': 'context budget exceeded; request a narrower line range'})
            continue
        blocks.append({'path': path, 'text': content, 'bytes': size, 'lines': [start, end] if start else None})
        used += size
    return blocks, diagnostics, search_hits


def build_messages(prompt, context, previous_failure=None, inventory=None, read_notes=None):
    blocks = [f"### Change request\n{prompt.strip()}\n"]
    if context:
        blocks.append("### Current brain source (base commit, read-only)")
        for item in context:
            blocks.append(f"--- {item['path']} ---\n{item['text']}")
    else:
        blocks.append("### No source context is available. Do not invent APIs; report a concrete blocker if needed.")
    if previous_failure:
        blocks.append(f"### Your previous reply was rejected\n{previous_failure}\nReturn a corrected unified diff.")
    if inventory:
        # Full package names remain visible even when listing every test path
        # would waste the model's source budget.
        packages = sorted({str(Path(p).parent) for p in inventory})
        blocks.append('### Readable repository packages at the pinned commit\n' + '\n'.join(packages)[:20000])
    if read_notes:
        blocks.append('### Repository read results\n' + json.dumps(read_notes, ensure_ascii=False))
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": "\n\n".join(blocks)},
    ]


def extract_diff(content):
    """The unified diff in a model reply: a ```diff fence if present, else the
    text from the first diff header on. 'NO CHANGE POSSIBLE' returns ''."""
    if content is None:
        return ""
    if content.strip() == "NO CHANGE POSSIBLE":
        return ""
    fenced = DIFF_FENCE.search(content)
    if fenced:
        return fenced.group(1).strip() + "\n"
    lines = content.splitlines()
    for i, line in enumerate(lines):
        if line.startswith("diff --git ") or line.startswith("--- "):
            return "\n".join(lines[i:]).strip() + "\n"
    return ""


def diff_paths(diff_text):
    paths = []
    for line in diff_text.splitlines():
        m = DIFF_PATH.match(line)
        if m and m.group(1) != "/dev/null":
            paths.append(m.group(1))
    return paths


def scope_violations(diff_text, repo=None, commit=None):
    added = set()
    previous = None
    for line in diff_text.splitlines():
        if line.startswith('--- '):
            previous = line[4:].strip()
        elif line.startswith('+++ b/') and previous == '/dev/null':
            added.add(line[6:].strip())
    bad = []
    for path in diff_paths(diff_text):
        new_test = path in added and path.endswith('_test.go')
        if new_test and repo is not None:
            new_test = read_at_commit(repo, commit, path) is None
        if not in_scope(path, new_test=new_test):
            bad.append(path)
    return sorted(set(bad))


def openai_transport(url, headers, payload, timeout):  # pragma: no cover - network
    import urllib.error
    import urllib.request
    request = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"),
                                     headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        # Providers sometimes echo credentials in an authentication error.
        raise PlannerError(9, f"OpenAI API returned HTTP {error.code}; check the configured endpoint, key and model")
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise PlannerError(9, f"OpenAI API request failed: {error}")


def message_content(response):
    if 'output' in response or 'output_text' in response:
        if response.get('status') not in (None, 'completed'):
            raise PlannerError(9, 'OpenAI response was not completed (%s)' % response.get('status'))
        if isinstance(response.get('output_text'), str):
            return response['output_text']
        return '\n'.join(part['text'] for item in response.get('output', []) if item.get('type') == 'message'
                         for part in item.get('content', []) if part.get('type') == 'output_text')
    try:
        return response["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        raise PlannerError(9, "OpenAI API response had no message content")


def check_model(env):
    """Check real authentication and model access without generating a completion."""
    import urllib.request
    import urllib.error
    key, model = env.get('OPENAI_API_KEY', '').strip(), env.get('OPENAI_MODEL', '').strip()
    base = (env.get('OPENAI_BASE_URL') or DEFAULT_BASE_URL).rstrip('/')
    req = urllib.request.Request(base + '/models', headers={'Authorization': 'Bearer ' + key,
                                                          'User-Agent': 'PhorvexBenchmark/1.0'})
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            models = json.load(response)
    except urllib.error.HTTPError as err:
        raise PlannerError(9, 'model access check returned HTTP %s; check endpoint and key' % err.code)
    except (urllib.error.URLError, OSError, ValueError):
        raise PlannerError(9, 'model access check failed; check endpoint connectivity')
    if model not in {m.get('id') for m in models.get('data', [])}:
        raise PlannerError(9, 'configured model is not listed by this endpoint')


def plan(args, transport):
    key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not key:
        raise PlannerError(2, "OPENAI_API_KEY is not set")
    model = args.model or os.environ.get("OPENAI_MODEL", "").strip()
    if not model:
        raise PlannerError(2, "set the model with --model or OPENAI_MODEL")
    base_url = (os.environ.get("OPENAI_BASE_URL", "").strip() or DEFAULT_BASE_URL).rstrip("/")
    api = os.environ.get('OPENAI_API', 'chat').strip()
    if api not in ('chat', 'responses'):
        raise PlannerError(2, 'OPENAI_API must be chat or responses')
    url = f"{base_url}/" + ('responses' if api == 'responses' else 'chat/completions')
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json", "User-Agent": "PhorvexBenchmark/1.0"}

    prompt = Path(args.prompt_file).read_text()
    if not prompt.strip():
        raise PlannerError(2, "the prompt is empty")

    paths = args.context or rank_context_files(args.src_repo, args.base_commit, prompt)
    context, skipped = gather_context(args.src_repo, args.base_commit, paths, args.max_context_bytes)
    inventory = source_inventory(args.src_repo, args.base_commit)

    extra = {}
    if os.environ.get("OPENAI_REASONING_EFFORT"):
        extra["reasoning_effort"] = os.environ["OPENAI_REASONING_EFFORT"]
    if os.environ.get("OPENAI_TEMPERATURE"):
        extra["temperature"] = float(os.environ["OPENAI_TEMPERATURE"])

    attempts, failure, diff_text, context_reads = [], None, "", []
    read_notes = None
    while len(attempts) < args.max_attempts:
        n = len(attempts) + 1
        messages = build_messages(prompt, context, failure, inventory, read_notes)
        if api == 'responses':
            options = dict(extra)
            effort = options.pop('reasoning_effort', None)
            payload = {'model': model, 'instructions': messages[0]['content'], 'input': messages[1]['content'],
                       'max_output_tokens': 16000, **options}
            if effort:
                payload['reasoning'] = {'effort': effort}
        else:
            payload = {"model": model, "messages": messages, **extra}
        response = transport(url, headers, payload, args.timeout)
        content = message_content(response)
        if (content or '').strip().startswith('REQUEST_CONTEXT:'):
            if len(context_reads) >= MAX_CONTEXT_READS:
                attempts.append({'attempt': n, 'result': 'context read limit reached',
                                 'reason': 'Four repository reads exhausted; narrow the change or supply a bounded context.'})
                break
            try:
                added, notes, hits = context_request(content, args.src_repo, args.base_commit,
                                                      inventory, args.max_context_bytes)
                # Most recent explicit reads take priority. Keep earlier source
                # within the same limit; never silently exceed the source cap.
                merged, used, seen = [], 0, set()
                for item in added + context:
                    key_id = (item['path'], tuple(item.get('lines') or (None, None)))
                    if key_id in seen or used + item['bytes'] > args.max_context_bytes:
                        continue
                    seen.add(key_id); merged.append(item); used += item['bytes']
                context = merged
                read_notes = {'diagnostics': notes, 'search_hits': hits}
                context_reads.append({'read': len(context_reads)+1, 'files': [
                    {k: v for k, v in item.items() if k != 'text'} for item in added], 'diagnostics': notes})
                failure = None
            except ValueError as err:
                read_notes = {'error': str(err)}
                context_reads.append({'read': len(context_reads)+1, 'error': str(err)})
            continue
        declined = bool(re.match(r'^NO CHANGE POSSIBLE(?:\s*:|\s*$)', (content or '').strip()))
        candidate_diff = '' if declined else extract_diff(content)
        record = {"attempt": n, "finishReason": response.get('status') or (response.get("choices") or [{}])[0].get("finish_reason")}
        if not candidate_diff:
            record["result"] = "model declined" if declined else "no diff"
            if declined and ':' in content:
                reason = content.split(':', 1)[1].strip().splitlines()[0] if content.split(':', 1)[1].strip() else ''
                reason = reason.replace(key, '[redacted]').replace(base_url, '[endpoint]')
                record['reason'] = re.sub(r'https?://\S+', '[url]', reason)[:400]
            failure = "You did not return a unified diff. Return only a unified diff, or exactly NO CHANGE POSSIBLE."
            attempts.append(record)
            if declined:
                break
            continue
        violations = scope_violations(candidate_diff, args.src_repo, args.base_commit)
        if violations:
            record["result"] = "out of scope"
            record["violations"] = violations
            failure = ("These paths are out of scope: " + ", ".join(violations)
                       + ". Change only phorvex/**/*.go outside phorvex/tools/. Existing tests are immutable; add a new test file instead.")
            attempts.append(record)
            continue
        record["result"] = "ok"
        record["diffSha256"] = sha256_text(candidate_diff)
        attempts.append(record)
        diff_text = candidate_diff
        break

    record = {
        "schema": SCHEMA,
        "provider": "openai",
        "baseUrl": base_url,
        "api": api,
        "model": model,
        "baseCommit": args.base_commit,
        "promptSha256": sha256_text(prompt),
        "contextFiles": [{"path": c["path"], "bytes": c["bytes"]} for c in context],
        "contextSkipped": skipped,
        "contextSelection": "explicit" if args.context else "ranked",
        "contextReads": context_reads,
        "attempts": attempts,
        "diffFound": bool(diff_text),
        "createdAt": utc_now(),
    }
    if args.out:
        out = Path(args.out)
        tmp = out.with_suffix(out.suffix + ".tmp")
        tmp.write_text(json.dumps(record, indent=2) + "\n")
        tmp.replace(out)
    if not diff_text:
        reason = attempts[-1]["result"] if attempts else "no attempts"
        raise PlannerError(8, f"no in-scope diff after {len(attempts)} attempt(s) (last: {reason})")
    Path(args.out_diff).write_text(diff_text)
    return record, diff_text


def parse_args(argv):
    p = argparse.ArgumentParser(add_help=True)
    p.add_argument("--src-repo", required=True)
    p.add_argument("--base-commit", required=True)
    p.add_argument("--prompt-file", required=True)
    p.add_argument("--out-diff", required=True)
    p.add_argument("--out")
    p.add_argument("--context", action="append", default=[])
    p.add_argument("--model")
    p.add_argument("--max-attempts", type=int, default=2)
    p.add_argument("--max-context-bytes", type=int, default=DEFAULT_MAX_CONTEXT)
    p.add_argument("--timeout", type=float, default=120.0)
    return p.parse_args(argv)


def main(argv):
    args = parse_args(argv)
    if not re.fullmatch(r"[0-9a-f]{40}", args.base_commit):
        print("planner: --base-commit must be a full 40-character lowercase SHA", file=sys.stderr)
        return 2
    try:
        record, _ = plan(args, openai_transport)
    except PlannerError as error:
        print(f"planner: {error}", file=sys.stderr)
        return error.code
    print(f"diff written to {args.out_diff} ({record['model']}, {len(record['attempts'])} attempt(s))",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
