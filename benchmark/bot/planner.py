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

SYSTEM_PROMPT = """\
You modify the Go source of the Phorvex "brain" (its decision logic) to satisfy a change request.

Output rules, strictly:
- Reply with ONE unified diff and nothing else: no prose, no explanation, no code fences.
- Use git diff headers with a/ and b/ prefixes (--- a/PATH and +++ b/PATH).
- Change only files matching phorvex/**/*.go. Never touch phorvex/tools/**, any *_test.go file,
  go.mod, go.sum, Dockerfiles, charts, or anything outside phorvex/.
- Keep the change minimal and compilable. Do not reformat unrelated code.
- If the request cannot be met within these rules, reply with exactly: NO CHANGE POSSIBLE
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
    scoped = [p for p in listed if in_scope(p)]
    mentioned = [p for p in scoped if p in prompt]
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
    ranked = [p for p, _ in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])) if p not in mentioned]
    return (mentioned + ranked)[:limit]


def gather_context(repo, commit, paths, max_bytes):
    """Read the given in-scope paths at the commit, within a byte budget."""
    context, used, skipped = [], 0, []
    for path in paths:
        if not in_scope(path):
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


def build_messages(prompt, context, previous_failure=None):
    blocks = [f"### Change request\n{prompt.strip()}\n"]
    if context:
        blocks.append("### Current brain source (base commit, read-only)")
        for item in context:
            blocks.append(f"--- {item['path']} ---\n{item['text']}")
    else:
        blocks.append("### No source files were pre-selected; infer the paths to change.")
    if previous_failure:
        blocks.append(f"### Your previous reply was rejected\n{previous_failure}\nReturn a corrected unified diff.")
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


def scope_violations(diff_text):
    bad = [p for p in diff_paths(diff_text) if not in_scope(p)]
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

    extra = {}
    if os.environ.get("OPENAI_REASONING_EFFORT"):
        extra["reasoning_effort"] = os.environ["OPENAI_REASONING_EFFORT"]
    if os.environ.get("OPENAI_TEMPERATURE"):
        extra["temperature"] = float(os.environ["OPENAI_TEMPERATURE"])

    attempts, failure, diff_text = [], None, ""
    for n in range(1, args.max_attempts + 1):
        messages = build_messages(prompt, context, failure)
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
        candidate_diff = extract_diff(content)
        record = {"attempt": n, "finishReason": response.get('status') or (response.get("choices") or [{}])[0].get("finish_reason")}
        if not candidate_diff:
            record["result"] = "no diff" if content.strip() != "NO CHANGE POSSIBLE" else "model declined"
            failure = "You did not return a unified diff. Return only a unified diff, or exactly NO CHANGE POSSIBLE."
            attempts.append(record)
            if content.strip() == "NO CHANGE POSSIBLE":
                break
            continue
        violations = scope_violations(candidate_diff)
        if violations:
            record["result"] = "out of scope"
            record["violations"] = violations
            failure = ("These paths are out of scope: " + ", ".join(violations)
                       + ". Change only phorvex/**/*.go (never phorvex/tools/ or *_test.go).")
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
