"""Per-attempt evidence and bounded abort reporting; no network or retry of actions."""
import html
import json
import os
import re
import uuid
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path

import checks


def error_text(error):
    text = f"{type(error).__name__}: {error}"
    # Do not serialize config, environment, traceback locals or unbounded responses.
    for key, value in os.environ.items():
        if value and any(word in key.upper() for word in ('PASSWORD', 'TOKEN', 'SECRET')):
            text = text.replace(value, '[REDACTED]')
    return text[:2000]


class Cleanup(ExitStack):
    """Collect cleanup failures without replacing the original pipeline exception."""
    def __init__(self):
        super().__init__()
        self.errors = []

    def callback(self, fn, *args, **kwargs):
        def attempt():
            try:
                fn(*args, **kwargs)
            except Exception as error:
                self.errors.append(error_text(error))
        return super().callback(attempt)


class RunOutput:
    def __init__(self, directory, mode, target=None, run_id=None, source_commit=None, label=None):
        self.started = datetime.now(timezone.utc)
        stamp = self.started.strftime('%Y%m%dT%H%M%S%fZ')
        self.run_id = run_id or f'{stamp}-{uuid.uuid4().hex[:12]}'
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,159}', self.run_id):
            raise ValueError('invalid run ID')
        self.directory = Path(directory)
        self.identity = {'runId': self.run_id,
                         'sourceCommit': source_commit or os.getenv('GITHUB_SHA') or 'unknown',
                         'githubRunId': os.getenv('GITHUB_RUN_ID'),
                         'githubRunAttempt': os.getenv('GITHUB_RUN_ATTEMPT'),
                         'runLabel': (label or '')[:300]}
        self.mode, self.target = mode, target
        self.stage = 'initialization'
        self.results = []
        self.injection = None

    def abort(self, error, cleanup_errors=()):
        evaluated = {c['id']: c for c in self.results}
        catalogue = [{k: v for k, v in c.items() if k != 'fn'} for c in checks.registry()]
        results = [evaluated.get(c['id'], dict(c, status='skip',
                   summary='Not evaluated: run aborted.', evidence=[])) for c in catalogue]
        return dict(self.identity, schema='phorvex.e2e/1',
                    startedAt=self.started.isoformat(), finishedAt=datetime.now(timezone.utc).isoformat(),
                    mode=self.mode, target={'name': self.target} if self.target else None,
                    verdict='ABORTED', status='aborted', exitCode=2,
                    abort={'stage': self.stage, 'error': error_text(error),
                           'cleanupErrors': list(cleanup_errors)},
                    checks=results, tally={s: sum(c['status'] == s for c in results)
                                          for s in ('pass', 'fail', 'warn', 'skip')},
                    # Abort is a harness failure, never eligible for a check baseline.
                    baselined=[], newFailures=['HARNESS_ABORT'], staleBaseline=[],
                    counts={}, groundTruth=[], injection=self.injection)

    @staticmethod
    def abort_html(doc):
        detail = html.escape(json.dumps({k: doc.get(k) for k in (
            'runId', 'sourceCommit', 'githubRunId', 'githubRunAttempt', 'abort', 'injection', 'tally')},
            ensure_ascii=False, indent=2))
        return ('<!doctype html><html lang="en"><meta charset="utf-8">'
                '<title>Phorvex E2E — ABORTED</title><h1>E2E run aborted</h1>'
                '<p>This is not a passing contract verdict. Unexecuted checks prove nothing. '
                'Any listed cleanup errors require follow-up.</p><pre>' + detail + '</pre></html>')

    def write(self, doc, renderer):
        doc.update(self.identity)
        try:
            body = self.abort_html(doc) if doc.get('status') == 'aborted' else renderer(doc)
        except Exception as error:
            self.stage = 'report rendering'
            doc = self.abort(error)
            body = self.abort_html(doc)
        self.directory.mkdir(parents=True, exist_ok=True)
        # JSON is the commit marker: never expose a completed JSON verdict before
        # its HTML pair exists. CI still independently checks the process exit code.
        for name, body in ((f'run-{self.run_id}.html', body), ('latest.html', body),
                           (f'run-{self.run_id}.json', json.dumps(doc, ensure_ascii=False, indent=2))):
            path = self.directory / name
            temporary = path.with_name(path.name + '.tmp')
            temporary.write_text(body, encoding='utf-8')
            temporary.replace(path)
        return doc
