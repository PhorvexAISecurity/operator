"""Offline tests for the Telegram bot: telegram.py, dashboard.py, report.py and
service.py, end to end.

Telegram and OpenAI are fake transports; the dashboard is a local HTTP server
that enforces the real API's cookie, Origin and status rules (for the client)
or a fake object (for the bot). /bench runs the real planner, candidate,
replay build (fake go), code experiment and Math Lab analysis.
"""
import http.server
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import report  # noqa: E402
import service  # noqa: E402
import testkit  # noqa: E402
from dashboard import Dashboard, DashboardError  # noqa: E402
from telegram import Telegram, TelegramError  # noqa: E402

TOKEN = '123456789:' + 'A' * 35
OWNER, STRANGER = 1001, 666
OPENAI_KEY = 'sk-test-openai-key-never-shown'
DASH_PASSWORD = 'dashboard-password-never-shown'


class FakeTelegram:
    """A Telegram Bot API transport: queued updates in, every call recorded."""

    def __init__(self):
        self.updates, self.calls = [], []

    def __call__(self, url, data, headers, timeout):
        method = url.rsplit('/', 1)[1]
        assert url.startswith('https://api.telegram.org/bot%s/' % TOKEN)
        if headers['Content-Type'].startswith('multipart/'):
            self.calls.append((method, {'raw': data}))
        else:
            self.calls.append((method, json.loads(data)))
        if method == 'getMe':
            return json.dumps({'ok': True, 'result': {'username': 'phbenchbot'}}).encode()
        if method == 'getUpdates':
            params = json.loads(data)
            out = [u for u in self.updates if u['update_id'] >= params.get('offset', 0)]
            return json.dumps({'ok': True, 'result': out}).encode()
        return json.dumps({'ok': True, 'result': {}}).encode()

    def texts(self):
        return [p['text'] for m, p in self.calls if m == 'sendMessage']

    def documents(self):
        return [p['raw'] for m, p in self.calls if m == 'sendDocument']


def message(user_id, text, update_id=1, chat_id=None):
    return {'update_id': update_id, 'message': {'from': {'id': user_id, 'username': 'u%d' % user_id},
                                                'chat': {'id': chat_id or user_id}, 'text': text}}


class TelegramClientTest(unittest.TestCase):
    def test_token_is_validated_and_never_in_an_error(self):
        with self.assertRaises(TelegramError):
            Telegram('not-a-token')

        def failing(url, data, headers, timeout):
            return b'{"ok": false, "description": "Unauthorized"}'
        with self.assertRaises(TelegramError) as cm:
            Telegram(TOKEN, failing).send_message(1, 'x')
        self.assertNotIn(TOKEN, str(cm.exception))
        self.assertNotIn(TOKEN.split(':')[1], str(cm.exception))

    def test_long_messages_are_split_and_documents_are_multipart(self):
        fake = FakeTelegram()
        tg = Telegram(TOKEN, fake)
        tg.send_message(5, 'x' * 9000)
        self.assertEqual([len(p['text']) for m, p in fake.calls], [4096, 4096, 808])
        tg.send_document(5, 'report "1".html', b'<html>body</html>', 'caption')
        raw = fake.documents()[0]
        self.assertIn(b'filename="report__1_.html"', raw)
        self.assertIn(b'<html>body</html>', raw)


class FakeDashboardServer(http.server.BaseHTTPRequestHandler):
    """The dashboard API's rules: login sets a cookie; every math route needs it;
    mutations need the public Origin; a stale session answers 401."""
    origin = 'https://dash.example:8444'
    sessions, log = set(), []
    expire_next = False

    def log_message(self, *a):
        pass

    def reply(self, code, body, cookie=None):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        if cookie:
            self.send_header('Set-Cookie', 'phorvex_benchmark_session=%s; Path=/api; HttpOnly' % cookie)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def authed(self):
        cookie = self.headers.get('Cookie', '')
        token = cookie.split('=', 1)[1] if '=' in cookie else ''
        if FakeDashboardServer.expire_next:
            FakeDashboardServer.expire_next = False
            FakeDashboardServer.sessions.discard(token)
        return token in FakeDashboardServer.sessions

    def do_GET(self):
        FakeDashboardServer.log.append(('GET', self.path))
        if not self.authed():
            return self.reply(401, {'message': 'Unauthorized'})
        if self.path.startswith('/api/math/experiments/e1/artifacts/'):
            data = b'# report'
            self.send_response(200)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            return self.wfile.write(data)
        if self.path == '/api/math/experiments/e1':
            return self.reply(200, {'id': 'e1', 'status': 'COMPLETE', 'progress': {'message': 'done'}})
        self.reply(200, {'path': self.path})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))) or b'{}')
        FakeDashboardServer.log.append(('POST', self.path, self.headers.get('Origin')))
        if self.headers.get('Origin') != self.origin:
            return self.reply(403, {'message': 'Invalid origin'})
        if self.path == '/api/auth/login':
            if body.get('password') != DASH_PASSWORD:
                return self.reply(401, {'message': 'Invalid password'})
            token = 'sess%d' % len(FakeDashboardServer.sessions)
            FakeDashboardServer.sessions.add(token)
            return self.reply(200, {'ok': True}, cookie=token)
        if not self.authed():
            return self.reply(401, {'message': 'Unauthorized'})
        if self.path == '/api/math/sync':
            return self.reply(409, {'message': 'A sync for this policy is already queued'})
        self.reply(201, {'id': 'e1', 'echo': body})


class DashboardClientTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), FakeDashboardServer)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.url = 'http://127.0.0.1:%d' % cls.server.server_port

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        FakeDashboardServer.sessions, FakeDashboardServer.log = set(), []
        self.dash = Dashboard(self.url, DASH_PASSWORD, origin=FakeDashboardServer.origin, sleep=lambda s: None)

    def test_login_cookie_origin_and_relogin(self):
        self.assertEqual(self.dash.create({'x': 1})['echo'], {'x': 1})
        self.assertEqual(FakeDashboardServer.log[0], ('POST', '/api/auth/login', FakeDashboardServer.origin))
        self.assertTrue(all(e[2] == FakeDashboardServer.origin for e in FakeDashboardServer.log if e[0] == 'POST'))
        FakeDashboardServer.expire_next = True  # the session expires: one 401, one re-login, the call succeeds
        self.assertEqual(self.dash.detail('e1')['status'], 'COMPLETE')
        self.assertEqual(sum(1 for e in FakeDashboardServer.log if e[1] == '/api/auth/login'), 2)

    def test_sync_conflict_waits_on_the_queued_sync_and_artifacts_are_raw(self):
        self.assertIsNone(self.dash.sync('vllm/vllm-defense'))
        self.assertEqual(self.dash.artifact('e1', 'report.md'), b'# report')
        seen = []
        self.assertEqual(self.dash.wait_experiment('e1', progress=seen.append)['status'], 'COMPLETE')
        self.assertEqual(seen, ['done'])

    def test_wrong_password_and_origin_fail_without_leaking_the_password(self):
        with self.assertRaises(DashboardError) as cm:
            Dashboard(self.url, 'wrong', origin=FakeDashboardServer.origin).policies()
        self.assertEqual(cm.exception.status, 401)
        with self.assertRaises(DashboardError) as cm:
            Dashboard(self.url, DASH_PASSWORD, origin='https://evil.example').policies()
        self.assertEqual(cm.exception.status, 403)
        self.assertNotIn(DASH_PASSWORD, str(cm.exception) + str(cm.exception.body))


class ReportTest(unittest.TestCase):
    ROWS = [{'arm_id': 'control', 'metric_id': 'M-P21', 'metric_name': 'Changed-decision share', 'unit': 'proportion',
             'value': 0.0, 'ci_low': 0.0, 'ci_high': 0.39, 'numerator': 0, 'denominator': 6, 'dimension': None,
             'data_status': 'OBSERVED'},
            {'arm_id': 'candidate', 'metric_id': 'M-P21', 'metric_name': 'Changed-decision share', 'unit': 'proportion',
             'value': 1 / 3, 'ci_low': 0.097, 'ci_high': 0.7, 'numerator': 2, 'denominator': 6, 'dimension': None,
             'data_status': 'OBSERVED', 'reason': '=HYPERLINK("x")'},
            {'arm_id': 'candidate', 'metric_id': 'M-P22', 'metric_name': 'Useful', 'unit': 'proportion', 'value': None,
             'dimension': None, 'data_status': 'UNAVAILABLE'}]

    def test_formatting_keeps_intervals_and_missing(self):
        self.assertEqual(report.fmt(self.ROWS[1]), '33.3% [9.7-70.0] (2/6)')
        self.assertEqual(report.fmt(self.ROWS[2]), 'n/a (unavailable)')

    def test_html_is_escaped_and_csv_is_neutralized(self):
        meta = {'kind': 'Code experiment', 'title': '<script>alert(1)</script>', 'request': '"><img src=x>'}
        page = report.page(meta, {'comparison_status': 'OBSERVATIONAL'}, self.ROWS)
        self.assertNotIn('<script>', page)
        self.assertNotIn('<img', page)
        self.assertIn('&lt;script&gt;', page)
        self.assertIn(b"'=HYPERLINK", report.table(self.ROWS))
        text = report.summary(meta, {'comparison_status': 'OBSERVATIONAL', 'population': {'control_eligible': 6}}, self.ROWS)
        self.assertIn('candidate    33.3% [9.7-70.0] (2/6)', text)


class FakeDashboard:
    def __init__(self, preflight_status='PASS'):
        self.calls, self.preflight_status = [], preflight_status

    def sync(self, policy):
        self.calls.append(('sync', policy))
        return {'id': 'job1'}

    def wait_job(self, job_id, cancelled=None):
        return {'id': job_id, 'status': 'COMPLETE'}

    def preflight(self, request):
        self.calls.append(('preflight', request))
        return {'status': self.preflight_status, 'checks': [{'id': 'VERSION_PIN', 'status': 'FAIL', 'message': 'mixed'}]}

    def create(self, request):
        self.calls.append(('create', request))
        return {'id': 'e1'}

    def wait_experiment(self, eid, cancelled=None, progress=None):
        progress('replaying 500 ticks x 3 arms')
        return {'id': eid, 'status': 'COMPLETE', 'result': {'comparison_status': 'MATCHED_REPLAY',
                                                           'population': {'control_eligible': 500, 'matched_by_arm': {}}},
                'manifest': {'limitations': ['Replay measures immediate decision sensitivity.']}}

    def metrics(self, eid):
        return ReportTest.ROWS[:2]

    def policies(self):
        return {'policies': [{'policy': 'vllm/vllm-defense'}]}

    def artifact(self, eid, name):
        return b'# Math Lab report'


class BotTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='bot-service-'))
        self.addCleanup(shutil.rmtree, self.tmp)
        self.fake = FakeTelegram()
        self.env = {'TELEGRAM_BOT_TOKEN': TOKEN, 'BOT_ALLOWED_USER_IDS': str(OWNER), 'BOT_STATE_DIR': str(self.tmp / 'state')}
        for k, v in (('OPENAI_API_KEY', OPENAI_KEY), ('OPENAI_MODEL', 'test-model')):
            os.environ[k] = v
            self.addCleanup(os.environ.pop, k, None)
        self.logged = []
        original = service.log
        service.log = lambda m: self.logged.append(m)
        self.addCleanup(setattr, service, 'log', original)

    def bot(self, dashboard=None, openai=None, **env):
        cfg = service.Config({**self.env, **env})
        return service.BenchBot(cfg, Telegram(TOKEN, self.fake), dashboard, openai or (lambda *a: None), sleep=lambda s: None)

    def history(self):
        return [json.loads(l) for l in (self.tmp / 'state/history.jsonl').read_text().splitlines()]

    def assert_no_secret_shown(self):
        shown = json.dumps(self.texts_and_docs()) + '\n'.join(self.logged)
        for secret in (TOKEN.split(':')[1], OPENAI_KEY, DASH_PASSWORD):
            self.assertNotIn(secret, shown)

    def texts_and_docs(self):
        return self.fake.texts() + [d.decode('utf-8', 'replace') for d in self.fake.documents()]

    def test_config_requires_an_allowlist(self):
        with self.assertRaisesRegex(service.ConfigError, 'BOT_ALLOWED_USER_IDS'):
            service.Config({**self.env, 'BOT_ALLOWED_USER_IDS': ''})
        with self.assertRaisesRegex(service.ConfigError, 'numeric'):
            service.Config({**self.env, 'BOT_ALLOWED_USER_IDS': '@me'})

    def test_strangers_get_no_reply_and_their_id_is_logged(self):
        bot = self.bot()
        bot.handle(message(STRANGER, '/bench do something dangerous please'))
        self.assertEqual(self.fake.texts(), [])
        self.assertEqual(bot.queue, [])
        self.assertTrue(any('666' in m and 'not in BOT_ALLOWED_USER_IDS' in m for m in self.logged))

    def test_first_start_skips_the_backlog_and_restarts_resume(self):
        self.fake.updates = [message(OWNER, '/bench an old command from before the deploy', 7)]
        bot = self.bot()
        offset = bot.skip_backlog()
        self.assertEqual(offset, 8)
        self.assertEqual(bot.poll_once(offset), 8)
        self.assertEqual(bot.queue, [], 'the old command was not run')
        self.fake.updates.append(message(OWNER, '/status', 8))
        offset = bot.poll_once(offset)
        self.assertEqual(offset, 9)
        self.assertEqual(self.bot().skip_backlog(), 9, 'a restart resumes from the saved offset')

    def test_help_status_runs_cancel_and_queue_limit(self):
        bot = self.bot()
        for text in ('/help', '/status', '/runs', '/cancel', '/nope'):
            bot.handle(message(OWNER, text))
        texts = self.fake.texts()
        self.assertIn('/bench', texts[0])
        self.assertEqual(texts[1:], ['Running: nothing\nQueue: empty', 'No runs yet.', 'Nothing is running.',
                                     'Unknown command. /help lists them.'])
        for i in range(service.MAX_QUEUE + 1):
            bot.handle(message(OWNER, '/param P-FEA-006 1.%d' % i))
        self.assertEqual(len(bot.queue), service.MAX_QUEUE)
        self.assertIn('queue is full', self.fake.texts()[-1])

    def test_param_runs_through_the_dashboard_and_returns_files(self):
        dash = FakeDashboard()
        bot = self.bot(dash)
        bot.handle(message(OWNER, '/param P-FEA-006 1.2 1.8 policy=vllm/vllm-defense ticks=200'))
        self.assertTrue(bot.run_next())
        sent = [c for c in dash.calls if c[0] == 'create'][0][1]
        self.assertEqual(sent['arms'], [{'arm_id': 'control', 'value_source': 'RECORDED_EFFECTIVE'},
                                        {'arm_id': 'v1.2', 'value': 1.2}, {'arm_id': 'v1.8', 'value': 1.8}])
        self.assertEqual(sent['cohort'], {'max_snapshots': 200, 'spacing': 'even'})
        self.assertEqual(dash.calls[0], ('sync', 'vllm/vllm-defense'))
        self.assertTrue(any('replaying 500 ticks' in t for t in self.fake.texts()))
        self.assertTrue(any('M-P21 Changed-decision share' in t for t in self.fake.texts()))
        self.assertEqual(len(self.fake.documents()), 3)  # report.html, metrics.csv, the Math Lab report.md
        self.assertEqual(self.history()[-1]['state'], 'DONE')
        self.assert_no_secret_shown()

    def test_param_preflight_failure_and_bad_usage(self):
        bot = self.bot(FakeDashboard(preflight_status='FAIL'))
        bot.handle(message(OWNER, '/param P-FEA-006 1.2 nosync'))
        bot.run_next()
        self.assertIn('preflight failed:\nVERSION_PIN: mixed', self.fake.texts()[-1])
        bot.handle(message(OWNER, '/param cost 1.2'))
        bot.run_next()
        self.assertIn('usage: /param', self.fake.texts()[-1])
        self.assertEqual([h['state'] for h in self.history()], ['FAILED', 'FAILED'])

    def bench_setup(self):
        repo = self.tmp / 'operator'
        base = testkit.make_repo(repo, threshold=3)
        data = self.tmp / 'dashboard-data'
        testkit.make_corpus(data, base)
        deployed = testkit.write_fake_replay(self.tmp / 'deployed-brain-replay', base, 3)
        (data / 'mathlab/bin').mkdir(parents=True)
        (data / 'mathlab/bin/current.json').write_text(json.dumps({
            'path': str(deployed), 'git_sha': base, 'binary_sha256': testkit.hashlib.sha256(deployed.read_bytes()).hexdigest(),
            'image_digest': 'sha256:' + 'e' * 64}))
        go, template = testkit.write_fake_go(self.tmp / 'fakego')
        os.environ['FAKE_REPLAY_TEMPLATE'] = str(template)
        self.addCleanup(os.environ.pop, 'FAKE_REPLAY_TEMPLATE', None)
        return repo, base, data, go

    def openai_returning(self, *contents):
        replies = list(contents)

        def transport(url, headers, payload, timeout):
            assert headers['Authorization'] == 'Bearer ' + OPENAI_KEY
            return {'choices': [{'message': {'content': replies.pop(0)}, 'finish_reason': 'stop'}]}
        return transport

    def test_bench_end_to_end_from_telegram(self):
        repo, base, data, go = self.bench_setup()
        before = (testkit.git(repo, 'status', '--porcelain'), testkit.git(repo, 'for-each-ref'))
        bot = self.bot(FakeDashboard(), self.openai_returning(testkit.threshold_diff(3, 5)),
                       BOT_REPO=str(repo), MATHLAB_DATA_DIR=str(data), BOT_GO=str(go))
        bot.handle(message(OWNER, '/bench ticks=100 raise the rotate threshold for vllm from 3 to 5'))
        self.assertTrue(bot.run_next())
        texts = self.fake.texts()
        self.assertTrue(any('asking the LLM for a change against manager-v0.12.0' in t for t in texts), texts)
        summary = next(t for t in texts if t.startswith('Code experiment'))
        self.assertIn('toolchain fidelity (deployed commit built here): EXACT', summary)
        self.assertIn('candidate    33.3%', summary)
        self.assertIn('base-local   0.0%', summary)
        self.assertIn('changed: phorvex/internal/decision/decision.go', summary)
        docs = self.fake.documents()
        self.assertEqual(len(docs), 3)  # report.html, metrics.csv, candidate.diff
        self.assertIn(b'+const RotateThreshold = 5', docs[2])
        job = self.history()[-1]
        self.assertEqual(job['state'], 'DONE')
        self.assertIn('changed decisions 33.3%', job['headline'])
        jobdir = self.tmp / 'state/jobs' / job['id']
        self.assertFalse((jobdir / 'candidate-src').exists())
        self.assertFalse((jobdir / 'base-src').exists())
        for kept in ('brain.diff', 'PLAN.json', 'CANDIDATE.json', 'report.html', 'experiment/evidence.zip'):
            self.assertTrue((jobdir / kept).exists(), kept)
        self.assertEqual((testkit.git(repo, 'status', '--porcelain'), testkit.git(repo, 'for-each-ref')), before)
        self.assert_no_secret_shown()

    def test_bench_refused_and_uncompilable_changes_are_reported(self):
        repo, base, data, go = self.bench_setup()
        out_of_scope = '--- a/deploy/x.yaml\n+++ b/deploy/x.yaml\n@@ -1 +1 @@\n-a\n+b\n'
        bot = self.bot(None, self.openai_returning(out_of_scope, out_of_scope),
                       BOT_REPO=str(repo), MATHLAB_DATA_DIR=str(data), BOT_GO=str(go))
        bot.handle(message(OWNER, '/bench nosync change the deploy files instead of the brain'))
        bot.run_next()
        self.assertIn('the LLM step failed: no in-scope diff', self.fake.texts()[-1])

        os.environ['FAKE_GO_FAIL'] = '1'
        self.addCleanup(os.environ.pop, 'FAKE_GO_FAIL', None)
        bot.openai_transport = self.openai_returning(testkit.threshold_diff(3, 4))
        bot.handle(message(OWNER, '/bench nosync lower the threshold a little bit'))
        bot.run_next()
        self.assertIn('the build failed (the candidate may not compile)', self.fake.texts()[-1])
        self.assertEqual([h['state'] for h in self.history()], ['FAILED', 'FAILED'])

    def test_bench_refuses_a_tampered_deployed_binary(self):
        repo, base, data, go = self.bench_setup()
        current = json.loads((data / 'mathlab/bin/current.json').read_text())
        Path(current['path']).write_text(Path(current['path']).read_text() + '# tampered\n')
        bot = self.bot(None, self.openai_returning(), BOT_REPO=str(repo), MATHLAB_DATA_DIR=str(data), BOT_GO=str(go))
        bot.handle(message(OWNER, '/bench nosync raise the rotate threshold please'))
        bot.run_next()
        self.assertIn('does not match its recorded sha256', self.fake.texts()[-1])

    def test_check_reports_every_dependency_without_secrets(self):
        repo, base, data, go = self.bench_setup()
        env = {**self.env, 'BOT_REPO': str(repo), 'MATHLAB_DATA_DIR': str(data), 'BOT_GO': str(go),
               'OPENAI_API_KEY': OPENAI_KEY, 'OPENAI_MODEL': 'test-model', 'DASHBOARD_PASSWORD': DASH_PASSWORD}
        cfg = service.Config(env)
        cfg.dashboard = lambda: FakeDashboard()
        lines = []
        self.assertEqual(service.check(cfg, env, Telegram(TOKEN, self.fake), lines.append), 0)
        text = '\n'.join(lines)
        for name in ('telegram token', 'allowlist', 'state directory', 'dashboard', 'deployed brain-replay',
                     'operator repository', 'go', 'openai'):
            self.assertRegex(text, r'(?m)^PASS +%s ' % name)
        self.assertIn('6 recorded ticks for vllm/vllm-defense', text)
        for secret in (TOKEN.split(':')[1], OPENAI_KEY, DASH_PASSWORD):
            self.assertNotIn(secret, text)

        # Only the essentials fail the check; the rest warn and name what they disable.
        lines = []
        bare = service.Config(self.env)
        self.assertEqual(service.check(bare, self.env, Telegram(TOKEN, self.fake), lines.append), 0)
        self.assertRegex('\n'.join(lines), r'(?m)^WARN openai .*disables /bench')

        def no_telegram(url, data, headers, timeout):
            return b'{"ok": false, "description": "Unauthorized"}'
        self.assertEqual(service.check(bare, self.env, Telegram(TOKEN, no_telegram), lambda line: None), 1)

    def test_cancel_stops_before_the_next_step(self):
        repo, base, data, go = self.bench_setup()
        bot = self.bot(None, self.openai_returning(testkit.threshold_diff(3, 5)),
                       BOT_REPO=str(repo), MATHLAB_DATA_DIR=str(data), BOT_GO=str(go))
        bot.handle(message(OWNER, '/bench nosync raise the rotate threshold please'))
        original = bot.step

        def step_then_cancel(job, label):
            original(job, label)
            if label.startswith('asking the LLM'):
                job.cancel.set()
        bot.step = step_then_cancel
        bot.run_next()
        self.assertEqual(self.history()[-1]['state'], 'CANCELLED')
        self.assertIn('cancelled before: landing the change', self.fake.texts()[-1])


class DeployFilesTest(unittest.TestCase):
    DEPLOY = HERE / 'deploy'

    def test_unit_matches_the_dashboard_layout(self):
        unit = (self.DEPLOY / 'phorvex-benchmark-bot.service').read_text()
        for line in ('EnvironmentFile=/home/hami/phorvex-benchmark/config/bot.env',
                     'WorkingDirectory=/home/hami/phorvex-benchmark/current/benchmark/bot',
                     'ExecStart=/home/hami/phorvex-benchmark/runtime/python/bin/python -B service.py',
                     'Environment=MATHLAB_DATA_DIR=/home/hami/phorvex-benchmark/data',
                     'UMask=0077', 'NoNewPrivileges=true'):
            self.assertIn(line, unit)
        dashboard_unit = (HERE.parent / 'deploy' / 'phorvex-benchmark-api.service').read_text()
        self.assertIn('/home/hami/phorvex-benchmark/runtime/python/bin/python', dashboard_unit)
        self.assertIn('DATA_DIR=/home/hami/phorvex-benchmark/data', dashboard_unit)

    def test_env_example_holds_no_secret_values(self):
        values = dict(l.split('=', 1) for l in (self.DEPLOY / 'bot.env.example').read_text().splitlines()
                      if l and not l.startswith('#'))
        for key in ('TELEGRAM_BOT_TOKEN', 'BOT_ALLOWED_USER_IDS', 'OPENAI_API_KEY', 'DASHBOARD_PASSWORD', 'OPENAI_MODEL'):
            self.assertEqual(values[key], '', key)

    def test_install_script(self):
        script = self.DEPLOY / 'install.sh'
        import subprocess
        subprocess.run(['bash', '-n', str(script)], check=True)
        self.assertTrue(os.access(script, os.X_OK))
        text = script.read_text()
        self.assertIn('must be mode 600', text)
        self.assertIn('systemd-run --user', text)
        self.assertNotRegex(text, r'(?m)^\s*(source|\.) ')
        self.assertNotIn('ln -sfn', text, 'the bot install must not move current')


if __name__ == '__main__':
    unittest.main()
