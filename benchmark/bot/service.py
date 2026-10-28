#!/usr/bin/env python3
"""The Phorvex benchmark Telegram bot.

  /param P-FEA-006 1.2 1.5 [policy=ns/name] [ticks=N] [nosync]
      A Math Lab parameter experiment, run by the benchmark dashboard: the same
      recorded production ticks replayed on the deployed brain with each value.
  /bench [policy=ns/name] [ticks=N] [nosync] <the brain change, in words>
      An LLM writes the change against the deployed commit (planner.py); it
      lands on a throwaway branch (candidate.py); brain-replay is built from
      the deployed commit and from the candidate (replay_build.py); and both
      are replayed against the deployed brain on recorded ticks
      (code_experiment.py).
  /guide: the English HTML and PDF playbook in the requesting chat
  /status, /runs, /cancel, /help

Both return a summary, report.html and metrics.csv in the chat; /bench also
returns the candidate diff. Everything is replay: no cluster is touched, no
action is dispatched, nothing is merged or pushed, and nothing is written to
the dashboard's data or the repository.

Only configured owners, the paired owner and invited members are served.
Anyone else gets no reply, and their id is logged. The update offset
is persisted, and any backlog that exists at the first start is skipped, so a
restart never replays old commands. One job runs at a time.

Configuration uses the environment (deploy/bot.env.example); owner/member
authorization persists privately in the state directory. Secrets
(TELEGRAM_BOT_TOKEN, DASHBOARD_PASSWORD, OPENAI_API_KEY) are never logged.
"""
import json
import hashlib
import hmac
import os
import re
import secrets
import shutil
import signal
import sys
import threading
import time
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import candidate  # noqa: E402
import code_experiment  # noqa: E402
import planner  # noqa: E402
import replay_build  # noqa: E402
import report  # noqa: E402
from dashboard import Dashboard, DashboardError  # noqa: E402
from telegram import Telegram, TelegramError  # noqa: E402

POLICY = re.compile(r'^[a-z0-9]([-a-z0-9]*[a-z0-9])?/[a-z0-9]([-a-z0-9]*[a-z0-9])?$')
PARAMETER = re.compile(r'^P-[A-Z]{3}-\d{3}$')
MAX_QUEUE = 5
HELP = """Phorvex benchmark bot (replay on recorded production ticks; nothing is deployed or dispatched)

/bench [policy=ns/name] [ticks=N] [nosync] <brain change in words>
  An LLM changes the brain's Go code; the candidate is compared with the deployed brain.
/param <P-XXX-000> <value> [value...] [policy=ns/name] [ticks=N] [nosync]
  Replays the deployed brain with each parameter value (Math Lab).
/guide    download the English step-by-step guide as HTML and PDF
/status   the running job and the queue
/runs     the last results
/check    check Telegram, dashboard, source, recorded ticks, disk and model access
/invite   owner: create a one-use member link, valid for 24 hours
/cancel   stop the running job after its current step

Defaults: policy=%(policy)s, ticks=%(ticks)d."""
COMMANDS = [
    {'command': 'guide', 'description': 'Download the English guide (HTML and PDF)'},
    {'command': 'bench', 'description': 'Test a brain code or formula change'},
    {'command': 'param', 'description': 'Compare brain parameter values'},
    {'command': 'status', 'description': 'Show the running job and queue'},
    {'command': 'runs', 'description': 'Show the five most recent runs'},
    {'command': 'check', 'description': 'Check benchmark dependencies and access'},
    {'command': 'cancel', 'description': 'Cancel the running job after its current step'},
    {'command': 'invite', 'description': 'Owner: create a one-use member invitation'},
    {'command': 'help', 'description': 'Show commands and usage'},
]
BOT_NAME = 'Phorvex Brain Benchmark'
BOT_DESCRIPTION = ('Benchmark brain changes before release. Compare parameters, code and formulas '
                   'against the deployed brain using recorded production ticks. '
                   'Use /guide to download the English HTML and PDF playbook. '
                   'Authorized members only. Replay results do not deploy changes or measure live defense outcomes.')
BOT_SHORT_DESCRIPTION = 'Brain replay benchmarks: code, formulas and parameters. Use /guide for the English HTML and PDF playbook.'


def configure_interface(telegram):
    """Keep the default and existing English/Persian locale surfaces in English."""
    for language in ('', 'en', 'fa'):
        telegram.call('setMyCommands', {'commands': COMMANDS, 'language_code': language})
        telegram.call('setMyName', {'name': BOT_NAME, 'language_code': language})
        telegram.call('setMyDescription', {'description': BOT_DESCRIPTION, 'language_code': language})
        telegram.call('setMyShortDescription', {'short_description': BOT_SHORT_DESCRIPTION, 'language_code': language})
    telegram.call('setChatMenuButton', {'menu_button': {'type': 'commands'}})


def utc():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def log(message):
    print('%s %s' % (utc(), message), file=sys.stderr, flush=True)


def private_dir(path):
    """Create `path` mode 700 if it does not exist; an existing one is left as is (--check reports it)."""
    path = Path(path)
    if not path.exists():
        path.mkdir(parents=True, mode=0o700)
        path.chmod(0o700)
    return path


class ConfigError(Exception):
    pass


class JobError(Exception):
    """A user-facing failure: its message is sent to the chat."""


def read_members(state):
    path = Path(state) / 'members.json'
    if not path.exists():
        return []
    try:
        rows = json.loads(path.read_text())
        if path.stat().st_mode & 0o077 or not isinstance(rows, list):
            raise ValueError()
        if any(not isinstance(row, dict) or type(row.get('id')) is not int or row['id'] <= 0
               or type(row.get('invited_by')) is not int or row['invited_by'] <= 0 for row in rows):
            raise ValueError()
        return rows
    except (OSError, ValueError):
        raise ConfigError('members.json must be private and contain valid member records')


class Config:
    def __init__(self, env):
        self.token = env.get('TELEGRAM_BOT_TOKEN', '')
        try:
            self.allowed = {int(x) for x in env.get('BOT_ALLOWED_USER_IDS', '').replace(' ', '').split(',') if x}
        except ValueError:
            raise ConfigError('BOT_ALLOWED_USER_IDS must be comma-separated numeric Telegram user ids')
        if not self.allowed:
            raise ConfigError('BOT_ALLOWED_USER_IDS is empty; the bot serves nobody without it')
        self.state = Path(env.get('BOT_STATE_DIR') or Path.home() / 'phorvex-benchmark' / 'bot')
        owner = self.state / 'owner.json'
        if self.allowed == {0} and owner.exists():
            data = json.loads(owner.read_text())
            if owner.stat().st_mode & 0o077 or not isinstance(data.get('id'), int) or data['id'] <= 0:
                raise ConfigError('owner.json must be private and contain a positive Telegram user id')
            self.allowed = {data['id']}
        self.admins = self.allowed - {0}
        self.allowed.update(row['id'] for row in read_members(self.state) if row['invited_by'] in self.admins)
        self.repo = env.get('BOT_REPO') or None
        self.data = env.get('MATHLAB_DATA_DIR') or None
        self.policy = env.get('BOT_DEFAULT_POLICY', 'vllm/vllm-defense')
        self.ticks = int(env.get('BOT_MAX_TICKS', '500'))
        self.go = env.get('BOT_GO', 'go')
        try:
            self.min_free_gb = float(env.get('BOT_MIN_FREE_GB', '4'))
        except ValueError:
            raise ConfigError('BOT_MIN_FREE_GB must be a number of gigabytes')
        self.dashboard_url = env.get('DASHBOARD_URL') or None
        self.dashboard_password = env.get('DASHBOARD_PASSWORD', '')
        self.dashboard_origin = env.get('DASHBOARD_ORIGIN') or None
        self.dashboard_ca = env.get('DASHBOARD_CA') or None
        if not POLICY.match(self.policy):
            raise ConfigError('BOT_DEFAULT_POLICY must be namespace/name')

    def dashboard(self):
        if not self.dashboard_url or not self.dashboard_password:
            return None
        return Dashboard(self.dashboard_url, self.dashboard_password, self.dashboard_origin, self.dashboard_ca)


class Job:
    def __init__(self, kind, chat_id, user, text):
        self.id = uuid.uuid4().hex[:12]
        self.kind, self.chat_id, self.user, self.text = kind, chat_id, user, text
        self.created, self.state, self.step = utc(), 'QUEUED', ''
        self.cancel = threading.Event()


def parse_options(words, cfg):
    """Leading key=value options and flags; returns (options, remaining words)."""
    opts = {'policy': cfg.policy, 'ticks': cfg.ticks, 'sync': True}
    rest = list(words)
    while rest:
        w = rest[0]
        if w.startswith('policy='):
            opts['policy'] = w[7:]
            if not POLICY.match(opts['policy']):
                raise JobError('policy must be namespace/name, like vllm/vllm-defense')
        elif w.startswith('ticks='):
            if not w[6:].isdigit() or not 1 <= int(w[6:]) <= 5000:
                raise JobError('ticks must be 1 to 5000')
            opts['ticks'] = int(w[6:])
        elif w == 'nosync':
            opts['sync'] = False
        else:
            break
        rest.pop(0)
    return opts, rest


class BenchBot:
    def __init__(self, cfg, telegram, dashboard=None, openai_transport=planner.openai_transport, sleep=time.sleep):
        self.cfg, self.tg, self.dashboard = cfg, telegram, dashboard
        self.openai_transport, self.sleep = openai_transport, sleep
        self.queue, self.current, self.lock = [], None, threading.Lock()
        self.guide_chats = set()
        self.wake, self.stopping = threading.Event(), threading.Event()
        private_dir(cfg.state)
        private_dir(cfg.state / 'jobs')

    # ── chat ───────────────────────────────────────────────────────────────
    def say(self, chat_id, text):
        try:
            self.tg.send_message(chat_id, text)
        except TelegramError as err:
            log('sendMessage failed: %s' % err)

    def send_file(self, chat_id, name, data, caption=None):
        try:
            self.tg.send_document(chat_id, name, data, caption)
        except TelegramError as err:
            log('sendDocument %s failed: %s' % (name, err))

    def handle(self, update):
        msg = update.get('message') or {}
        user = msg.get('from') or {}
        chat_id, text = (msg.get('chat') or {}).get('id'), (msg.get('text') or '').strip()
        if not chat_id or not text:
            return
        if user.get('id') not in self.cfg.allowed:
            if self.pair_owner(msg, text) or self.join_member(msg, text):
                self.say(chat_id, 'Your account is now authorized.\n' + HELP % {'policy': self.cfg.policy, 'ticks': self.cfg.ticks})
                return
            log('ignored a message from Telegram user id %s (@%s): not in BOT_ALLOWED_USER_IDS'
                % (user.get('id'), user.get('username', '')))
            return
        command, _, rest = text.partition(' ')
        command = command.split('@')[0].lower()
        who = '%s (@%s)' % (user.get('id'), user.get('username', ''))
        if command in ('/start', '/help'):
            self.say(chat_id, HELP % {'policy': self.cfg.policy, 'ticks': self.cfg.ticks})
        elif command == '/guide':
            return self.start_guide(chat_id)
        elif command == '/status':
            self.say(chat_id, self.status())
        elif command == '/runs':
            self.say(chat_id, self.runs())
        elif command == '/check':
            def dependency_check():
                lines = []
                check(self.cfg, os.environ, self.tg, lines.append)
                self.say(chat_id, '\n'.join(lines))
            threading.Thread(target=dependency_check, name='bench-check', daemon=True).start()
        elif command == '/invite':
            if user.get('id') not in self.cfg.admins:
                self.say(chat_id, 'Only a bot owner can create invitations.')
            elif (msg.get('chat') or {}).get('type') != 'private' or chat_id != user['id']:
                self.say(chat_id, 'Create invitations in your private chat with the bot.')
            else:
                self.say(chat_id, 'One-use member invite (valid for 24 hours):\n' + self.create_invite(user['id']))
        elif command == '/cancel':
            with self.lock:
                job = self.current
            if job:
                job.cancel.set()
                self.say(chat_id, 'Cancelling job %s after its current step (%s).' % (job.id, job.step))
            else:
                self.say(chat_id, 'Nothing is running.')
        elif command in ('/bench', '/param'):
            if not rest.strip():
                self.say(chat_id, HELP % {'policy': self.cfg.policy, 'ticks': self.cfg.ticks})
                return
            with self.lock:
                if len(self.queue) >= MAX_QUEUE:
                    self.say(chat_id, 'The queue is full (%d jobs); try again later.' % MAX_QUEUE)
                    return
                job = Job(command[1:], chat_id, who, rest.strip())
                self.queue.append(job)
                ahead = len(self.queue) - 1 + (1 if self.current else 0)
            log('queued %s job %s from %s' % (job.kind, job.id, who))
            self.say(chat_id, 'Queued %s job %s%s.' % (job.kind, job.id, ' (%d ahead)' % ahead if ahead else ''))
            self.wake.set()
        else:
            self.say(chat_id, 'Unknown command. /help lists them.')

    def start_guide(self, chat_id):
        """Upload independently of the benchmark queue and the polling thread."""
        with self.lock:
            pending = chat_id in self.guide_chats
            if not pending:
                self.guide_chats.add(chat_id)
        if pending:
            self.say(chat_id, 'Your guide download is already in progress. Please wait for the attachments.')
            return None
        worker = threading.Thread(target=self.deliver_guide, args=(chat_id,), name='bench-guide', daemon=True)
        try:
            worker.start()
        except Exception:
            with self.lock:
                self.guide_chats.discard(chat_id)
            raise
        return worker

    def deliver_guide(self, chat_id):
        try:
            # Read both before uploading, so an incomplete release cannot send half a guide.
            try:
                files = [(extension, (HERE / ('guide-en.' + extension)).read_bytes())
                         for extension in ('html', 'pdf')]
            except OSError as err:
                log('guide files unavailable: %s' % type(err).__name__)
                self.say(chat_id, 'The English guide is unavailable in this release. Please ask the operator to restore its HTML and PDF files.')
                return
            self.say(chat_id, 'English Brain Benchmark Playbook: HTML for offline reading and the command builder; PDF for reading and printing.')
            for extension, data in files:
                try:
                    receipt = self.tg.send_document(chat_id, 'phorvex-brain-benchmark-guide-en.' + extension, data,
                                                  'English Brain Benchmark Playbook (' + extension.upper() + ')')
                    log('guide %s delivered to chat %s (message %s)' % (extension, chat_id,
                                                                    (receipt or {}).get('message_id', '?')))
                except TelegramError as err:
                    log('guide %s upload failed: %s' % (extension, err))
                    self.say(chat_id, 'Could not send the %s guide. Please try /guide again.' % extension.upper())
        finally:
            with self.lock:
                self.guide_chats.discard(chat_id)

    def pair_owner(self, msg, text):
        """Consume an operator-created, expiring /start link while no owner is set."""
        pairing = self.cfg.state / 'pairing.json'
        parts = text.split()
        user_id = (msg.get('from') or {}).get('id')
        chat = msg.get('chat') or {}
        if (self.cfg.allowed != {0} or len(parts) != 2 or parts[0] != '/start'
                or chat.get('type') != 'private' or not isinstance(user_id, int) or user_id <= 0
                or chat.get('id') != user_id or not pairing.exists()):
            return False
        try:
            data = json.loads(pairing.read_text())
            if (pairing.stat().st_mode & 0o077 or time.time() >= data['expires_at']
                    or not hmac.compare_digest(hashlib.sha256(parts[1].encode()).hexdigest(), data['sha256'])):
                return False
        except (ValueError, KeyError, OSError, TypeError):
            return False
        owner = self.cfg.state / 'owner.json'
        with owner.open('x') as f:
            owner.chmod(0o600)
            json.dump({'id': user_id}, f)
        self.cfg.allowed = {user_id}
        self.cfg.admins = {user_id}
        pairing.unlink()
        log('paired Telegram owner id %s' % user_id)
        return True

    def create_invite(self, invited_by):
        if invited_by not in self.cfg.admins:
            raise JobError('only a bot owner can create invitations')
        username = self.tg.call('getMe')['username']
        payload = 'join_' + secrets.token_urlsafe(24)
        digest = hashlib.sha256(payload.encode()).hexdigest()
        directory = private_dir(self.cfg.state / 'invites')
        fd = os.open(directory / (digest + '.json'), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as f:
            json.dump({'expires_at': int(time.time()) + 86400, 'invited_by': invited_by}, f)
        return 'https://t.me/%s?start=%s' % (username, payload)

    def join_member(self, msg, text):
        parts = text.split()
        user_id = (msg.get('from') or {}).get('id')
        chat = msg.get('chat') or {}
        if (not self.cfg.admins or len(parts) != 2 or parts[0] != '/start'
                or not parts[1].startswith('join_') or chat.get('type') != 'private'
                or type(user_id) is not int or user_id <= 0 or chat.get('id') != user_id):
            return False
        digest = hashlib.sha256(parts[1].encode()).hexdigest()
        invite = self.cfg.state / 'invites' / (digest + '.json')
        try:
            data = json.loads(invite.read_text())
            if (invite.stat().st_mode & 0o077 or time.time() >= data['expires_at']
                    or data['invited_by'] not in self.cfg.admins):
                return False
        except (OSError, ValueError, KeyError, TypeError):
            return False
        # Claim the token before writing membership, so another consumer cannot
        # use the same invite even if the process stops during the write.
        claimed = invite.with_suffix('.used')
        try:
            invite.rename(claimed)
        except OSError:
            return False
        temp = self.cfg.state / ('members-' + uuid.uuid4().hex + '.tmp')
        try:
            rows = [row for row in read_members(self.cfg.state) if row['id'] != user_id]
            rows.append({'id': user_id, 'invited_by': data['invited_by'], 'joined_at': utc()})
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as f:
                json.dump(rows, f)
            temp.replace(self.cfg.state / 'members.json')
        except (OSError, ConfigError):
            temp.unlink(missing_ok=True)
            claimed.replace(invite)
            log('member authorization could not be persisted')
            return False
        self.cfg.allowed.add(user_id)
        claimed.unlink(missing_ok=True)
        log('authorized Telegram member id %s by invite' % user_id)
        return True

    def status(self):
        with self.lock:
            job, queued = self.current, list(self.queue)
        lines = ['Running: %s job %s, %s' % (job.kind, job.id, job.step) if job else 'Running: nothing']
        lines += ['Queued: %s job %s from %s' % (j.kind, j.id, j.user) for j in queued] or ['Queue: empty']
        return '\n'.join(lines)

    def runs(self, n=5):
        path = self.cfg.state / 'history.jsonl'
        if not path.exists():
            return 'No runs yet.'
        rows = [json.loads(line) for line in path.read_text().splitlines()[-n:]]
        return '\n'.join('%s %s %s %s: %s' % (r['finished'], r['kind'], r['id'], r['state'], r.get('headline', ''))
                         for r in reversed(rows))

    # ── jobs ───────────────────────────────────────────────────────────────
    def step(self, job, label):
        if job.cancel.is_set():
            raise JobError('cancelled before: %s' % label)
        job.step = label
        log('job %s: %s' % (job.id, label))
        self.say(job.chat_id, '[%s] %s' % (job.id, label))

    def run_next(self):
        with self.lock:
            if not self.queue:
                return False
            job = self.current = self.queue.pop(0)
        job.state = 'RUNNING'
        job.dir = self.cfg.state / 'jobs' / job.id
        job.dir.mkdir(parents=True)
        headline = ''
        try:
            headline = (self.run_param if job.kind == 'param' else self.run_bench)(job)
            job.state = 'DONE'
        except JobError as err:
            job.state = 'CANCELLED' if job.cancel.is_set() else 'FAILED'
            headline = str(err)
            self.say(job.chat_id, '[%s] %s: %s' % (job.id, job.state.lower(), err))
        except Exception as err:  # a bug, not a user error: details go to the job log only
            job.state = 'FAILED'
            headline = '%s during %s' % (type(err).__name__, job.step)
            (job.dir / 'error.txt').write_text(traceback.format_exc())
            log('job %s failed: %s' % (job.id, traceback.format_exc()))
            self.say(job.chat_id, '[%s] failed during "%s" (%s); details are in %s/error.txt on the host.'
                     % (job.id, job.step, type(err).__name__, job.dir))
        finally:
            for clone in ('candidate-src', 'base-src'):
                shutil.rmtree(job.dir / clone, ignore_errors=True)
            with open(self.cfg.state / 'history.jsonl', 'a') as f:
                f.write(json.dumps({'id': job.id, 'kind': job.kind, 'user': job.user, 'state': job.state,
                                    'created': job.created, 'finished': utc(), 'request': job.text[:300],
                                    'headline': headline[:300]}) + '\n')
            with self.lock:
                self.current = None
        return True

    def free_gb(self):
        return shutil.disk_usage(self.cfg.state).free / 2 ** 30

    def need_dashboard(self):
        if self.dashboard is None:
            raise JobError('the dashboard is not configured (DASHBOARD_URL, DASHBOARD_PASSWORD)')
        return self.dashboard

    def sync(self, job, policy):
        dash = self.need_dashboard()
        self.step(job, 'syncing recorded ticks for %s' % policy)
        try:
            started = dash.sync(policy)
            if started:
                done = dash.wait_job(started['id'], cancelled=job.cancel.is_set)
                if done.get('status') != 'COMPLETE':
                    raise JobError('sync failed: %s' % (done.get('message') or done.get('status')))
        except DashboardError as err:
            raise JobError('sync: %s' % err)

    def deliver(self, job, meta, result, rows, extra=(), limitations=()):
        text = report.summary(meta, result, rows)
        self.say(job.chat_id, text)
        html = report.page(meta, result, rows, limitations).encode()
        csv = report.table(rows)
        (job.dir / 'report.html').write_bytes(html)
        (job.dir / 'metrics.csv').write_bytes(csv)
        self.send_file(job.chat_id, 'report-%s.html' % job.id, html, 'Report %s' % job.id)
        self.send_file(job.chat_id, 'metrics-%s.csv' % job.id, csv)
        for name, data in extra:
            self.send_file(job.chat_id, name, data)
        if result.get('state') in ('INVALID', 'FAILED') or result.get('toolchain_fidelity') == 'DIVERGED':
            raise JobError('comparison is invalid or the local baseline diverged; inspect the attached report before using this candidate')
        changed = next((r for r in rows if r['metric_id'] == 'M-P21' and r['arm_id'] != 'control'
                        and r['arm_id'] != 'base-local' and r.get('dimension') is None), None)
        return 'changed decisions %s' % report.fmt(changed) if changed else (result.get('state') or '')

    def run_param(self, job):
        words = job.text.split()
        if not words or not PARAMETER.match(words[0]):
            raise JobError('usage: /param P-XXX-000 <value> [value...]; for example /param P-FEA-006 1.2 1.5')
        parameter, rest = words[0], words[1:]
        values = [w for w in rest if '=' not in w and w != 'nosync']
        opts, _ = parse_options([w for w in rest if '=' in w or w == 'nosync'], self.cfg)
        if not 1 <= len(values) <= 11:
            raise JobError('give 1 to 11 values to compare with the recorded value')
        arms = [{'arm_id': 'control', 'value_source': 'RECORDED_EFFECTIVE'}]
        for v in values:
            if v == 'unset':
                arms.append({'arm_id': 'unset', 'unset': True})
                continue
            try:
                number = float(v)
            except ValueError:
                raise JobError('%s is not a number' % v)
            arms.append({'arm_id': ('v%s' % v)[:40], 'value': number})
        if opts['sync']:
            self.sync(job, opts['policy'])
        dash = self.need_dashboard()
        cohort = {'max_snapshots': opts['ticks'], 'spacing': 'even'}
        cohort.update(self.recorded_window(opts['policy']))
        request = {'title': 'Telegram %s: %s %s' % (job.id, parameter, ' '.join(values)), 'mode': 'REPLAY',
                   'parameter_id': parameter, 'policy': opts['policy'], 'arms': arms,
                   'cohort': cohort,
                   'hypothesis': 'Requested from Telegram by %s' % job.user, 'primary_metric_id': 'M-P21',
                   'secondary_metric_ids': ['M-P26', 'M-P19', 'M-P22', 'M-P25'], 'safety_metric_ids': []}
        try:
            self.step(job, 'preflight')
            pf = dash.preflight(request)
            if pf.get('status') != 'PASS':
                bad = ['%s: %s' % (c.get('id'), c.get('message')) for c in pf.get('checks', []) if c.get('status') == 'FAIL']
                errs = ['%s %s' % (e.get('error_code'), e.get('reason')) for e in pf.get('errors', [])]
                raise JobError('preflight failed:\n' + '\n'.join(bad + errs or [str(pf.get('status'))]))
            self.step(job, 'replaying on the dashboard')
            experiment = dash.create(request)
            done = dash.wait_experiment(experiment['id'], cancelled=job.cancel.is_set,
                                        progress=lambda m: self.say(job.chat_id, '[%s] %s' % (job.id, m)))
            if done['status'] in ('FAILED', 'INTERRUPTED', 'PREFLIGHT_FAILED', 'INVALID'):
                raise JobError('the experiment ended %s: %s' % (done['status'], done.get('message') or ''))
            rows = dash.metrics(experiment['id'])
            md = dash.artifact(experiment['id'], 'report.md')
        except DashboardError as err:
            raise JobError(str(err) + ('\n' + json.dumps(err.body)[:800] if err.body else ''))
        result = {**(done.get('result') or {}), 'state': done['status']}
        meta = {'kind': 'Parameter experiment', 'title': request['title'], 'policy': opts['policy'],
                'parameter': parameter, 'job': job.id}
        return self.deliver(job, meta, result, rows, [('math-lab-report-%s.md' % job.id, md)],
                            (done.get('manifest') or {}).get('limitations') or [])

    def recorded_window(self, policy):
        """A contiguous deployed-revision window, using the dashboard's existing time filters."""
        if not self.cfg.data:
            return {}
        current = Path(self.cfg.data) / 'mathlab/bin/current.json'
        if not current.exists():
            raise JobError('no deployed brain-replay identity; sync first')
        base = json.loads(current.read_text())['git_sha']
        ns, name = policy.split('/')
        entries = code_experiment.local_index(self.cfg.data, ns, name)
        indices = [i for i, entry in enumerate(entries) if entry['header'].get('gitSHA') == base]
        if not indices:
            raise JobError('no recorded ticks from deployed commit %s; sync current snapshots first' % base[:12])
        last = first = indices[-1]
        while first > 0 and entries[first - 1]['header'].get('gitSHA') == base:
            first -= 1
        window = {'since': entries[first]['header']['capturedAt']}
        if last + 1 < len(entries):
            window['until'] = entries[last + 1]['header']['capturedAt']
        return window

    def run_bench(self, job):
        opts, words = parse_options(job.text.split(), self.cfg)
        prompt = ' '.join(words).strip()
        if len(prompt) < 10:
            raise JobError('describe the brain change in words, for example: /bench raise the rotate threshold for vllm')
        if not self.cfg.repo or not self.cfg.data:
            raise JobError('the bot needs BOT_REPO (an operator clone) and MATHLAB_DATA_DIR for /bench')
        # Two checkouts and a Go build: never let a job fill the host's disk.
        free = self.free_gb()
        if free < self.cfg.min_free_gb:
            raise JobError('only %.1f GB is free on the host and /bench needs %.1f GB (BOT_MIN_FREE_GB); '
                           'free some space first' % (free, self.cfg.min_free_gb))
        if opts['sync']:
            self.sync(job, opts['policy'])
        ns, name = opts['policy'].split('/')

        self.step(job, 'reading the deployed brain')
        control = json.loads((Path(self.cfg.data) / 'mathlab' / 'bin' / 'current.json').read_text()) \
            if (Path(self.cfg.data) / 'mathlab' / 'bin' / 'current.json').exists() else None
        if not control or not control.get('git_sha') or not Path(control.get('path', '')).exists():
            raise JobError('no verified deployed brain-replay yet; run a sync on the dashboard (or drop nosync)')
        if replay_build.sha256_file(control['path']) != control.get('binary_sha256'):
            raise JobError('the deployed brain-replay on disk does not match its recorded sha256; re-sync on the dashboard')
        try:
            toolchain = replay_build.deployed_toolchain(control['path'], go=self.cfg.go)
        except replay_build.BuildError as err:
            raise JobError(str(err))
        base = control['git_sha']
        try:
            present = replay_build._git(self.cfg.repo, 'cat-file', '-t', base + '^{commit}') == 'commit'
        except replay_build.BuildError:
            present = False
        if not present:
            raise JobError('BOT_REPO does not contain the deployed commit %s; fetch it there' % base[:12])
        tags = replay_build.tags_at(self.cfg.repo, base)
        tag = tags[0] if tags else None  # the deployed binary's sha256 and git_sha are the base's provenance
        base_name = '%s (%s)' % (tag, base[:12]) if tag else base[:12]

        self.step(job, 'selecting recorded ticks from deployed commit %s' % base[:12])
        cohort_request = {'max_snapshots': opts['ticks'], 'spacing': 'even', 'git_sha': base}
        cohort = code_experiment.select_cohort(self.cfg.data, {'namespace': ns, 'policy': name, 'cohort': cohort_request})
        if not cohort:
            raise JobError('no recorded ticks from deployed commit %s; sync current snapshots before benchmarking' % base[:12])
        cohort_request['digests'] = [entry['digest'] for entry in cohort]

        self.step(job, 'asking the LLM for a change against %s' % base_name)
        (job.dir / 'prompt.txt').write_text(prompt + '\n')
        try:
            plan_record, _ = planner.plan(planner.parse_args([
                '--src-repo', self.cfg.repo, '--base-commit', base, '--prompt-file', str(job.dir / 'prompt.txt'),
                '--out-diff', str(job.dir / 'brain.diff'), '--out', str(job.dir / 'PLAN.json')]), self.openai_transport)
        except planner.PlannerError as err:
            raise JobError('the LLM step failed: %s' % err)

        self.step(job, 'landing the change on a throwaway branch')
        try:
            cand = candidate.make_candidate(candidate.parse_args([
                '--src-repo', self.cfg.repo, '--run-dir', str(job.dir), '--run-id', job.id,
                *(['--base-tag', tag] if tag else []), '--base-commit', base, '--diff', str(job.dir / 'brain.diff'), '--prompt-file', str(job.dir / 'prompt.txt'),
                '--summary', prompt[:60], '--planner', 'openai', '--model', plan_record['model'],
                '--out', str(job.dir / 'CANDIDATE.json')]))
        except candidate.CandidateError as err:
            raise JobError('the proposed change was refused: %s' % err)

        try:
            base_src = replay_build.checkout(self.cfg.repo, base, job.dir / 'base-src')
            packages = sorted({'./internal/decision', './cmd/brain-replay'} | {
                './' + str(Path(c['path']).parent.relative_to('phorvex')) for c in cand['changedPaths']})
            tests = {}
            for arm, src, commit in (('base-local', base_src, base),
                                     ('candidate', cand['repo'], cand['candidateCommit'])):
                # A newly added package has no baseline tests.
                selected = [p for p in packages if (Path(src) / 'phorvex' / p).is_dir()]
                self.step(job, 'running Go unit tests: %s (%s; %s)' % (arm, ', '.join(selected), toolchain))
                tests[arm] = replay_build.test(src, commit, selected, go=self.cfg.go,
                                               log=job.dir / ('tests-%s.jsonl' % arm), toolchain=toolchain)
                (job.dir / 'TESTS.json').write_text(json.dumps(tests, indent=2) + '\n')
                if tests[arm]['status'] != 'PASS':
                    self.send_file(job.chat_id, 'tests-%s-%s.jsonl' % (arm, job.id),
                                   (job.dir / ('tests-%s.jsonl' % arm)).read_bytes())
                    raise JobError('%s Go tests %s; benchmark stopped. See the attached test log.'
                                   % (arm, tests[arm]['status']))
            self.step(job, 'building brain-replay from the deployed commit and from the candidate')
            replay_build.build(base_src, base, job.dir / 'bin' / 'base-local', go=self.cfg.go,
                               log=job.dir / 'build-base.log', toolchain=toolchain)
            replay_build.build(cand['repo'], cand['candidateCommit'], job.dir / 'bin' / 'candidate', go=self.cfg.go,
                               log=job.dir / 'build-candidate.log', toolchain=toolchain)
            base_local = code_experiment.identity(job.dir / 'bin' / 'base-local')
            cand_id = code_experiment.identity(job.dir / 'bin' / 'candidate')
        except replay_build.BuildError as err:
            raise JobError('the build failed (the candidate may not compile): %s' % err)

        self.step(job, 'replaying recorded ticks: deployed, deployed-built-here, candidate')
        request = {'experiment_id': 'bot-' + job.id, 'title': prompt[:200], 'namespace': ns, 'policy': name,
                   'cohort': cohort_request, 'base_commit': base,
                   'candidate_commit': cand['candidateCommit'], 'created_at': job.created,
                   'tests': tests,
                   'hypothesis': 'Requested from Telegram by %s' % job.user,
                   'provenance': {'base_tag': tag, 'candidate_tag': cand['candidateTag'], 'changed_paths': cand['changedPaths'],
                                  'go_toolchain': toolchain,
                                  'model': plan_record['model'], 'prompt_sha256': cand['promptSha256'], 'diff_sha256': cand['diffSha256']}}
        try:
            result, rows = code_experiment.run(self.cfg.data, job.dir / 'experiment', request, control, base_local, cand_id)
        except code_experiment.CodeExperimentError as err:
            raise JobError(str(err))
        result['tests'] = tests
        meta = {'kind': 'Code experiment (LLM candidate vs deployed brain)', 'title': prompt[:200], 'policy': opts['policy'],
                'base': base_name, 'candidate': '%s %s' % (cand['candidateTag'], cand['candidateCommit'][:12]),
                'changed': ', '.join(c['path'] for c in cand['changedPaths']), 'request': prompt, 'job': job.id}
        manifest = json.loads((job.dir / 'experiment' / 'experiment_manifest.json').read_text())
        return self.deliver(job, meta, result, rows, [('candidate-%s.diff' % job.id, (job.dir / 'brain.diff').read_bytes()),
                            ('tests-%s.json' % job.id, (job.dir / 'TESTS.json').read_bytes())],
                            manifest.get('limitations') or [])

    # ── loops ──────────────────────────────────────────────────────────────
    def worker(self):
        while not self.stopping.is_set():
            if not self.run_next():
                self.wake.wait(5)
                self.wake.clear()

    def skip_backlog(self):
        """At the first start, confirm and ignore anything already waiting."""
        offset_file = self.cfg.state / 'offset'
        if offset_file.exists():
            return int(offset_file.read_text())
        updates = self.tg.get_updates(timeout=0)
        offset = (max(u['update_id'] for u in updates) + 1) if updates else 0
        if updates:
            log('first start: skipped %d waiting update(s) without running them' % len(updates))
        offset_file.write_text(str(offset))
        return offset

    def poll_once(self, offset):
        for update in self.tg.get_updates(offset=offset or None) or []:
            offset = update['update_id'] + 1
            (self.cfg.state / 'offset').write_text(str(offset))
            self.handle(update)
        return offset

    def serve(self):
        try:
            configure_interface(self.tg)
            log('English command menu and profile configured')
        except TelegramError as err:
            log('could not update the Telegram interface: %s; retry on next restart' % err)
        offset = self.skip_backlog()
        threading.Thread(target=self.worker, name='bench-worker', daemon=True).start()
        backoff = 1
        log('serving Telegram user ids %s' % sorted(self.cfg.allowed))
        while not self.stopping.is_set():
            try:
                offset = self.poll_once(offset)
                backoff = 1
            except TelegramError as err:
                log('getUpdates failed: %s; retrying in %ds' % (err, backoff))
                self.sleep(backoff)
                backoff = min(backoff * 2, 60)


def check(cfg, env, telegram=None, out=print, model_probe=planner.check_model):
    """Preflight every dependency; print one line each, never a secret value.
    The Telegram token, the allowlist and the state directory are essential;
    anything else only disables the commands named."""
    import subprocess
    rows, essential_failed = [], False

    def item(name, fn, essential=False, disables=''):
        nonlocal essential_failed
        try:
            rows.append(('PASS', name, fn() or ''))
        except Exception as err:  # each check reports its own reason
            if essential:
                essential_failed = True
            rows.append(('FAIL' if essential else 'WARN', name, '%s%s' % (err, '; disables ' + disables if disables else '')))

    item('telegram token', lambda: 'bot @%s' % (telegram or Telegram(cfg.token)).call('getMe')['username'], essential=True)
    if cfg.allowed == {0}:
        rows.append(('WARN', 'allowlist', 'owner pairing pending; no Telegram account is authorized'))
    else:
        item('allowlist', lambda: '%d Telegram user id(s)' % len(cfg.allowed), essential=True)

    def state():
        private_dir(cfg.state)
        if cfg.state.stat().st_mode & 0o077:
            raise ConfigError('%s is readable by others; chmod 700 it' % cfg.state)
        return str(cfg.state)
    item('state directory', state, essential=True)

    def dash():
        d = cfg.dashboard()
        if d is None:
            raise ConfigError('DASHBOARD_URL and DASHBOARD_PASSWORD are not set')
        policies = d.policies()
        return 'logged in; capture policies %s' % ', '.join(p['policy'] for p in policies.get('policies', []))
    item('dashboard', dash, disables='/param and the sync before /bench')

    def deployed():
        if not cfg.data:
            raise ConfigError('MATHLAB_DATA_DIR is not set')
        current = Path(cfg.data) / 'mathlab' / 'bin' / 'current.json'
        ident = json.loads(current.read_text())
        if replay_build.sha256_file(ident['path']) != ident.get('binary_sha256'):
            raise ConfigError('%s does not match its recorded sha256' % ident['path'])
        ns, name = cfg.policy.split('/')
        entries = code_experiment.select_cohort(cfg.data, {'namespace': ns, 'policy': name,
                                                         'cohort': {'max_snapshots': 5000, 'git_sha': ident['git_sha']}})
        ticks = sum(e['header'].get('gitSHA') == ident['git_sha'] for e in entries)
        if not ticks:
            raise ConfigError('brain %s; no recorded ticks from this commit; sync current snapshots' % ident['git_sha'][:12])
        return 'brain %s; %d recorded ticks for %s from this commit (up to 5000 inspected)' % (ident['git_sha'][:12], ticks, cfg.policy)
    item('deployed brain-replay', deployed, disables='/bench')

    def repo():
        if not cfg.repo:
            raise ConfigError('BOT_REPO is not set')
        deployed = json.loads((Path(cfg.data or '/nonexistent') / 'mathlab' / 'bin' / 'current.json').read_text())['git_sha']
        if replay_build._git(cfg.repo, 'cat-file', '-t', deployed + '^{commit}') != 'commit':
            raise ConfigError('%s does not contain the deployed commit %s' % (cfg.repo, deployed[:12]))
        tags = replay_build.tags_at(cfg.repo, deployed)
        return '%s holds the deployed commit %s%s' % (cfg.repo, deployed[:12], ' (%s)' % tags[0] if tags else ', untagged')
    item('operator repository', repo, disables='/bench')

    def disk():
        private_dir(cfg.state)
        free = shutil.disk_usage(cfg.state).free / 2 ** 30
        if free < cfg.min_free_gb:
            raise ConfigError('%.1f GB free, below BOT_MIN_FREE_GB=%.1f' % (free, cfg.min_free_gb))
        return '%.1f GB free (BOT_MIN_FREE_GB=%.1f)' % (free, cfg.min_free_gb)
    item('free disk', disk, disables='/bench')
    def go():
        version = subprocess.run([cfg.go, 'version'], capture_output=True, text=True, check=True).stdout.strip()
        current = Path(cfg.data or '/nonexistent') / 'mathlab/bin/current.json'
        if current.exists():
            ident = json.loads(current.read_text())
            version += '; replay uses ' + replay_build.deployed_toolchain(ident['path'], go=cfg.go)
        return version
    item('go', go, disables='/bench')

    def openai():
        missing = [k for k in ('OPENAI_API_KEY', 'OPENAI_MODEL') if not env.get(k)]
        if missing:
            raise ConfigError('%s not set' % ' and '.join(missing))
        if env.get('OPENAI_API', 'chat') not in ('chat', 'responses'):
            raise ConfigError('OPENAI_API must be chat or responses')
        model_probe(env)
        return 'authenticated; model %s at %s (%s)' % (env['OPENAI_MODEL'],
            env.get('OPENAI_BASE_URL') or planner.DEFAULT_BASE_URL, env.get('OPENAI_API', 'chat'))
    item('openai', openai, disables='/bench')
    for status, name, detail in rows:
        out('%-4s %-22s %s' % (status, name, detail))
    return 1 if essential_failed else 0


def main():
    try:
        cfg = Config(os.environ)
        if sys.argv[1:] == ['--check']:
            return check(cfg, os.environ)
        bot = BenchBot(cfg, Telegram(cfg.token), cfg.dashboard())
    except (ConfigError, TelegramError) as err:
        log('configuration error: %s' % err)
        return 2

    def stop(*_):
        bot.stopping.set()
        with bot.lock:
            job = bot.current
        if job:
            bot.say(job.chat_id, '[%s] the bot is restarting; this job is interrupted. Send it again.' % job.id)
        log('stopping')
        sys.exit(0)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    bot.serve()
    return 0


if __name__ == '__main__':
    sys.exit(main())
