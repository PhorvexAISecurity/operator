"""Client for the benchmark dashboard's Math Lab API (benchmark/apps/api).

The bot runs parameter experiments through the dashboard rather than beside it,
so they share its one-job-at-a-time queue, preflight, storage and exports, and
show up in the dashboard too. Login is the dashboard password (a signed
httpOnly cookie); mutations carry the configured public Origin, as the API
requires. TLS is verified against the given CA, for example Caddy's internal
root. The password is never logged.
"""
import json
import ssl
import time
import urllib.error
import urllib.request
from http.cookiejar import CookieJar
from urllib.parse import urlsplit

TERMINAL = {'COMPLETE', 'PARTIAL', 'INVALID', 'PREFLIGHT_FAILED', 'FAILED', 'INTERRUPTED'}


class DashboardError(Exception):
    def __init__(self, message, status=None, body=None):
        super().__init__(message)
        self.status, self.body = status, body


class Dashboard:
    def __init__(self, url, password, origin=None, cafile=None, timeout=60, sleep=time.sleep):
        self.url = url.rstrip('/')
        parts = urlsplit(self.url)
        self.origin = origin or '%s://%s' % (parts.scheme, parts.netloc)
        self._password = password
        self.timeout, self.sleep = timeout, sleep
        handlers = [urllib.request.HTTPCookieProcessor(CookieJar())]
        if parts.scheme == 'https':
            handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=cafile)))
        self.opener = urllib.request.build_opener(*handlers)
        self._logged_in = False

    def _call(self, method, path, body=None, raw=False, retry=True):
        headers = {'Accept': 'application/json'}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers['Content-Type'] = 'application/json'
        if method not in ('GET', 'HEAD'):
            headers['Origin'] = self.origin
        req = urllib.request.Request(self.url + path, data=data, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                payload = resp.read()
        except urllib.error.HTTPError as err:
            text = err.read().decode('utf-8', 'replace')[:600]
            if err.code == 401 and retry and path != '/api/auth/login':
                self.login()
                return self._call(method, path, body, raw, retry=False)
            try:
                parsed = json.loads(text)
            except ValueError:
                parsed = None
            raise DashboardError('%s %s: HTTP %d' % (method, path, err.code), err.code, parsed or text)
        except (urllib.error.URLError, OSError) as err:
            raise DashboardError('%s %s: %s' % (method, path, getattr(err, 'reason', err)))
        if raw:
            return payload
        return json.loads(payload) if payload else None

    def login(self):
        self._call('POST', '/api/auth/login', {'password': self._password}, retry=False)
        self._logged_in = True

    def _ensure(self):
        if not self._logged_in:
            self.login()

    def policies(self):
        self._ensure()
        return self._call('GET', '/api/math/policies')

    def sync(self, policy):
        """Start a sync of recorded ticks; reuse one already queued for the policy."""
        self._ensure()
        try:
            return self._call('POST', '/api/math/sync', {'policy': policy})
        except DashboardError as err:
            if err.status == 409:
                return None
            raise

    def job(self, job_id):
        return self._call('GET', '/api/math/jobs/%s' % job_id)

    def preflight(self, request):
        self._ensure()
        return self._call('POST', '/api/math/experiments/preflight', request)

    def create(self, request):
        self._ensure()
        return self._call('POST', '/api/math/experiments', request)

    def detail(self, experiment_id):
        return self._call('GET', '/api/math/experiments/%s' % experiment_id)

    def metrics(self, experiment_id):
        return self._call('GET', '/api/math/experiments/%s/metrics' % experiment_id)

    def artifact(self, experiment_id, name):
        return self._call('GET', '/api/math/experiments/%s/artifacts/%s' % (experiment_id, name), raw=True)

    def wait_job(self, job_id, timeout=3600, poll=5, cancelled=lambda: False):
        deadline = time.monotonic() + timeout
        while True:
            job = self.job(job_id)
            if job.get('status') in ('COMPLETE', 'FAILED'):
                return job
            if cancelled() or time.monotonic() > deadline:
                raise DashboardError('job %s did not finish (%s)' % (job_id, job.get('status')))
            self.sleep(poll)

    def wait_experiment(self, experiment_id, timeout=4 * 3600, poll=10, cancelled=lambda: False, progress=None):
        deadline, last = time.monotonic() + timeout, None
        while True:
            detail = self.detail(experiment_id)
            status = detail.get('status')
            message = (detail.get('progress') or {}).get('message')
            if progress and message and message != last:
                progress(message)
                last = message
            if status in TERMINAL:
                return detail
            if cancelled() or time.monotonic() > deadline:
                raise DashboardError('experiment %s did not finish (%s)' % (experiment_id, status))
            self.sleep(poll)
