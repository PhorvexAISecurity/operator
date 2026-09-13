"""How the pipeline reaches the system under test.

The console binds to localhost on the jump server, so almost every real run goes through
SSH. `local` exists for running the pipeline ON that server (or anywhere the console and
kubectl are directly reachable), and keeps the rest of the code transport-agnostic.

No secret is ever written to disk by this module. The SSH password is passed to sshpass
through an environment variable rather than argv, and the console bearer credential travels
to curl as a `-K -` configuration file on the child's stdin, so neither appears in `ps`
output, in a shell command string, in a URL or in a retained error.

Every read of the cluster returns an `Observation` (see observation.py) rather than a bare
value. A Forbidden pod list and an empty pod list are the same `{}` to a caller that only
looks at the value, and that equivalence is precisely how "the pod is gone" became
"the rotation was confirmed". Callers here have to look at the status.
"""

import ipaddress
import json
import os
import re
import selectors
import shlex
import signal
import stat
import subprocess
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

import observation as obs
from capture import CaptureLimits, CaptureOverflow, CaptureScope, StreamCapture


class TransportError(RuntimeError):
    pass


class ConsoleAccessError(TransportError):
    """The console could be reached but this client cannot use it as configured.

    Absent, malformed or rejected console credentials, a missing grant, a redirect, a
    certificate the transport host does not trust, or a configuration that names none of
    those correctly. Nothing here fixes itself by waiting, so the readiness wait re-raises
    it instead of retrying until its deadline and reporting "did not become ready".
    """


# The console bearer credential. The value arrives ONLY through this variable or a private
# token file; never through config.json, argv or a URL. The variable is scrubbed from every
# child environment so it is not inherited by kubectl, curl or a remote shell.
CONSOLE_TOKEN_ENV = "PHORVEX_CONSOLE_TOKEN"
CONSOLE_TOKEN_FILE_ENV = "PHORVEX_CONSOLE_TOKEN_FILE"
CONSOLE_BASE_ENV = "PHORVEX_CONSOLE_BASE"
CONSOLE_MODE_ENV = "PHORVEX_CONSOLE_MODE"
CONSOLE_AUTH_ENV = "PHORVEX_CONSOLE_AUTH"
CONSOLE_CA_FILE_ENV = "PHORVEX_CONSOLE_CA_FILE"
# Bounds on what is accepted as a credential. A bearer token is opaque here — the deployed
# verifier decides what it means — but it must be ONE line of the RFC 6750 token charset,
# which is also exactly what can be placed in a curl configuration line without escaping.
# The byte bound keeps that line under the 4 KiB configuration-line limit of older curl
# builds on a jump host, where a silently truncated header would surface as a puzzling 401.
MAX_TOKEN_BYTES = 4000
MIN_TOKEN_CHARS = 16
_BEARER_TOKEN = re.compile(r"^[A-Za-z0-9._~+/-]+=*$")
# curl exit codes that name a contract failure rather than a transient one.
CURL_TOO_MANY_REDIRECTS = 47
CURL_TLS_EXITS = (35, 51, 53, 54, 58, 59, 60, 66, 77, 80, 82, 83, 90, 91)


# How a deliberately bounded stream command reports "the window elapsed": `timeout` kills
# with 124, `curl -m` gives up with 28, and a shell reports a SIGTERM'd child as 143. Any
# other non-zero exit means the read failed and the window was not observed.
EXPECTED_STREAM_EXITS = (0, 28, 124, 143)


def _password():
    """SSH password from the environment, then a 0600 file. Never from config.json."""
    env = os.environ.get("PHORVEX_SSH_PASSWORD")
    if env:
        return env
    secret = Path.home() / ".phorvex-e2e" / "secret"
    if secret.exists():
        return secret.read_text(encoding="utf-8").strip()
    raise TransportError(
        "no SSH password: set PHORVEX_SSH_PASSWORD or write it to ~/.phorvex-e2e/secret (chmod 600)"
    )


def rfc3339(epoch):
    """kubectl --since-time wants RFC3339; seconds resolution is what the API accepts."""
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Transport:
    """Environment overrides win over config.json.

    CI keeps the jump host in repository secrets rather than in a committed file, and a
    developer testing against a different cluster should not have to edit — and risk
    committing — config.json to do it.
    """

    def __init__(self, cfg):
        self.kind = os.environ.get("PHORVEX_TRANSPORT") or cfg.get("kind", "local")
        self.host = os.environ.get("PHORVEX_SSH_HOST") or cfg.get("host")
        self.user = os.environ.get("PHORVEX_SSH_USER") or cfg.get("user")
        self.port = int(os.environ.get("PHORVEX_SSH_PORT") or cfg.get("port", 22))
        self.connect_timeout = int(cfg.get("connect_timeout_sec", 10))
        if self.kind == "ssh":
            self._pw = _password()

    def describe(self):
        return "local shell" if self.kind == "local" else f"ssh {self.user}@{self.host}:{self.port}"

    def _command(self, command):
        if self.kind == "local":
            argv, env = ["/bin/sh", "-c", command], None
        else:
            argv = [
                "sshpass", "-e", "ssh",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "LogLevel=ERROR",
                "-o", f"ConnectTimeout={self.connect_timeout}",
                "-p", str(self.port), f"{self.user}@{self.host}", command,
            ]
            env = dict(os.environ, SSHPASS=self._pw)
        # The console credential is delivered on stdin by the caller that owns it; the child
        # (a shell, kubectl, curl or a remote login) never inherits it through the environment.
        if env is None:
            env = dict(os.environ)
        env.pop(CONSOLE_TOKEN_ENV, None)
        return argv, env

    def run(self, command, timeout=60, stdin=None):
        """Run a shell command; returns (rc, stdout, stderr), including probe failures.

        `stdin` is text handed to the child's standard input and closed — the only channel a
        credential travels on. Without it the child reads end-of-file, never this process's
        terminal, so a remote command cannot block on input nobody will type.
        """
        argv, env = self._command(command)
        try:
            p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=env,
                               input=stdin if stdin is not None else "")
        except subprocess.TimeoutExpired:
            return obs.TIMEOUT_RC, "", f"timeout after {timeout}s"
        except FileNotFoundError as e:
            raise TransportError(f"transport binary missing: {e}") from e
        return p.returncode, p.stdout, p.stderr

    def capture_live(self, command, seconds, limits, scope=None, on_connected=None, stdin=None):
        """Frame the stream as it arrives; fire (once) only after it is genuinely open.

        A post-fire reconnect can lose a fast reaction: the deployed console's initial
        replay has a small byte window, not a guaranteed record count. Wait for its actual
        heartbeat, then fire once and observe a full window.

        There is deliberately no reconnect. Reopening the stream after a drop would produce
        a record set with an unknown hole in it, and nothing in this API proves gap-free
        continuity, so a lost stream fails closed instead of resuming.
        """
        argv, env = self._command(command)
        stream = StreamCapture(limits, scope)
        errors = bytearray()
        live = on_connected is not None
        deadline = time.monotonic() + self.connect_timeout + 15
        # Without a callback there is nothing to synchronise with, so the window starts now.
        if not live:
            deadline = time.monotonic() + seconds
        closed_early = False
        p = subprocess.Popen(argv, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, start_new_session=True)
        try:
            # Whatever the command needs on stdin (the curl credential configuration) is
            # written and closed up front; the stream itself only ever flows back.
            try:
                if stdin:
                    p.stdin.write(stdin.encode())
                p.stdin.close()
            except BrokenPipeError:
                pass    # the child already exited; its exit and stderr say why below
            finally:
                if not p.stdin.closed:
                    try:
                        p.stdin.close()
                    except BrokenPipeError:
                        pass
            with selectors.DefaultSelector() as selector:
                selector.register(p.stdout, selectors.EVENT_READ, "stdout")
                selector.register(p.stderr, selectors.EVENT_READ, "stderr")
                while time.monotonic() < deadline:
                    for key, _ in selector.select(min(0.5, max(0, deadline - time.monotonic()))):
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            if key.data == "stdout":
                                closed_early = True
                            continue
                        if key.data == "stderr":
                            errors.extend(chunk)
                            del errors[:-65536]
                            continue
                        try:
                            stream.feed(chunk)
                        except CaptureOverflow as overflow:
                            raise TransportError(str(overflow)) from overflow
                        if on_connected is not None and stream.connected:
                            on_connected()          # exactly once; the pipe retains early decisions
                            on_connected = None
                            deadline = time.monotonic() + seconds
                    if closed_early:
                        break
                if closed_early and live:
                    # The remote window outlives ours by 90s, so an early close here means
                    # the stream dropped — and the reaction we fired for may be in the hole.
                    raise TransportError(
                        "audit stream closed before observation completed: "
                        + obs.redact(errors.decode(errors="replace")[-500:]))
                if on_connected is not None:
                    raise TransportError("audit stream never acknowledged readiness; no signal fired")
                if closed_early:
                    # Without a callback the remote command bounds the window itself, so it
                    # ending is the normal path — but only with an exit code that means
                    # "the window elapsed". Anything else is a failed read, not a short one.
                    code = p.wait(timeout=5)
                    if code not in EXPECTED_STREAM_EXITS:
                        return stream.finish(
                            complete=False,
                            reason=f"the stream command exited {code}: "
                                   + obs.redact(errors.decode(errors="replace")[-300:]))
                return stream.finish()
        finally:
            # Own process group only; also stops local shell pipeline children.
            if p.poll() is None:
                try:
                    os.killpg(p.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(p.pid, signal.SIGKILL)
                    p.wait(timeout=5)
            p.stdout.close()
            p.stderr.close()


def _tail(text, n):
    """The last n characters of a message, redacted first so no secret fragment survives."""
    text = obs.redact((text or "").strip(), limit=1 << 30)
    return text[-n:]


def _is_loopback_host(hostname):
    """Loopback as the transport host's curl will resolve it: localhost, 127/8 or ::1."""
    if not hostname:
        return False
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _validate_bearer_token(value, source):
    """One bounded line of the RFC 6750 token charset, or a named refusal.

    The client never decodes the token: whether it is a valid, unexpired, granted identity is
    the deployed verifier's decision. What is checked here is only that the value is a
    credential-shaped secret that can be carried safely — anything else (an empty secret, a
    pasted multi-line blob, a value with quotes or spaces) is a configuration mistake that
    would otherwise surface as an opaque 401.
    """
    if isinstance(value, bytes):
        try:
            value = value.decode("ascii")
        except UnicodeDecodeError as e:
            raise ConsoleAccessError(f"console token from {source} is not ASCII text") from e
    if value.endswith("\r\n"):
        value = value[:-2]
    elif value.endswith("\n"):
        value = value[:-1]
    if value == "":
        raise ConsoleAccessError(f"console token from {source} is empty")
    if "\n" in value or "\r" in value:
        raise ConsoleAccessError(
            f"console token from {source} spans several lines; a bearer token is exactly one line")
    if len(value) > MAX_TOKEN_BYTES:
        raise ConsoleAccessError(
            f"console token from {source} exceeds {MAX_TOKEN_BYTES} bytes")
    if len(value) < MIN_TOKEN_CHARS:
        raise ConsoleAccessError(
            f"console token from {source} is shorter than {MIN_TOKEN_CHARS} characters; "
            "that is not a credential")
    if not _BEARER_TOKEN.match(value):
        raise ConsoleAccessError(
            f"console token from {source} contains characters outside the bearer token "
            "charset (letters, digits, '-._~+/' and trailing '='); check for whitespace, "
            "quotes or a wrapped value")
    return value


def _read_token_file(path):
    """A private regular file owned by this user, holding one bounded line."""
    expanded = os.path.expanduser(path)
    try:
        st = os.stat(expanded)
    except FileNotFoundError:
        raise ConsoleAccessError(
            f"console token file {path} does not exist; write the bearer token there "
            f"(chmod 600) or set {CONSOLE_TOKEN_ENV}") from None
    except OSError as e:
        raise ConsoleAccessError(f"console token file {path} is not readable: {e}") from e
    if not stat.S_ISREG(st.st_mode):
        raise ConsoleAccessError(f"console token file {path} is not a regular file")
    if st.st_mode & 0o077:
        raise ConsoleAccessError(
            f"console token file {path} is readable by other users "
            f"(mode {stat.S_IMODE(st.st_mode):04o}); chmod 600 it")
    if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
        raise ConsoleAccessError(f"console token file {path} is not owned by this user")
    if st.st_size > MAX_TOKEN_BYTES + 2:
        raise ConsoleAccessError(
            f"console token file {path} is {st.st_size} bytes and exceeds the "
            f"{MAX_TOKEN_BYTES}-byte bound on a bearer token")
    with open(expanded, "rb") as f:
        return _validate_bearer_token(f.read(MAX_TOKEN_BYTES + 3), f"file {path}")


def _console_token(cfg):
    """The bearer credential from exactly one configured source.

    `PHORVEX_CONSOLE_TOKEN` carries the value itself (a CI secret); `PHORVEX_CONSOLE_TOKEN_FILE`
    or `console.token_file` names a private file. Both present is refused rather than
    resolved: two credentials configured at once means nobody can say which identity a run
    used. The loaded value is registered for redaction before it is returned.
    """
    env_value = os.environ.get(CONSOLE_TOKEN_ENV)
    file_path = os.environ.get(CONSOLE_TOKEN_FILE_ENV) or cfg.get("token_file")
    file_present = bool(file_path) and os.path.lexists(os.path.expanduser(file_path))
    if env_value:
        if file_present:
            raise ConsoleAccessError(
                f"console credential is configured twice: {CONSOLE_TOKEN_ENV} is set and "
                f"the token file {file_path} exists; keep exactly one")
        token = _validate_bearer_token(env_value, f"${CONSOLE_TOKEN_ENV}")
        source = f"${CONSOLE_TOKEN_ENV}"
    elif file_path:
        token = _read_token_file(file_path)
        source = f"file {file_path}"
    else:
        raise ConsoleAccessError(
            f"no console credential: set {CONSOLE_TOKEN_ENV} (CI secret) or name a private "
            f"token file in console.token_file / {CONSOLE_TOKEN_FILE_ENV}; DevOps provisions "
            "the bearer identity and its grant (docs/CONSOLE-AUTH.md)")
    obs.register_secret(token)
    return token, source


def _validate_console_base(base, auth, transport_kind):
    """The console URL a bearer may be sent to.

    HTTPS with the transport host's normal certificate verification, or plain HTTP to a
    loopback address — which is loopback ON THE TRANSPORT HOST (the SSH jump host in ssh
    mode), i.e. a tunnel or port-forward DevOps owns there. Userinfo, query strings and
    non-loopback HTTP are refused before any request is made, because a credential sent that
    way is a credential disclosed.
    """
    if not base:
        raise ConsoleAccessError(
            f"console base URL is not configured: set {CONSOLE_BASE_ENV} or console.base to "
            "the HTTPS console endpoint (or an explicit loopback HTTP tunnel on the "
            f"{transport_kind} transport host)")
    parts = urllib.parse.urlsplit(base)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ConsoleAccessError(f"console base URL {base!r} must be http(s)://host[:port][/prefix]")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise ConsoleAccessError("console base URL must not carry userinfo; the credential is "
                                 "sent as a bearer header, never in the URL")
    if parts.query or parts.fragment:
        raise ConsoleAccessError("console base URL must not carry a query string or fragment")
    try:
        parts.port
    except ValueError as e:
        raise ConsoleAccessError(f"console base URL has an invalid port: {e}") from e
    if auth == "bearer" and parts.scheme == "http" and not _is_loopback_host(parts.hostname):
        raise ConsoleAccessError(
            f"console base URL {base!r} is plain HTTP to a non-loopback host; a bearer "
            "credential is only sent over HTTPS, or over HTTP to a loopback address on the "
            f"{transport_kind} transport host")
    return base.rstrip("/")


class Console:
    """Typed access to the Phorvex console API over whatever transport is configured.

    Two modes. `http` sends real HTTP requests with curl from the transport host to
    `console.base`, and with `auth: bearer` (the default) carries the console credential the
    deployed verifier authenticates. `kubectl-proxy` reaches the in-cluster Service through
    the API server; it can carry NO console credential — the API server authenticates the
    kubectl user to itself, not to the console — so it stays only as an anonymous
    compatibility path, and its 401 says so rather than "did not become ready".

    The `lens` is a presentation hint the console may use to narrow a view. It authenticates
    nobody and authorizes nothing; the verified identity's server-side grant does.
    """

    def __init__(self, transport, cfg):
        self.t = transport
        self.lens = cfg.get("lens", "operator")
        self.mode = os.environ.get(CONSOLE_MODE_ENV) or cfg.get("mode", "http")
        if self.mode not in ("http", "kubectl-proxy"):
            raise ConsoleAccessError(f"console.mode must be http or kubectl-proxy, not {self.mode!r}")
        auth = os.environ.get(CONSOLE_AUTH_ENV) or cfg.get("auth")
        svc = cfg.get("service", {})
        ns = svc.get("namespace", "phorvex-system")
        name = svc.get("name", "phorvex-console")
        port = svc.get("port", 80)
        self.proxy = f"/api/v1/namespaces/{ns}/services/{name}:{port}/proxy"
        self.token = None
        self.token_source = None
        self.ca_file = None
        self.base = ""
        if self.mode == "kubectl-proxy":
            if auth not in (None, "none"):
                raise ConsoleAccessError(
                    "console.auth=bearer cannot be combined with mode=kubectl-proxy: `kubectl "
                    "get --raw` carries the kubeconfig identity to the API server and no "
                    "console credential; use mode=http with an HTTPS or loopback base URL")
            self.auth = "none"
            return
        self.auth = auth or "bearer"
        if self.auth not in ("bearer", "none"):
            raise ConsoleAccessError(f"console.auth must be bearer or none, not {self.auth!r}")
        transport_kind = getattr(transport, "kind", "local")
        self.base = _validate_console_base(
            os.environ.get(CONSOLE_BASE_ENV) or cfg.get("base"), self.auth, transport_kind)
        self.ca_file = os.environ.get(CONSOLE_CA_FILE_ENV) or cfg.get("ca_file")
        if self.auth == "bearer":
            self.token, self.token_source = _console_token(cfg)

    def describe(self):
        if self.mode == "kubectl-proxy":
            return f"kubectl-proxy {self.proxy} (no console credential)"
        if self.auth == "bearer":
            return f"{self.base} (bearer from {self.token_source})"
        return f"{self.base} (anonymous; auth=none)"

    # ── HTTP mode ────────────────────────────────────────────────────────────

    def _curl(self, seconds, *extra):
        """curl argv for one console request. Never `-k`, never `-L` past zero redirects.

        `-L --max-redirs 0` makes any redirect an explicit failure (exit 47) after exactly one
        request: the credential is never re-sent to a `Location` the console did not serve.
        `-K -` reads the credential header from stdin; nothing secret is in this argv.
        """
        argv = ["curl", "-sS", "-m", str(max(1, int(seconds))), "-L", "--max-redirs", "0"]
        if self.ca_file and self.base.startswith("https://"):
            argv += ["--cacert", self.ca_file]
        if self.auth == "bearer":
            argv += ["-K", "-"]
        argv += ["-H", "X-Phorvex-Lens: " + self.lens]
        argv += list(extra)
        return shlex.join(argv)

    def _stdin(self):
        """The curl configuration carrying the bearer header, or nothing."""
        if self.auth != "bearer":
            return None
        return 'header = "Authorization: Bearer ' + self.token + '"\n'

    def _auth_hint(self):
        if self.auth == "bearer":
            return (f"the bearer credential from {self.token_source} was not accepted (absent, "
                    "malformed, expired, or from an issuer/audience this console does not verify)")
        return ("this client sent no console credential (console.auth=none); the lens is a "
                "presentation hint, not an authorization — configure auth=bearer")

    @staticmethod
    def _server_error(body):
        """The console's `error` field (or the body), redacted BEFORE it is shortened."""
        if not body:
            return "no body"
        try:
            doc = json.loads(body)
        except (json.JSONDecodeError, TypeError):
            doc = None
        if isinstance(doc, dict) and isinstance(doc.get("error"), str):
            return obs.redact(doc["error"], limit=200)
        return obs.redact(body.strip(), limit=200)

    def _http(self, what, seconds, timeout, *extra):
        """One curl request; returns (status, body). Raises on anything but an HTTP answer."""
        cmd = self._curl(seconds, "-w", "%{http_code}", *extra)
        rc, out, err = self.t.run(cmd, timeout=timeout, stdin=self._stdin())
        detail = _tail(err, 300) or "no output"
        if rc == CURL_TOO_MANY_REDIRECTS:
            raise ConsoleAccessError(
                f"{what}: the console endpoint answered with a redirect; this client never "
                "follows one with a credential. Point console.base at an endpoint that reaches "
                f"the console verifier directly (a login redirect means it does not): {detail}")
        if rc in CURL_TLS_EXITS:
            raise ConsoleAccessError(
                f"{what}: TLS to {self.base} could not be verified on the transport host; "
                "provide the CA bundle with console.ca_file / "
                f"{CONSOLE_CA_FILE_ENV} rather than disabling verification: {detail}")
        if rc != 0:
            raise TransportError(f"{what} failed (rc={rc}): {detail}")
        status, body = out[-3:], out[:-3]
        if not status.isdigit():
            raise TransportError(f"{what} returned no HTTP status: {obs.redact(out, limit=200)!r}")
        status = int(status)
        if status == 401:
            raise ConsoleAccessError(
                f"{what}: console rejected the request as unauthenticated (HTTP 401: "
                f"{self._server_error(body)}); {self._auth_hint()}")
        if status == 403:
            raise ConsoleAccessError(
                f"{what}: console authenticated the caller but refused it (HTTP 403: "
                f"{self._server_error(body)}); the verified subject needs an explicit console "
                "grant covering this route's role, tenant and target (docs/CONSOLE-AUTH.md)")
        if 300 <= status < 400:
            raise ConsoleAccessError(
                f"{what}: console endpoint answered HTTP {status} (a redirect); the credential "
                "is never forwarded — configure a base URL that reaches the verifier directly")
        return status, body

    # ── kubectl-proxy mode ───────────────────────────────────────────────────

    def _kubectl_raw(self, cmd, what, timeout):
        rc, out, err = self.t.run(cmd, timeout=timeout)
        text = (err or "") + (out if rc != 0 else "")
        if rc != 0 and ("must be logged in" in text or "Unauthorized" in text or "401" in text):
            raise ConsoleAccessError(
                f"{what}: console rejected the request as unauthenticated (HTTP 401 through "
                "kubectl-proxy): the API-server proxy authenticates the kubectl user to the API "
                "server and carries NO console credential. Configure console.mode=http with an "
                "HTTPS or loopback base URL and a bearer credential (docs/CONSOLE-AUTH.md)")
        if rc != 0 and ("Forbidden" in text or "403" in text):
            raise ConsoleAccessError(
                f"{what}: refused (HTTP 403 through kubectl-proxy): either the kubectl user may "
                "not reach services/proxy, or the console refused this caller; the proxy path "
                f"carries no console credential: {_tail(text, 300)}")
        if rc != 0 and not out:
            raise TransportError(f"{what} failed (rc={rc}): {_tail(err, 300) or 'no output'}")
        return out

    def _lens_q(self, path):
        return path + ("&" if "?" in path else "?") + "lens=" + self.lens

    # ── requests ─────────────────────────────────────────────────────────────

    def get_json(self, path, timeout=20):
        what = f"GET {path}"
        if self.mode == "kubectl-proxy":
            out = self._kubectl_raw(
                f"kubectl get --raw {shlex.quote(self.proxy + self._lens_q(path))}", what, timeout)
        else:
            status, out = self._http(what, timeout - 2, timeout, self.base + path)
            if status != 200:
                raise TransportError(f"{what} returned HTTP {status}: {self._server_error(out)}")
        try:
            return json.loads(out)
        except json.JSONDecodeError as e:
            raise TransportError(f"{what} did not return JSON: {obs.redact(out, limit=200)!r}") from e

    def wait_preflight(self, timeout=60):
        """Read-only readiness wait before capture/attack; never retry a POST.

        A rolling console can briefly have no Service endpoints. Both health and
        version must answer within one bounded window; permanent failures remain
        transport failures and never produce a passing E2E verdict. A rejected or
        misconfigured credential is not "not ready yet": it stops the wait at once.
        """
        deadline = time.monotonic() + timeout
        last_error = "console did not become ready"
        while deadline - time.monotonic() > 2:
            try:
                health = self.get_json("/api/health", timeout=min(10, deadline - time.monotonic()))
                if not isinstance(health, dict) or health.get("ok") is not True:
                    raise TransportError("console health did not return ok=true")
                remaining = deadline - time.monotonic()
                if remaining <= 2:
                    break
                version = self.get_json("/api/version", timeout=min(10, remaining))
                if not isinstance(version, dict) or not version.get("operator"):
                    raise TransportError("console did not report an operator version")
                return health, version
            except ConsoleAccessError:
                raise
            except TransportError as e:
                last_error = str(e)
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(2, remaining))
        raise TransportError(f"console readiness deadline ({timeout}s): {last_error}")

    def post_json(self, path, body, timeout=40):
        """One POST, issued exactly once. A failed POST is reported, never retried here.

        A 2xx JSON body is the console's answer. A 401/403 is a credential/grant failure and
        raises. Any other error status with a JSON object body is returned with `ok` forced
        false and the status attached, so a "503: no attackable pod" stays a reportable
        stage failure — but can never read as a fired attack or an acknowledged clear.
        """
        what = f"POST {path}"
        if self.mode == "kubectl-proxy":
            # `kubectl create --raw` issues the POST; the body is piped in on stdin. The
            # console decodes JSON from the request body regardless of Content-Type.
            out = self._kubectl_raw(
                f"printf %s {shlex.quote(json.dumps(body))} "
                f"| kubectl create --raw {shlex.quote(self.proxy + self._lens_q(path))} -f -",
                what, timeout)
            try:
                return json.loads(out)
            except json.JSONDecodeError:
                return {"_raw": out}
        status, out = self._http(
            what, timeout - 5, timeout, "-X", "POST", "-H", "Content-Type: application/json",
            "-d", json.dumps(body), self.base + path)
        try:
            doc = json.loads(out)
        except json.JSONDecodeError:
            doc = None
        if 200 <= status < 300:
            return doc if doc is not None else {"_raw": out}
        if isinstance(doc, dict):
            doc["ok"] = False
            doc["_httpStatus"] = status
            doc.setdefault("error", f"HTTP {status}")
            return doc
        raise TransportError(f"{what} returned HTTP {status}: {self._server_error(out)}")

    def stream_decisions(self, seconds, limits, scope=None, on_connected=None):
        """Capture the audit SSE stream for a bounded window.

        The stream replays the audit file and then tails it, so a short window still
        yields the recent decision history. The result carries its own completeness: a
        capped, truncated or mid-frame stream comes back with `complete=False` and the
        caller must not treat it as a shorter successful observation.

        Readiness is the console's own heartbeat on a successful stream. `-f` turns a 4xx/5xx
        into a failed command with no body, so a JSON `401` can never reach the framer, and
        a stimulus callback can never fire before an authenticated stream is open.
        """
        # The callback may perform two bounded 30s detector calls (or one console
        # POST). Keep the remote process bounded, but allow the observation window
        # to begin AFTER the callback. capture_live terminates it at that deadline.
        remote_seconds = seconds + 90 if on_connected else seconds
        replay = "&tail=1" if on_connected else ""
        # No `head -c` any more: truncating the stream remotely produces a partial final
        # frame that the reader cannot tell from a decision it lost. The byte budget is
        # enforced locally by StreamCapture, where hitting it is a reportable failure.
        if self.mode == "kubectl-proxy":
            cmd = (f"timeout {remote_seconds} kubectl get --raw "
                   f"{shlex.quote(self.proxy + '/api/live?lens=' + self.lens + replay)}")
            return self.t.capture_live(cmd, seconds, limits, scope, on_connected)
        cmd = self._curl(remote_seconds, "-N", "-f",
                         self.base + "/api/live?lens=" + self.lens + replay)
        try:
            got = self.t.capture_live(cmd, seconds, limits, scope, on_connected,
                                      stdin=self._stdin())
        except TransportError as e:
            self._raise_if_stream_rejected(str(e))
            raise
        if not got.complete:
            self._raise_if_stream_rejected(got.reason or "")
        return got

    def _raise_if_stream_rejected(self, text):
        """`curl -f` reports a refused stream as `(22) ... returned error: 401`; name it."""
        match = re.search(r"returned error: (\d{3})", text)
        if not match:
            return
        status = int(match.group(1))
        if status == 401:
            raise ConsoleAccessError(
                "GET /api/live: console rejected the stream as unauthenticated (HTTP 401); "
                + self._auth_hint())
        if status == 403:
            raise ConsoleAccessError(
                "GET /api/live: console authenticated the caller but refused the stream (HTTP "
                "403); the verified subject needs a grant covering the audit's tenants")


class Metrics:
    """The audit writer's own Prometheus endpoint.

    Some operator state never reaches the audit record — most importantly the global kill
    switch, which suppresses actuation while leaving `dryRun` false. Reading it here is how
    the pipeline tells a deliberate decision-only mirror apart from a broken actuator,
    instead of inferring it from an absence.

    A failed scrape and a scrape with no such gauge are different facts, and A06 changes its
    verdict between them, so this returns an Observation rather than an empty dict.
    """

    def __init__(self, transport, cfg):
        self.t = transport
        cfg = cfg or {}
        self.url = cfg.get("metrics_url")
        # The in-cluster operator publishes metrics on a container port with no Service and
        # no ingress, so there is no URL the jump host can curl. Rather than expose an
        # operator's internals to the internet just to read one gauge, go through the API
        # server's pod proxy — the same credentials kubectl already uses for ground truth.
        self.proxy = cfg.get("kubectl_pod_proxy")

    def describe(self):
        if self.proxy:
            p = self.proxy
            return f"kubectl proxy {p['namespace']}/{p['selector']}:{p['port']}{p.get('path', '/metrics')}"
        return self.url or "—"

    def scrape(self, timeout=15):
        if self.proxy:
            return self._scrape_proxy(timeout)
        if not self.url:
            return obs.Observation.unavailable(
                "no audit_writer.metrics_url or kubectl_pod_proxy is configured",
                source="metrics", reason_code=obs.NOT_FOUND)
        rc, out, err = self.t.run(
            f"curl -s -m {timeout - 3} {shlex.quote(self.url)}", timeout=timeout)
        return obs.classify(rc, out, err, source="metrics scrape", parser=self._parse)

    def _scrape_proxy(self, timeout):
        """Read the operator's own metrics through the API server's pod proxy.

        The pod name is resolved at scrape time rather than configured: the operator is
        recreated on every deploy, and a stale pod name would return an empty scrape that
        looks exactly like "the gauge is absent" — which is the one thing check A06 must
        never get wrong.
        """
        p = self.proxy
        ns, sel, port = p["namespace"], p["selector"], int(p["port"])
        path = p.get("path", "/metrics")
        cmd = (
            f"POD=$(kubectl -n {shlex.quote(ns)} get pod -l {shlex.quote(sel)} "
            f"--field-selector=status.phase=Running "
            f"-o jsonpath='{{.items[0].metadata.name}}') && "
            f"[ -n \"$POD\" ] && "
            f"kubectl get --raw \"/api/v1/namespaces/{ns}/pods/$POD:{port}/proxy{path}\""
        )
        rc, out, err = self.t.run(cmd, timeout=timeout)
        return obs.classify(rc, out, err, source="metrics pod proxy", parser=self._parse)

    @staticmethod
    def _parse(out):
        vals = {}
        for line in out.splitlines():
            if line.startswith("#") or " " not in line:
                continue
            name, _, val = line.rpartition(" ")
            try:
                vals[name.strip()] = float(val)
            except ValueError:
                continue
        return vals


# ─────────────────────────── selector evaluation ───────────────────────────

def selector_matches(selector, labels):
    """Full LabelSelector semantics, matchExpressions included.

    Reading only matchLabels made every expression-based policy look like it selected
    nothing, which silently downgraded a real quarantine to "the policy does not select
    the pod" — and, in the other direction, let an expression-based *allow* policy sit
    unnoticed next to a deny-all.
    """
    if selector is None:
        return False
    labels = labels or {}
    for key, want in (selector.get("matchLabels") or {}).items():
        if labels.get(key) != want:
            return False
    for expression in selector.get("matchExpressions") or []:
        key = expression.get("key")
        operator = expression.get("operator")
        values = expression.get("values") or []
        present = key in labels
        if operator == "In" and (not present or labels[key] not in values):
            return False
        if operator == "NotIn" and present and labels[key] in values:
            return False
        if operator == "Exists" and not present:
            return False
        if operator == "DoesNotExist" and present:
            return False
        if operator not in ("In", "NotIn", "Exists", "DoesNotExist"):
            raise ValueError(f"unknown label selector operator {operator!r}")
    return True


def _pod_identity(item, namespace):
    """The identity a later observation can be compared against.

    Namespace + Pod UID + controller UID. A name alone is not an identity: a Deployment
    recreates the same name with a new UID, and a name that reappears under a different
    controller is a different workload entirely.
    """
    meta = item.get("metadata") or {}
    status = item.get("status") or {}
    conditions = status.get("conditions") or []
    ready = next((c.get("status") == "True" for c in conditions if c.get("type") == "Ready"), None)
    owner = next((r for r in meta.get("ownerReferences") or [] if r.get("controller") is True), None)
    terminated = [
        {"container": c.get("name"), "reason": (c.get("state", {}).get("terminated") or {}).get("reason"),
         "exitCode": (c.get("state", {}).get("terminated") or {}).get("exitCode"),
         "finishedAt": (c.get("state", {}).get("terminated") or {}).get("finishedAt")}
        for c in status.get("containerStatuses") or []
        if (c.get("state") or {}).get("terminated")
    ]
    uid = meta.get("uid")
    if not uid:
        raise ValueError("pod inventory item carries no UID")
    return {
        "namespace": meta.get("namespace") or namespace,
        "name": meta.get("name"),
        "uid": uid,
        "ownerKind": (owner or {}).get("kind"),
        "ownerName": (owner or {}).get("name"),
        "ownerUID": (owner or {}).get("uid"),
        "phase": status.get("phase", "Unknown"),
        # None, not False: "there is no Ready condition yet" is not "it reported not ready".
        "ready": ready,
        "terminating": bool(meta.get("deletionTimestamp")),
        "deletionTimestamp": meta.get("deletionTimestamp"),
        "creationTimestamp": meta.get("creationTimestamp"),
        "labels": meta.get("labels") or {},
        "terminated": terminated,
    }


class Cluster:
    """kubectl ground truth — deliberately independent of anything Phorvex reports."""

    def __init__(self, transport):
        self.t = transport

    def kubectl(self, args, timeout=25):
        rc, out, err = self.t.run("kubectl " + args, timeout=timeout)
        return rc, out.strip(), err.strip()

    def observe(self, args, source, parser=None, timeout=25, absent_is_ok=False):
        """One kubectl read, classified. This is the only way anything here reads state."""
        rc, out, err = self.kubectl(args, timeout=timeout)
        return obs.classify(rc, out, err, source=source, parser=parser,
                            absent_is_ok=absent_is_ok)

    def pod_uids(self, namespace, selector=None):
        """Observed pod identities in one namespace, keyed by name.

        The value is a mapping only for convenience: every comparison downstream is on the
        UID and the controller UID inside it, because a Deployment happily reuses a name.
        """
        sel = f"-l {shlex.quote(selector)} " if selector else ""

        def parse(out):
            doc = json.loads(out)
            items = doc.get("items")
            if not isinstance(items, list):
                raise ValueError("pod list carries no items array")
            return {item["metadata"]["name"]: _pod_identity(item, namespace) for item in items}

        return self.observe(
            f"-n {shlex.quote(namespace)} get pod {sel}-o json",
            source=f"pod inventory {namespace}", parser=parse)

    def controller_pods(self, namespace="phorvex-system", deployments=None):
        """Resolve expected Deployments -> ReplicaSets -> Pods by controller UID.

        Namespace membership and labels alone are not controller identity. Synthetic
        deployment entries preserve missing/unknown observations for the health gate.
        The shipped defaults follow the stack's Phorvex and Phoenix Deployment names;
        other releases must explicitly configure controller_deployments.
        """
        expected = deployments if deployments is not None else [
            "phorvex-phorvex", "operator-controller-manager"]
        if (not isinstance(expected, list) or not expected or
                any(not isinstance(name, str) or not name.strip() for name in expected) or
                len(set(expected)) != len(expected)):
            raise TransportError("controller_deployments must be a nonempty list of unique Deployment names")

        def unavailable(phase, reason):
            return {f"deployment/{name}": {"phase": phase, "restarts": 0,
                    "ready": False, "reason": reason} for name in expected}

        read = self.observe(
            f"-n {shlex.quote(namespace)} get deployments.apps,replicasets.apps,pods -o json",
            source=f"controller inventory {namespace}")
        if not read.usable:
            return obs.Observation(read.status,
                                   unavailable("Unknown", "controller inventory could not be read: "
                                               + (read.reason_code or read.status)),
                                   reason=read.reason, reason_code=read.reason_code,
                                   source=read.source)
        try:
            items = json.loads(read.value)["items"]
            if not isinstance(items, list) or any(not isinstance(x, dict) for x in items):
                raise ValueError("invalid inventory")

            def owner(obj, kind):
                return next((r.get("uid") for r in obj.get("metadata", {}).get("ownerReferences", [])
                             if r.get("controller") is True and r.get("kind") == kind), None)

            by_name = {x["metadata"]["name"]: x for x in items if x.get("kind") == "Deployment"}
            pods = {}
            for name in expected:
                deployment = by_name.get(name)
                uid = (deployment or {}).get("metadata", {}).get("uid")
                if not uid:
                    pods[f"deployment/{name}"] = {"phase": "Missing", "restarts": 0,
                        "ready": False, "reason": "expected Deployment not observed"}
                    continue
                replica_sets = {x["metadata"]["uid"] for x in items
                                if x.get("kind") == "ReplicaSet" and owner(x, "Deployment") == uid
                                and x.get("metadata", {}).get("uid")}
                owned = [x for x in items if x.get("kind") == "Pod"
                         and owner(x, "ReplicaSet") in replica_sets]
                if not owned:
                    pods[f"deployment/{name}"] = {"phase": "Missing", "restarts": 0,
                        "ready": False, "reason": "expected Deployment has no owned Pods"}
                for pod in owned:
                    status = pod.get("status", {})
                    containers = status.get("containerStatuses", [])
                    if status.get("phase") == "Running":
                        declared = {c["name"] for c in pod.get("spec", {}).get("containers", [])}
                        observed = {c.get("name") for c in containers if "restartCount" in c}
                        if not declared or not declared.issubset(observed):
                            raise ValueError("missing running container restart evidence")
                    restarts = [c.get("restartCount", 0) for c in containers + status.get("initContainerStatuses", [])]
                    if any(type(count) is not int or count < 0 for count in restarts):
                        raise ValueError("invalid restart count")
                    pods[pod["metadata"]["name"]] = {
                        "phase": status.get("phase", "Unknown"),
                        "restarts": max(restarts, default=0),
                        "ready": any(c.get("type") == "Ready" and c.get("status") == "True"
                                     for c in status.get("conditions", [])),
                        "deployment": name,
                        "uid": pod.get("metadata", {}).get("uid"),
                        "ownerUID": owner(pod, "ReplicaSet"),
                    }
            return obs.Observation.observed(pods, source=read.source)
        except (ValueError, KeyError, TypeError, AttributeError) as error:
            # The synthetic "Unknown" entries are kept as the value so P05 still sees an
            # unhealthy controller set rather than an empty one it could read as "nothing
            # to check"; the status says why they are synthetic.
            return obs.Observation(
                obs.MALFORMED, unavailable("Unknown", "controller inventory was malformed"),
                reason=f"controller inventory was malformed: {type(error).__name__}: {error}",
                reason_code=obs.INVALID, source=read.source)

    def pod_is_stateful(self, namespace, pod):
        """Mirror of ingest/kube.go:406 — StatefulSet-owned, or mounts a PVC, or a Job."""
        def parse(out):
            owner, _, claims = out.strip("'").partition("|")
            return owner in ("StatefulSet", "Job") or bool(claims.strip())

        return self.observe(
            f"-n {shlex.quote(namespace)} get pod {shlex.quote(pod)} "
            "-o jsonpath='{.metadata.ownerReferences[0].kind}|"
            "{range .spec.volumes[*]}{.persistentVolumeClaim.claimName}{\" \"}{end}'",
            source=f"stateful probe {namespace}/{pod}", parser=parse)

    def network_policies(self, namespace):
        """Every NetworkPolicy in the namespace, because isolation is an additive property."""
        def parse(out):
            items = json.loads(out).get("items")
            if not isinstance(items, list):
                raise ValueError("networkpolicy list carries no items array")
            return items

        return self.observe(f"-n {shlex.quote(namespace)} get networkpolicy -o json",
                            source=f"networkpolicy inventory {namespace}", parser=parse)

    def quarantine_state(self, namespace, pod, expect_uid=None):
        """Read the configuration behind a claimed quarantine — and only that.

        A NetworkPolicy that selects the pod is *configuration* evidence. It is not proof
        that packets stop: another policy in the namespace may additively allow the same
        traffic, and whether the CNI enforces policy at all is outside what kubectl can
        answer. Both facts travel with the result so a verdict cannot overstate them.
        """
        policy_name = f"{namespace}-{pod}-policy"
        pod_read = self.observe(
            f"-n {shlex.quote(namespace)} get pod {shlex.quote(pod)} -o json",
            source=f"pod {namespace}/{pod}", parser=json.loads, absent_is_ok=True)
        if not pod_read.usable:
            return pod_read
        policies = self.network_policies(namespace)
        if not policies.usable:
            return policies

        pod_doc = pod_read.value
        pod_uid = ((pod_doc or {}).get("metadata") or {}).get("uid")
        labels = ((pod_doc or {}).get("metadata") or {}).get("labels") or {}
        by_name = {(p.get("metadata") or {}).get("name"): p for p in policies.value}
        policy = by_name.get(policy_name)

        selecting, allowing = [], []
        try:
            for name, doc in by_name.items():
                spec = doc.get("spec") or {}
                if not selector_matches(spec.get("podSelector") or {}, labels):
                    continue
                selecting.append(name)
                if (spec.get("ingress") or []) or (spec.get("egress") or []):
                    allowing.append(name)
        except ValueError as error:
            return obs.Observation.malformed(
                f"a NetworkPolicy selector could not be evaluated: {error}",
                source=f"quarantine {namespace}/{pod}")

        spec = (policy or {}).get("spec") or {}
        policy_types = set(spec.get("policyTypes") or [])
        deny_all = bool(policy) and not (spec.get("ingress") or []) and not (spec.get("egress") or [])
        selects = policy_name in selecting
        identity_ok = expect_uid is None or (pod_uid is not None and pod_uid == expect_uid)
        active = bool(policy) and selects and deny_all and {"Ingress", "Egress"}.issubset(policy_types)

        state = {
            "active": active and identity_ok,
            "policy": policy_name,
            "policyPresent": bool(policy),
            "podUID": pod_uid,
            "identityMatches": identity_ok,
            "selects": selects,
            "denyAll": deny_all,
            "policyTypes": sorted(policy_types),
            "selectingPolicies": sorted(selecting),
            "additiveAllowPolicies": sorted(n for n in allowing if n != policy_name),
            # Nothing here probes a packet. Say so, in the record, every time.
            "effectiveBlockingProven": False,
            "evidence": (
                f"policy={'present' if policy else '<missing>'}; selectsPod={str(selects).lower()}; "
                f"denyAll={str(deny_all).lower()}; "
                f"policyTypes={','.join(sorted(policy_types)) or '<missing>'}; "
                f"podUID={(pod_uid or '<missing>')[:8]}; "
                f"identityMatches={str(identity_ok).lower()}; "
                f"additiveAllow={','.join(sorted(n for n in allowing if n != policy_name)) or 'none'}"),
        }
        if pod_doc is None:
            return obs.Observation.partial(
                state, "the target Pod no longer exists, so no policy can select it",
                reason_code=obs.NOT_FOUND, source=f"quarantine {namespace}/{pod}")
        return obs.Observation.observed(state, source=f"quarantine {namespace}/{pod}")

    def container_log(self, namespace, pod, pod_uid, since_epoch, pattern, tail=400,
                      container=None):
        """Command-specific, time-bounded, instance-bound log evidence.

        Three bindings, all required. `--since-time` from the action's own start, so a line
        written before the command cannot answer for it. A compiled command-specific
        pattern, because "lora" appears in a vLLM startup banner. And a re-read of the Pod
        UID, because `kubectl logs <name>` after a rotation reads a *different* container's
        log under the same name.
        """
        identity = self.observe(
            f"-n {shlex.quote(namespace)} get pod {shlex.quote(pod)} -o jsonpath='{{.metadata.uid}}'",
            source=f"log identity {namespace}/{pod}", absent_is_ok=True)
        if not identity.usable:
            return identity
        observed_uid = (identity.value or "").strip().strip("'")
        if pod_uid and observed_uid != pod_uid:
            return obs.Observation.unavailable(
                f"the pod under this name is no longer the observed instance "
                f"({(observed_uid or 'absent')[:8]} != {pod_uid[:8]}), so its log cannot "
                f"answer for the action",
                source=f"container log {namespace}/{pod}", reason_code=obs.NOT_FOUND)

        c = f"-c {shlex.quote(container)} " if container else ""
        read = self.observe(
            f"-n {shlex.quote(namespace)} logs {shlex.quote(pod)} {c}"
            f"--since-time={shlex.quote(rfc3339(since_epoch))} --tail={int(tail)}",
            source=f"container log {namespace}/{pod}", timeout=35)
        if not read.usable:
            return read

        # The UID was checked before the read; a rotation between the two would have handed
        # us the successor's log under the same name. Check it again on the way out, so the
        # window between the two reads cannot silently change whose log this is.
        after = self.observe(
            f"-n {shlex.quote(namespace)} get pod {shlex.quote(pod)} -o jsonpath='{{.metadata.uid}}'",
            source=f"log identity {namespace}/{pod}", absent_is_ok=True)
        if not after.usable:
            return after
        settled_uid = (after.value or "").strip().strip("'")
        if settled_uid != observed_uid:
            return obs.Observation.unavailable(
                f"the pod was replaced while its log was being read "
                f"({observed_uid[:8]} → {(settled_uid or 'absent')[:8]})",
                source=f"container log {namespace}/{pod}", reason_code=obs.NOT_FOUND)

        try:
            expression = re.compile(pattern)
        except re.error as error:
            return obs.Observation.malformed(f"invalid log evidence pattern: {error}",
                                             source=f"container log {namespace}/{pod}")
        lines = (read.value or "").splitlines()
        matches = [line for line in lines if expression.search(line)]
        # `--tail` caps how far back the read reached. A read that filled its cap may have
        # left earlier lines unseen, so an ABSENT match over it proves nothing — which is a
        # different fact from an absent match over the whole window.
        truncated = len(lines) >= int(tail)
        value = {"matches": matches, "podUID": observed_uid, "sinceTime": rfc3339(since_epoch),
                 "pattern": pattern, "linesRead": len(lines), "tail": int(tail),
                 "truncated": truncated}
        if truncated:
            return obs.Observation.partial(
                value, f"the log read filled its {int(tail)}-line tail cap, so earlier lines "
                       f"in the window were not observed",
                reason_code=obs.TRUNCATED, source=read.source)
        return obs.Observation.observed(value, source=read.source)

    def phorvex_policy(self, namespace):
        """The governing PhorvexPolicy, with the identity a per-owner budget belongs to.

        `items[0]` used to be taken blind. Two policies in one namespace is not a detail:
        without knowing which one governs a decision there is no owner to hold a budget
        against, so ambiguity is reported rather than resolved by list order.
        """
        def parse(out):
            items = json.loads(out).get("items")
            if not isinstance(items, list):
                raise ValueError("phorvexpolicy list carries no items array")
            return items

        read = self.observe(f"-n {shlex.quote(namespace)} get phorvexpolicy -o json",
                            source=f"phorvexpolicy {namespace}", parser=parse)
        if not read.usable:
            return read
        items = read.value
        if not items:
            return obs.Observation(obs.OK, None, reason="no PhorvexPolicy governs this namespace",
                                   reason_code=obs.NOT_FOUND, source=read.source)
        if len(items) > 1:
            return obs.Observation.partial(
                None, f"{len(items)} PhorvexPolicies govern {namespace}; a per-owner budget "
                      f"cannot be attributed to one of them",
                reason_code=obs.INVALID, source=read.source)
        item = items[0]
        meta, spec = item.get("metadata") or {}, item.get("spec") or {}
        budget = (spec.get("budget") or {}).get("maxMovesPerTick")
        return obs.Observation.observed({
            "uid": meta.get("uid"),
            "name": meta.get("name"),
            "namespace": meta.get("namespace") or namespace,
            "maxMovesPerTick": budget if isinstance(budget, int) and not isinstance(budget, bool) else None,
            "budgetDeclared": budget is not None,
            "mode": spec.get("mode"),
            "dryRun": spec.get("dryRun"),
        }, source=read.source)


def capture_limits(cfg):
    """Build the capture bounds from config, with the record cap made explicit."""
    return CaptureLimits(
        max_total_bytes=int(cfg.get("max_bytes", 16000000)),
        max_records=int(cfg.get("max_records", 20000)),
        max_frame_bytes=int(cfg.get("max_frame_bytes", 1 << 20)))


def capture_scope(cfg, target):
    """Declare what a run's captures cover.

    A run with a target scopes to that namespace: the pipeline only reads *that*
    namespace's policy, baseline and pods, so a record from elsewhere is traffic it cannot
    verify anything about. An untargeted observe run makes the cluster-wide claim, and the
    run document says which of the two it was.
    """
    declared = cfg.get("namespaces", "target")
    if declared is None:
        return CaptureScope(None, note="explicitly configured as cluster-wide")
    if isinstance(declared, list):
        return CaptureScope(declared, note="explicitly configured namespace list")
    if declared != "target":
        raise TransportError("capture.namespaces must be null, a list, or \"target\"")
    if not target:
        return CaptureScope(None, note="no target: cluster-wide observation")
    return CaptureScope([target["namespace"]],
                        note="scoped to the target namespace the run can verify")


__all__ = ["Cluster", "Console", "Metrics", "Transport", "TransportError",
           "CaptureLimits", "CaptureScope", "capture_limits", "capture_scope",
           "selector_matches", "rfc3339"]
