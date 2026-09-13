"""A local console stand-in with a REAL bearer verifier, for the transport regressions.

The deployed console (internal/console, M-136) authenticates `Authorization: Bearer <jwt>`
against an issuer, audience and key set, then authorizes the verified subject against an
explicit grant table. This fixture reproduces that contract on a loopback HTTP or TLS port
so the pipeline's `Console` -> `Transport` -> curl path can be driven for real:

  - tokens are RS256 JWTs signed with a key generated for this process; the verifier checks
    the signature, `iss`, `aud`, `sub`, `exp` and `nbf`, and refuses `alg=none`/HMAC;
  - identity never comes from a lens header, a query string or the request body;
  - a subject with no grant is 403 with the console's own message; a control without the
    operator role, or a tenant/target outside the grant, is 403; anything unauthenticated
    is 401 with `WWW-Authenticate`;
  - `/api/health` is public, `/api/live` is SSE with the console's `: connected` heartbeat.

Every request is recorded (method, path, whether and which credential arrived, lens) so a
test can assert exactly what reached the server — one POST, no retry, no forwarded token.

The real verifier's contract is anchored separately by the Go test in internal/console that
drives this same Python client against the actual `Authenticator`; this fixture exists so
the Python suite can exercise every client branch without a cluster or a Go toolchain.
"""

import base64
import hashlib
import json
import math
import secrets
import shutil
import ssl
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ISSUER = "https://idp.fixture.test"
AUDIENCE = "phorvex-console"
KID = "fixture-key-1"
NO_GRANT = ("no authorization grant for this identity; a console administrator must bind "
            "this subject to a role and tenant scope")
CONTROL_ROLE = "this control requires the operator role; investor and owner grants are read-only"
READ_ROLE = "this data requires an investor or operator grant"


# ─────────────────────────── RS256, in the standard library ───────────────────────────

def _probable_prime(n, rounds=24):
    if n < 4:
        return n in (2, 3)
    if n % 2 == 0:
        return False
    for small in (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % small == 0:
            return n == small
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    rng = secrets.SystemRandom()
    for _ in range(rounds):
        a = rng.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _random_prime(bits):
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _probable_prime(candidate):
            return candidate


class RSAKey:
    """A signing key generated here and never persisted. 1024 bits keeps the fixture fast;
    the client never inspects key size and the real verifier's own tests use 2048."""

    def __init__(self, bits=1024, kid=KID):
        e = 65537
        while True:
            p, q = _random_prime(bits // 2), _random_prime(bits // 2)
            lam = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
            if p != q and math.gcd(e, lam) == 1:
                break
        self.n, self.e, self.d, self.kid = p * q, e, pow(e, -1, lam), kid
        self.size = (self.n.bit_length() + 7) // 8

    _DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")

    def _encoded_message(self, data):
        t = self._DIGEST_INFO + hashlib.sha256(data).digest()
        return int.from_bytes(b"\x00\x01" + b"\xff" * (self.size - 3 - len(t)) + b"\x00" + t, "big")

    def sign(self, data):
        return pow(self._encoded_message(data), self.d, self.n).to_bytes(self.size, "big")

    def verify(self, data, signature):
        if len(signature) != self.size:
            return False
        return pow(int.from_bytes(signature, "big"), self.e, self.n) == self._encoded_message(data)

    def jwk(self):
        return {"kty": "RSA", "kid": self.kid, "use": "sig", "alg": "RS256",
                "n": _b64u(self.n.to_bytes(self.size, "big")),
                "e": _b64u(self.e.to_bytes(3, "big"))}


def _b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64u_decode(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def mint(key, subject, issuer=ISSUER, audience=AUDIENCE, ttl=300, now=None, nbf=None,
         alg="RS256", kid=None, omit_exp=False):
    """A signed bearer token for `subject`; every knob exists so a test can bend ONE field."""
    now = time.time() if now is None else now
    claims = {"iss": issuer, "sub": subject, "aud": audience, "iat": int(now)}
    if not omit_exp:
        claims["exp"] = int(now + ttl)
    if nbf is not None:
        claims["nbf"] = int(nbf)
    header = {"alg": alg, "typ": "JWT", "kid": kid or key.kid}
    signing = _b64u(json.dumps(header, separators=(",", ":")).encode()) + "." + \
        _b64u(json.dumps(claims, separators=(",", ":")).encode())
    if alg == "none":
        return signing + "."
    return signing + "." + _b64u(key.sign(signing.encode()))


class Verifier:
    """The bearer contract: signature over the literal header.payload, then the claims."""

    def __init__(self, keys, issuer=ISSUER, audience=AUDIENCE, leeway=5):
        self.keys = {k.kid: k for k in keys}
        self.issuer, self.audience, self.leeway = issuer, audience, leeway

    def verify(self, token, now=None):
        """The verified (issuer, subject) or None. Nothing about WHY is disclosed to the
        caller, exactly as the console answers every failure with one 401."""
        now = time.time() if now is None else now
        parts = token.split(".")
        if len(parts) != 3:
            return None
        try:
            header = json.loads(_b64u_decode(parts[0]))
            claims = json.loads(_b64u_decode(parts[1]))
            signature = _b64u_decode(parts[2])
        except (ValueError, UnicodeDecodeError):
            return None
        if not isinstance(header, dict) or header.get("alg") != "RS256":
            return None
        key = self.keys.get(header.get("kid"))
        if key is None or not key.verify((parts[0] + "." + parts[1]).encode(), signature):
            return None
        if not isinstance(claims, dict) or claims.get("iss") != self.issuer:
            return None
        aud = claims.get("aud")
        if not (aud == self.audience or (isinstance(aud, list) and self.audience in aud)):
            return None
        sub = claims.get("sub")
        if not isinstance(sub, str) or not sub:
            return None
        exp = claims.get("exp")
        if not isinstance(exp, (int, float)) or exp + self.leeway < now:
            return None
        nbf = claims.get("nbf")
        if isinstance(nbf, (int, float)) and nbf - self.leeway > now:
            return None
        return self.issuer, sub


# ─────────────────────────────────── the console ───────────────────────────────────

class Grant:
    def __init__(self, roles, tenants=("*",), targets=("default",)):
        self.roles, self.tenants, self.targets = list(roles), list(tenants), list(targets)

    def allows_tenant(self, tenant):
        return "*" in self.tenants or tenant in self.tenants

    def allows_target(self, target):
        return "*" in self.targets or target in self.targets

    @property
    def can_read(self):
        return bool({"investor", "operator"} & set(self.roles))

    @property
    def can_operate(self):
        return "operator" in self.roles


class FixtureConsole:
    """One loopback console. `grants` maps subject -> Grant. `records` is what /api/live
    replays (then it keeps the stream open until the client goes away)."""

    def __init__(self, key=None, grants=None, records=(), tls_dir=None, redirect_to=None,
                 version=None):
        self.key = key or RSAKey()
        self.verifier = Verifier([self.key])
        self.grants = dict(grants or {})
        self.records = list(records)
        self.requests = []
        self.disconnects = []
        self.redirect_to = redirect_to
        self.version = version or {"console": "fixture", "operator": "fixture-operator"}
        self._lock = threading.Lock()
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, *_):
                pass

            def do_GET(self):
                fixture.handle(self, "GET")

            def do_POST(self):
                fixture.handle(self, "POST")

        class Server(ThreadingHTTPServer):
            daemon_threads = True

            def handle_error(self, request, client_address):
                # A client that refuses this certificate resets during the handshake; that is
                # the expected outcome of the TLS tests, counted rather than printed.
                with fixture._lock:
                    fixture.connection_errors += 1

        self.connection_errors = 0
        self.server = Server(("127.0.0.1", 0), Handler)
        self.scheme = "http"
        if tls_dir is not None:
            cert, key_file = self_signed_cert(tls_dir)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key_file)
            self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
            self.scheme = "https"
            self.ca_file = cert
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def base(self):
        return f"{self.scheme}://127.0.0.1:{self.port}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def token(self, subject, **overrides):
        return mint(self.key, subject, **overrides)

    # ── request handling ──

    def _record(self, method, path, query, auth, lens):
        with self._lock:
            self.requests.append({"method": method, "path": path, "query": query,
                                  "authorization": auth, "lens": lens, "at": time.monotonic()})

    def handle(self, h, method):
        url = urlsplit(h.path)
        query = parse_qs(url.query)
        auth = h.headers.get("Authorization")
        lens = h.headers.get("X-Phorvex-Lens") or (query.get("lens") or [None])[0]
        self._record(method, url.path, url.query, auth, lens)
        body = b""
        length = int(h.headers.get("Content-Length") or 0)
        if length:
            body = h.rfile.read(length)

        def reply(status, doc, headers=()):
            raw = json.dumps(doc).encode()
            h.send_response(status)
            h.send_header("Content-Type", "application/json")
            h.send_header("Content-Length", str(len(raw)))
            for name, value in headers:
                h.send_header(name, value)
            h.end_headers()
            h.wfile.write(raw)

        if url.path == "/api/health":
            return reply(200, {"ok": True})
        if url.path == "/api/redirect":
            h.send_response(302)
            h.send_header("Location", (self.redirect_to or self.base) + "/api/version")
            h.end_headers()
            return None
        if not url.path.startswith("/api/"):
            return reply(404, {"error": "not found"})

        # ── the trust boundary: credential -> subject -> grant -> role -> scope ──
        identity = None
        if auth and auth.startswith("Bearer "):
            identity = self.verifier.verify(auth[len("Bearer "):].strip())
        if identity is None:
            return reply(401, {"error": "authentication required"},
                         [("WWW-Authenticate", 'Bearer realm="phorvex-console"')])
        grant = self.grants.get(identity[1])
        if grant is None:
            return reply(403, {"error": NO_GRANT})
        if not grant.allows_target("default"):
            return reply(403, {"error": "this route acts on cluster target default, which is "
                                        "outside this identity's target scope"})
        if url.path == "/api/echo-error":
            # A misbehaving upstream that reflects the request into an error body; the
            # client must not retain what it reflects.
            return reply(500, {"error": "upstream failed while handling " + (auth or "")})
        if url.path == "/api/session":
            return reply(200, {"subject": identity[1], "issuer": identity[0], "source": "bearer",
                               "roles": grant.roles, "tenants": grant.tenants,
                               "targets": grant.targets, "lens": lens,
                               "canRead": grant.can_read, "canEdit": grant.can_operate})
        if url.path == "/api/version":
            if not grant.can_read:
                return reply(403, {"error": READ_ROLE})
            return reply(200, dict(self.version))
        if url.path == "/api/workload/attack":
            if method != "POST":
                return reply(405, {"error": "method not allowed; /api/workload/attack accepts POST"})
            if not grant.can_operate:
                return reply(403, {"error": CONTROL_ROLE})
            try:
                doc = json.loads(body)
            except ValueError:
                return reply(400, {"error": "bad request body"})
            namespace = (doc or {}).get("namespace", "")
            if not grant.allows_tenant(namespace):
                return reply(403, {"error": f"namespace {namespace} is outside this identity's tenant scope"})
            if doc.get("action") == "unarmed":
                return reply(503, {"ok": False, "error": "no attackable pod left"})
            return reply(200, {"ok": True, "pod": namespace + "-a", "expect": "rotate",
                               "action": doc.get("action")})
        if url.path == "/api/live":
            if not grant.can_read:
                return reply(403, {"error": READ_ROLE})
            asked = (query.get("tenant") or [""])[0]
            if asked and not grant.allows_tenant(asked):
                return reply(403, {"error": f"tenant {asked} is outside this identity's tenant scope"})
            return self._stream(h, grant)
        return reply(404, {"error": "not found"})

    def _stream(self, h, grant):
        h.send_response(200)
        h.send_header("Content-Type", "text/event-stream")
        h.send_header("Cache-Control", "no-cache")
        h.end_headers()
        try:
            h.wfile.write(b": connected\n\n")
            h.wfile.flush()
            for record in self.records:
                if grant.allows_tenant(record.get("tenant", "")):
                    h.wfile.write(b"data: " + json.dumps(record).encode() + b"\n\n")
            h.wfile.flush()
            # Tail: keep the connection open until the client disconnects, like the console.
            while True:
                time.sleep(0.1)
                h.wfile.write(b": keepalive\n\n")
                h.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            with self._lock:
                self.disconnects.append(time.monotonic())


def openssl_available():
    return shutil.which("openssl") is not None


def self_signed_cert(directory):
    """A throwaway localhost certificate for the TLS server; nothing else trusts it."""
    directory = Path(directory)
    cert, key = directory / "cert.pem", directory / "key.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
         "-nodes", "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost",
         "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost", "-days", "2"],
        check=True, capture_output=True)
    return str(cert), str(key)
