"""Authenticated console transport (T1-E2E-AUTH), driven for real.

Every test below runs the production `Console` -> `Transport` -> `/bin/sh` -> `curl` path
against `console_fixture.FixtureConsole`, a loopback console whose bearer verifier and grant
table reproduce the deployed console's contract. Nothing between the pipeline's config and
the socket is stubbed; the fixture records exactly which requests, credentials and lenses
reached it, and whether the client went away when its window ended.

The incident (PR179 run34762525956): after the M-136 identity boundary rolled out, the
pipeline's client still authorised itself with `?lens=operator` and nothing else. Health
answered, every protected route was 401, and preflight aborted. The first test class is
that baseline; the rest is the configured, authenticated caller.
"""
import contextlib
import io
import json
import os
import re
import shlex
import shutil
import signal
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import console_fixture as CF
import fixtures as F
import observation as obs
from capture import CaptureLimits
from transport import (CONSOLE_TOKEN_ENV, CONSOLE_TOKEN_FILE_ENV, CONSOLE_BASE_ENV,
                       CONSOLE_CA_FILE_ENV, SSH_KNOWN_HOSTS_ENV, MAX_TOKEN_BYTES, Console,
                       ConsoleAccessError, Transport, TransportError)

LIMITS = CaptureLimits(max_total_bytes=200_000, max_records=1_000)
CI_SUBJECT = "e2e-ci-subject"
RECORDS = [F.record(tenant="voice", namespace="voice", pod="voice-a", action="rotate"),
           F.record(tenant="other", namespace="other", pod="other-a", action="noop")]


class RecordingTransport(Transport):
    """The real local transport, remembering every argv, environment and stdin it used."""

    def __init__(self):
        super().__init__({"kind": "local"})
        self.argvs, self.envs, self.stdins, self.commands = [], [], [], []

    def _command(self, command):
        argv, env = super()._command(command)
        self.commands.append(command)
        self.argvs.append(argv)
        self.envs.append(env)
        return argv, env

    def run(self, command, timeout=60, stdin=None):
        self.stdins.append(stdin)
        return super().run(command, timeout, stdin)

    def capture_live(self, command, seconds, limits, scope=None, on_connected=None, stdin=None):
        self.stdins.append(stdin)
        return super().capture_live(command, seconds, limits, scope, on_connected, stdin)


def clean_env(**extra):
    """The console variables are decided per test; nothing leaks in from the developer's shell."""
    scrubbed = {k: v for k, v in os.environ.items() if not k.startswith("PHORVEX_CONSOLE_")}
    scrubbed.update(extra)
    return patch.dict(os.environ, scrubbed, clear=True)


def token_file(directory, value, mode=0o600, name="console-token"):
    path = Path(directory) / name
    path.write_bytes(value if isinstance(value, bytes) else value.encode())
    path.chmod(mode)
    return str(path)


class FixtureCase(unittest.TestCase):
    """One loopback console per test, with the CI subject granted operator on `voice`."""

    grants = None

    def setUp(self):
        self.key = CF.RSAKey()
        self.server = CF.FixtureConsole(
            key=self.key, records=RECORDS,
            grants=self.grants if self.grants is not None else {
                CI_SUBJECT: CF.Grant(["operator"], ["voice"])})
        self.addCleanup(self.server.close)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.transport = RecordingTransport()

    def console(self, subject=CI_SUBJECT, token=None, **cfg):
        """An authenticated client whose token lives in a private file — the developer path."""
        value = token if token is not None else self.server.token(subject)
        config = {"mode": "http", "auth": "bearer", "base": self.server.base,
                  "token_file": token_file(self.tmp.name, value + "\n"), "lens": "operator"}
        config.update(cfg)
        with clean_env():
            return Console(self.transport, config)

    def requests(self, path=None):
        return [r for r in self.server.requests if path is None or r["path"] == path]


# ─────────────────────────────────── the incident ───────────────────────────────────

class IncidentBaselineTests(FixtureCase):
    """The old caller against a verifying console: reachable, and unable to use it."""

    def legacy_console(self):
        # `auth: none` is exactly the old client — curl with a lens header and nothing else.
        with clean_env():
            return Console(self.transport, {"mode": "http", "auth": "none",
                                            "base": self.server.base, "lens": "operator"})

    def test_public_health_answers_but_a_lens_authenticates_nobody(self):
        console = self.legacy_console()
        self.assertEqual(console.get_json("/api/health"), {"ok": True})     # reachability control
        with self.assertRaises(ConsoleAccessError) as caught:
            console.get_json("/api/version")
        message = str(caught.exception)
        self.assertIn("HTTP 401", message)
        self.assertIn("no console credential", message)
        self.assertIn("lens is a presentation hint", message)
        served = self.requests("/api/version")
        self.assertEqual(len(served), 1)
        self.assertIsNone(served[0]["authorization"])
        self.assertEqual(served[0]["lens"], "operator")   # the lens DID arrive; it is not identity

    def test_preflight_stops_on_the_credential_failure_instead_of_waiting_out_its_deadline(self):
        console = self.legacy_console()
        started = time.monotonic()
        with self.assertRaisesRegex(ConsoleAccessError, "HTTP 401"):
            console.wait_preflight(timeout=30)
        self.assertLess(time.monotonic() - started, 10)
        self.assertEqual(len(self.requests("/api/version")), 1)   # no retry of a refused route

    def test_an_unauthenticated_stream_never_counts_as_readiness(self):
        console = self.legacy_console()
        fired = []
        with self.assertRaisesRegex(ConsoleAccessError, "HTTP 401"):
            console.stream_decisions(1, LIMITS, on_connected=lambda: fired.append(True))
        self.assertEqual(fired, [])
        self.assertEqual(len(self.requests("/api/live")), 1)

    def test_kubectl_proxy_names_its_own_limitation_on_a_401(self):
        class ProxyDenied:
            kind = "local"

            def run(self, command, timeout=60, stdin=None):
                assert command.startswith("kubectl get --raw"), command
                return 1, "", ("error: You must be logged in to the server (the server has "
                               "asked for the client to provide credentials)\n")
        console = Console(ProxyDenied(), {"mode": "kubectl-proxy"})
        with self.assertRaises(ConsoleAccessError) as caught:
            console.wait_preflight(timeout=5)
        self.assertIn("carries NO console credential", str(caught.exception))
        self.assertIn("mode=http", str(caught.exception))
        # Health itself was the refused route, so nothing beyond the API server is claimed.
        self.assertIn("public health itself was refused", str(caught.exception))
        self.assertNotIn("console refusing", str(caught.exception))

    def test_kubectl_proxy_cannot_be_told_to_carry_a_bearer(self):
        with self.assertRaisesRegex(ConsoleAccessError, "cannot be combined"):
            Console(self.transport, {"mode": "kubectl-proxy", "auth": "bearer"})


# ───────────────────────────── the authenticated caller ─────────────────────────────

class AuthenticatedCallerTests(FixtureCase):
    def test_get_version_and_session_carry_the_bearer_and_succeed(self):
        console = self.console()
        health, version = console.wait_preflight(timeout=10)
        self.assertEqual(health, {"ok": True})
        self.assertEqual(version["operator"], "fixture-operator")
        session = console.get_json("/api/session")
        self.assertEqual(session["subject"], CI_SUBJECT)
        self.assertEqual(session["source"], "bearer")
        self.assertEqual(session["lens"], "operator")
        for served in self.requests("/api/version") + self.requests("/api/session"):
            self.assertEqual(served["authorization"], "Bearer " + console.token)
        self.assertEqual(len(self.requests("/api/health")), 1)

    def test_post_carries_the_bearer_once_and_is_never_retried(self):
        console = self.console()
        got = console.post_json("/api/workload/attack", {"namespace": "voice", "action": "foothold"})
        self.assertIs(got["ok"], True)
        self.assertEqual(got["pod"], "voice-a")
        served = self.requests("/api/workload/attack")
        self.assertEqual(len(served), 1)
        self.assertEqual(served[0]["method"], "POST")
        self.assertEqual(served[0]["authorization"], "Bearer " + console.token)

    def test_sse_fires_the_stimulus_once_after_the_authenticated_heartbeat(self):
        console = self.console()
        fired = []
        got = console.stream_decisions(0.5, LIMITS, on_connected=lambda: fired.append(True))
        self.assertEqual(fired, [True])
        self.assertTrue(got.complete, got.reason)
        # The grant covers `voice` only; the fixture's `other` record never reaches the wire.
        self.assertEqual([r["pod"] for r in got.records], ["voice-a"])
        served = self.requests("/api/live")
        self.assertEqual(len(served), 1)
        self.assertEqual(served[0]["authorization"], "Bearer " + console.token)
        self.assertEqual(served[0]["query"], "lens=operator&tail=1")   # replay is a tail when armed

    def test_observe_window_streams_without_a_callback(self):
        got = self.console().stream_decisions(0.4, LIMITS)
        self.assertTrue(got.complete, got.reason)
        self.assertEqual(len(got.records), 1)

    def test_the_stream_process_is_gone_when_the_window_ends(self):
        console = self.console()
        console.stream_decisions(0.3, LIMITS, on_connected=lambda: None)
        deadline = time.monotonic() + 5
        while not self.server.disconnects and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertEqual(len(self.server.disconnects), 1, "the curl child kept the stream open")
        listing = subprocess.run(["pgrep", "-af", f"curl .*{self.server.port}/api/live"],
                                 capture_output=True, text=True).stdout
        self.assertEqual(listing.strip(), "")

    def test_the_remote_process_is_bounded_and_the_replay_is_a_tail(self):
        console = self.console()
        console.stream_decisions(0.2, LIMITS, on_connected=lambda: None)
        words = shlex.split(self.transport.commands[-1])
        self.assertEqual(words[words.index("-m") + 1], "90")      # seconds + 90 for the callback
        self.assertIn("-N", words)
        self.assertIn("-f", words)
        self.assertTrue(words[-1].endswith("/api/live?lens=operator&tail=1"), words[-1])

    def test_investor_grant_reads_but_cannot_fire(self):
        self.server.grants = {CI_SUBJECT: CF.Grant(["investor"], ["voice"])}
        console = self.console()
        self.assertEqual(console.get_json("/api/version")["operator"], "fixture-operator")
        with self.assertRaises(ConsoleAccessError) as caught:
            console.post_json("/api/workload/attack", {"namespace": "voice", "action": "foothold"})
        self.assertIn("HTTP 403", str(caught.exception))
        self.assertIn("operator role", str(caught.exception))
        self.assertEqual(len(self.requests("/api/workload/attack")), 1)


class RejectedCredentialTests(FixtureCase):
    """Every way a verifying console says no, and how the client reports it."""

    def assert_401(self, console, path="/api/version"):
        with self.assertRaises(ConsoleAccessError) as caught:
            console.get_json(path)
        self.assertIn("HTTP 401", str(caught.exception))
        self.assertIn("was not accepted", str(caught.exception))
        self.assertIn("authentication required", str(caught.exception))

    def test_expired_token(self):
        self.assert_401(self.console(token=self.server.token(CI_SUBJECT, ttl=-120)))

    def test_not_yet_valid_token(self):
        self.assert_401(self.console(token=self.server.token(CI_SUBJECT, nbf=time.time() + 600)))

    def test_token_signed_by_another_key(self):
        stranger = CF.RSAKey(kid=CF.KID)    # same kid, different key: the signature is what counts
        self.assert_401(self.console(token=CF.mint(stranger, CI_SUBJECT)))

    def test_unsigned_alg_none_token(self):
        self.assert_401(self.console(token=self.server.token(CI_SUBJECT, alg="none") + "x"))

    def test_wrong_audience_and_wrong_issuer(self):
        self.assert_401(self.console(token=self.server.token(CI_SUBJECT, audience="other-app")))
        self.assert_401(self.console(token=self.server.token(CI_SUBJECT, issuer="https://evil.test")))

    def test_valid_identity_without_a_grant_is_403_not_401(self):
        console = self.console(subject="nobody-bound-me")
        with self.assertRaises(ConsoleAccessError) as caught:
            console.wait_preflight(timeout=10)
        message = str(caught.exception)
        self.assertIn("HTTP 403", message)
        self.assertIn("no authorization grant", message)
        self.assertIn("no grant covers", message)
        self.assertIn("not proof", message)          # a 403 is not evidence of a verified identity
        self.assertEqual(len(self.requests("/api/version")), 1)

    def test_wrong_tenant_on_a_control_is_403_and_issued_once(self):
        console = self.console()
        with self.assertRaises(ConsoleAccessError) as caught:
            console.post_json("/api/workload/attack", {"namespace": "nats", "action": "foothold"})
        self.assertIn("outside this identity's tenant scope", str(caught.exception))
        self.assertEqual(len(self.requests("/api/workload/attack")), 1)

    def test_wrong_target_is_403(self):
        self.server.grants = {CI_SUBJECT: CF.Grant(["operator"], ["voice"], targets=["remote"])}
        with self.assertRaisesRegex(ConsoleAccessError, "target scope"):
            self.console().get_json("/api/version")

    def test_a_stream_outside_the_grant_never_fires_the_stimulus(self):
        console = self.console(subject="nobody-bound-me")
        fired = []
        with self.assertRaisesRegex(ConsoleAccessError, "HTTP 403"):
            console.stream_decisions(1, LIMITS, on_connected=lambda: fired.append(True))
        self.assertEqual(fired, [])

    def test_an_error_status_with_a_json_body_is_never_a_fired_attack(self):
        console = self.console()
        got = console.post_json("/api/workload/attack", {"namespace": "voice", "action": "unarmed"})
        self.assertIs(got["ok"], False)
        self.assertEqual(got["_httpStatus"], 503)
        self.assertIn("no attackable pod", got["error"])
        self.assertEqual(len(self.requests("/api/workload/attack")), 1)

    def test_a_non_200_get_is_not_a_document(self):
        with self.assertRaisesRegex(TransportError, "HTTP 404"):
            self.console().get_json("/api/does-not-exist")


# ───────────────────────────── endpoint and secret hygiene ─────────────────────────────

class EndpointSafetyTests(FixtureCase):
    def test_redirects_fail_and_the_credential_is_never_forwarded(self):
        sink = CF.FixtureConsole(key=self.key, grants={})
        self.addCleanup(sink.close)
        self.server.redirect_to = sink.base
        console = self.console()
        with self.assertRaises(ConsoleAccessError) as caught:
            console.get_json("/api/redirect")
        self.assertIn("redirect", str(caught.exception))
        self.assertEqual(sink.requests, [])                     # the Location was never fetched
        self.assertEqual(len(self.requests("/api/redirect")), 1)
        words = shlex.split(self.transport.commands[-1])
        self.assertEqual(words[words.index("--max-redirs") + 1], "0")

    def test_plain_http_to_a_non_loopback_host_is_refused_before_any_request(self):
        for base in ("http://10.0.0.5:8095", "http://console.phorvex.ai", "http://[fe80::1]:80"):
            with self.subTest(base=base), self.assertRaisesRegex(ConsoleAccessError, "non-loopback"):
                self.console(base=base)
        self.assertEqual(self.transport.commands, [])

    def test_loopback_http_is_the_explicit_exception_for_literal_addresses_only(self):
        for host in ("127.0.0.1", "127.1.2.3", "[::1]"):
            with self.subTest(host=host):
                console = self.console(base=f"http://{host}:{self.server.port}/")
                self.assertEqual(console.base, f"http://{host}:{self.server.port}")
        # A name is a lookup on the transport host — hosts file, resolver or proxy decide it.
        for host in ("localhost", "localhost.localdomain", "loopback.example"):
            with self.subTest(host=host), self.assertRaisesRegex(ConsoleAccessError, "literal loopback"):
                self.console(base=f"http://{host}:{self.server.port}")
        console = self.console(base="https://console.internal.example:8443/prefix/")
        self.assertEqual(console.base, "https://console.internal.example:8443/prefix")
        self.assertEqual(self.transport.commands, [])       # configuration makes no request

    def test_userinfo_query_fragment_and_bad_schemes_are_refused(self):
        for base, why in (("https://user:pw@console.example", "userinfo"),
                          ("https://console.example/?x=1", "query"),
                          ("https://console.example/#frag", "query"),
                          ("ftp://console.example", "http"),
                          ("console.example", "http"),
                          ("https://console.example:notaport", "port"),
                          ("", "not configured")):
            with self.subTest(base=base), self.assertRaisesRegex(ConsoleAccessError, why):
                self.console(base=base)

    def test_anonymous_mode_may_reach_any_scheme_but_still_names_itself(self):
        with clean_env():
            console = Console(self.transport, {"mode": "http", "auth": "none",
                                               "base": "http://10.0.0.5:8095"})
        self.assertIn("anonymous", console.describe())

    def test_the_token_is_on_stdin_only_never_in_argv_environment_or_command_text(self):
        console = self.console()
        console.get_json("/api/version")
        console.post_json("/api/workload/attack", {"namespace": "voice", "action": "foothold"})
        console.stream_decisions(0.2, LIMITS)
        self.assertEqual(len(self.transport.stdins), 3)
        for stdin in self.transport.stdins:
            self.assertEqual(stdin, f'header = "Authorization: Bearer {console.token}"\n')
        for command, argv, env in zip(self.transport.commands, self.transport.argvs,
                                      self.transport.envs):
            self.assertNotIn(console.token, command)
            self.assertFalse(any(console.token in word for word in argv), argv)
            self.assertFalse(any(console.token in value for value in env.values()))
            words = shlex.split(command)
            self.assertEqual(words[words.index("-K") + 1], "-")
            self.assertNotIn("-k", words)
            self.assertNotIn("--insecure", words)
            self.assertNotIn("Authorization", command)

    def test_the_environment_token_is_scrubbed_from_every_child(self):
        with clean_env(**{CONSOLE_TOKEN_ENV: self.server.token(CI_SUBJECT)}):
            console = Console(self.transport, {"mode": "http", "base": self.server.base})
            console.get_json("/api/version")
        self.assertEqual(console.token_source, "$" + CONSOLE_TOKEN_ENV)
        self.assertNotIn(CONSOLE_TOKEN_ENV, self.transport.envs[-1])
        self.assertEqual(self.requests("/api/version")[0]["authorization"],
                         "Bearer " + console.token)

    def test_ssh_transport_puts_the_configuration_on_stdin_and_nothing_in_argv(self):
        captured = {}

        def fake_run(argv, **kwargs):
            captured["argv"], captured["kwargs"] = argv, kwargs
            return subprocess.CompletedProcess(argv, 0, '{"ok":true}200', "")
        known_hosts = token_file(self.tmp.name, "[jump.example]:22 ssh-ed25519 AAAAfixture\n",
                                 name="known_hosts", mode=0o600)
        with clean_env(PHORVEX_SSH_PASSWORD="hunter2-fixture"):
            transport = Transport({"kind": "ssh", "host": "jump.example", "user": "ci",
                                   "known_hosts": known_hosts})
            console = Console(transport, {"mode": "http", "base": "http://127.0.0.1:8095",
                                          "token_file": token_file(self.tmp.name, "a" * 40)})
            with patch("transport.subprocess.run", side_effect=fake_run):
                self.assertEqual(console.get_json("/api/health"), {"ok": True})
        argv, kwargs = captured["argv"], captured["kwargs"]
        self.assertEqual(argv[:3], ["sshpass", "-e", "ssh"])
        self.assertIn("-K -", argv[-1])
        self.assertEqual(argv[argv.index("-o") + 1], "StrictHostKeyChecking=yes")
        self.assertIn(f"UserKnownHostsFile={known_hosts}", argv)
        self.assertFalse(any("a" * 40 in word for word in argv))
        self.assertEqual(kwargs["input"], 'header = "Authorization: Bearer ' + "a" * 40 + '"\n')
        self.assertEqual(kwargs["env"]["SSHPASS"], "hunter2-fixture")
        self.assertNotIn(CONSOLE_TOKEN_ENV, kwargs["env"])

    def test_a_reflected_credential_is_redacted_from_the_retained_error(self):
        console = self.console()
        with self.assertRaises(TransportError) as caught:
            console.get_json("/api/echo-error")
        message = str(caught.exception)
        self.assertIn("HTTP 500", message)
        self.assertNotIn(console.token, message)
        self.assertIn("[REDACTED]", message)
        self.assertNotIn(console.token, obs.redact("stray " + console.token + " tail"))


@unittest.skipUnless(CF.openssl_available(), "openssl is needed to mint the fixture certificate")
class TLSTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.server = CF.FixtureConsole(grants={CI_SUBJECT: CF.Grant(["operator"], ["voice"])},
                                        records=RECORDS, tls_dir=self.tmp.name)
        self.addCleanup(self.server.close)
        self.transport = RecordingTransport()
        self.token_path = token_file(self.tmp.name, self.server.token(CI_SUBJECT))

    def console(self, **cfg):
        config = {"mode": "http", "base": self.server.base, "token_file": self.token_path}
        config.update(cfg)
        with clean_env():
            return Console(self.transport, config)

    def test_an_untrusted_certificate_is_refused_and_no_request_is_made(self):
        with self.assertRaises(ConsoleAccessError) as caught:
            self.console().get_json("/api/version")
        self.assertIn("TLS", str(caught.exception))
        self.assertIn(CONSOLE_CA_FILE_ENV, str(caught.exception))
        self.assertEqual(self.server.requests, [])
        self.assertGreaterEqual(self.server.connection_errors, 1)
        self.assertNotIn("-k", shlex.split(self.transport.commands[-1]))

    def test_a_configured_ca_bundle_is_normal_verification(self):
        console = self.console(ca_file=self.server.ca_file)
        health, version = console.wait_preflight(timeout=10)
        self.assertEqual(version["operator"], "fixture-operator")
        got = console.stream_decisions(0.3, LIMITS, on_connected=lambda: None)
        self.assertEqual([r["pod"] for r in got.records], ["voice-a"])
        self.assertEqual(self.server.requests[-1]["authorization"], "Bearer " + console.token)
        words = shlex.split(self.transport.commands[-1])
        self.assertEqual(words[words.index("--cacert") + 1], self.server.ca_file)

    def test_the_ca_bundle_can_come_from_the_environment(self):
        with clean_env(**{CONSOLE_CA_FILE_ENV: self.server.ca_file, CONSOLE_BASE_ENV: self.server.base}):
            console = Console(self.transport, {"mode": "http", "token_file": self.token_path})
            self.assertEqual(console.get_json("/api/version")["operator"], "fixture-operator")

    def test_an_unauthenticated_tls_stream_is_still_refused(self):
        with clean_env():
            console = Console(self.transport, {"mode": "http", "auth": "none",
                                               "base": self.server.base, "ca_file": self.server.ca_file})
        fired = []
        with self.assertRaisesRegex(ConsoleAccessError, "HTTP 401"):
            console.stream_decisions(1, LIMITS, on_connected=lambda: fired.append(True))
        self.assertEqual(fired, [])


# ─────────────────────────────── credential input rules ───────────────────────────────

class CredentialSourceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.transport = RecordingTransport()
        self.good = "e" * 64

    def console(self, env=None, **cfg):
        config = {"mode": "http", "base": "https://console.internal.example"}
        config.update(cfg)
        with clean_env(**(env or {})):
            return Console(self.transport, config)

    def refuse(self, why, env=None, **cfg):
        with self.assertRaisesRegex(ConsoleAccessError, why):
            self.console(env, **cfg)
        self.assertEqual(self.transport.commands, [])

    def test_nothing_configured_is_actionable(self):
        self.refuse(f"set {CONSOLE_TOKEN_ENV}.*token_file")

    def test_an_empty_environment_secret_counts_as_absent(self):
        # GitHub passes an unset secret as an empty string; that is "not provisioned".
        self.refuse("no console credential", env={CONSOLE_TOKEN_ENV: ""})

    def test_a_missing_file_names_the_path(self):
        missing = str(Path(self.tmp.name) / "absent")
        self.refuse(f"{missing} does not exist", token_file=missing)

    def test_empty_multiline_oversized_short_and_malformed_values_are_refused(self):
        for value, why in (("", "is empty"), ("\n", "is empty"),
                           (self.good + "\n" + self.good + "\n", "several lines"),
                           ("x" * (MAX_TOKEN_BYTES + 800), "exceeds"), ("short", "shorter than"),
                           ("bad token with spaces" + "a" * 20, "charset"),
                           ('quoted"' + "a" * 20, "charset"), ("back\\slash" + "a" * 20, "charset"),
                           ("Bearer " + self.good, "charset"), ("é" * 20, "ASCII|charset")):
            with self.subTest(value=value[:20]):
                self.refuse(why, token_file=token_file(self.tmp.name, value))
                if value.strip("\n"):
                    self.refuse(why, env={CONSOLE_TOKEN_ENV: value})

    def test_one_trailing_newline_is_the_only_tolerated_decoration(self):
        for suffix in ("", "\n", "\r\n"):
            with self.subTest(suffix=repr(suffix)):
                console = self.console(token_file=token_file(self.tmp.name, self.good + suffix))
                self.assertEqual(console.token, self.good)
        self.refuse("charset", token_file=token_file(self.tmp.name, " " + self.good))

    def test_insecure_file_modes_are_refused(self):
        for mode in (0o644, 0o640, 0o604, 0o660, 0o606, 0o777):
            with self.subTest(mode=oct(mode)):
                self.refuse("readable by other users",
                            token_file=token_file(self.tmp.name, self.good, mode=mode))
        for mode in (0o600, 0o400):
            with self.subTest(mode=oct(mode)):
                self.console(token_file=token_file(self.tmp.name, self.good, mode=mode))

    def test_a_directory_or_device_is_not_a_token_file(self):
        self.refuse("not a regular file", token_file=self.tmp.name)
        if Path("/dev/null").exists():
            self.refuse("not a regular file|readable by other users", token_file="/dev/null")

    def test_two_configured_sources_conflict_whether_or_not_the_file_exists(self):
        present = token_file(self.tmp.name, self.good)
        absent = str(Path(self.tmp.name) / "absent")
        # Which identity a run uses is decided by its configuration, never by whether a path
        # happens to exist on this machine: the same configuration answers the same way.
        for path in (present, absent):
            with self.subTest(path=path):
                self.refuse("configured twice", env={CONSOLE_TOKEN_ENV: "f" * 64}, token_file=path)
                self.refuse("configured twice",
                            env={CONSOLE_TOKEN_ENV: "f" * 64, CONSOLE_TOKEN_FILE_ENV: path})
        # Exactly one configured source is unambiguous, from either direction.
        self.assertEqual(self.console(env={CONSOLE_TOKEN_ENV: "f" * 64}).token, "f" * 64)
        console = self.console(env={CONSOLE_TOKEN_FILE_ENV: present})
        self.assertEqual(console.token, self.good)
        self.assertEqual(console.token_source, f"file {present}")
        self.assertEqual(self.console(token_file=present).token, self.good)
        # An empty environment value is an unset one, so a configured file is not a conflict.
        self.assertEqual(self.console(env={CONSOLE_TOKEN_ENV: ""}, token_file=present).token, self.good)
        self.refuse("does not exist", env={CONSOLE_TOKEN_ENV: ""}, token_file=absent)

    def test_the_loaded_token_is_registered_for_redaction_and_absent_from_describe(self):
        console = self.console(token_file=token_file(self.tmp.name, self.good))
        self.assertNotIn(self.good, console.describe())
        self.assertNotIn(self.good, obs.redact("error mentioning " + self.good))

    def test_config_json_keeps_no_secret_field(self):
        cfg = json.loads((Path(__file__).resolve().parents[1] / "config.json").read_text())
        console_cfg = cfg["console"]
        self.assertEqual(console_cfg["mode"], "http")
        self.assertEqual(console_cfg["auth"], "bearer")
        self.assertNotIn("token", console_cfg)
        self.assertIsNone(console_cfg.get("base"))
        # No implicit file path: with one, the CI secret would conflict by construction.
        self.assertIsNone(console_cfg.get("token_file"))
        # The old proxy path stays reachable only by explicit choice.
        self.assertEqual(console_cfg["service"]["name"], "phorvex-console")
        self.assertIn("known_hosts", cfg["transport"])
        self.assertIsNone(cfg["transport"]["known_hosts"])


# ───────────────────────── the whole pipeline through the real client ─────────────────────────

class HybridTransport(RecordingTransport):
    """curl goes to the loopback console for real; kubectl goes to the fixture cluster."""

    def __init__(self, cluster):
        super().__init__()
        self.cluster = cluster

    def run(self, command, timeout=60, stdin=None):
        if command.startswith("kubectl"):
            return self.cluster.run(command, timeout)
        return super().run(command, timeout, stdin)

    def describe(self):
        return "hybrid fixture"


class FullRunTests(unittest.TestCase):
    """`e2e.run` in observe mode with preflight and both captures on the real client."""

    def setUp(self):
        self.server = CF.FixtureConsole(grants={CI_SUBJECT: CF.Grant(["operator"], ["voice"])},
                                        records=RECORDS)
        self.addCleanup(self.server.close)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        cluster = F.FakeKubectl(pods=[F.pod("voice-a", namespace="voice")],
                                inventory=F.deployment_stack("fixture-controller"),
                                policies=[F.phorvex_policy(namespace="voice")])
        self.transport = HybridTransport(cluster)

    def run_pipeline(self, console_cfg):
        import e2e
        cfg = {"invariants": {"known_actions": ["noop", "rotate"], "known_engines": ["p1-coverage"],
                              "known_phases": ["Warm"], "known_stages": ["recon", "exploit"],
                              "net_identity_tolerance": 0.005, "phoenix_actions": ["rotate"],
                              "law_reason_prefixes": {}, "max_controller_restarts": 10},
               "transport": {"kind": "local"}, "console": console_cfg,
               "capture": {"stream_seconds": 0.3, "post_attack_seconds": 1, "settle_seconds": 0,
                           "max_bytes": 1_000_000, "max_records": 500, "namespaces": None},
               "controller_deployments": ["fixture-controller"], "targets": []}
        with clean_env(), contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(e2e, "Transport", return_value=self.transport))
            stack.enter_context(patch.object(
                e2e.Metrics, "scrape",
                return_value=obs.Observation.observed({"phorvex_kill_switch_engaged": 0.0})))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            return e2e.run(cfg, "observe", None, self.tmp.name)

    def test_the_old_client_aborts_at_preflight_with_the_credential_diagnosis(self):
        doc, rc = self.run_pipeline({"mode": "http", "auth": "none", "base": self.server.base})
        self.assertEqual(rc, 2)
        self.assertEqual(doc["abort"]["stage"], "preflight")
        self.assertIn("HTTP 401", doc["abort"]["error"])
        self.assertIn("no console credential", doc["abort"]["error"])
        self.assertEqual([r["path"] for r in self.server.requests], ["/api/health", "/api/version"])

    def test_the_configured_caller_completes_preflight_and_observes_through_the_stream(self):
        path = token_file(self.tmp.name, self.server.token(CI_SUBJECT))
        doc, rc = self.run_pipeline({"mode": "http", "base": self.server.base, "token_file": path})
        self.assertNotEqual(doc.get("status"), "aborted", doc.get("abort"))
        self.assertEqual(doc["preflight"]["version"]["operator"], "fixture-operator")
        baseline = doc["capture"]["windows"]["baseline"]
        self.assertTrue(baseline["complete"], baseline["reason"])
        self.assertEqual(baseline["counters"]["accepted"], 1)
        paths = [r["path"] for r in self.server.requests]
        self.assertEqual(paths[:2], ["/api/health", "/api/version"])
        self.assertIn("/api/live", paths)
        for served in self.server.requests[1:]:
            self.assertTrue(served["authorization"].startswith("Bearer "))
        rendered = "".join(p.read_text() for p in Path(self.tmp.name).glob("run-*.json"))
        self.assertNotIn(self.server.requests[-1]["authorization"], rendered)

    def test_missing_provisioning_fails_closed_before_any_request(self):
        doc, rc = self.run_pipeline({"mode": "http", "auth": "bearer", "base": None})
        self.assertEqual(rc, 2)
        self.assertIn(CONSOLE_BASE_ENV, doc["abort"]["error"])
        self.assertEqual(self.server.requests, [])


# ─────────────────── lead review r1: transport-host and runner-side hazards ───────────────────

def fragments(secret, width=12):
    """Every window of a secret; a retained message may contain none of them."""
    return {secret[i:i + width] for i in range(0, len(secret) - width + 1, 7)}


class DefaultCurlConfigurationTests(FixtureCase):
    """R1: the transport host's `.curlrc` must not be able to redirect, weaken or persist
    the credential-carrying request. `-q` is the first curl option."""

    def curlrc(self, text):
        Path(self.tmp.name, ".curlrc").write_text(text)
        return self.tmp.name

    def test_a_curlrc_url_recipient_receives_nothing(self):
        sink = CF.FixtureConsole(key=self.key, grants={})
        self.addCleanup(sink.close)
        home = self.curlrc(f'url = "{sink.base}/unconfigured-recipient"\n')
        with clean_env(CURL_HOME=home):
            console = Console(self.transport, {"mode": "http", "base": self.server.base,
                                               "token_file": token_file(self.tmp.name, self.server.token(CI_SUBJECT))})
            self.assertEqual(console.get_json("/api/version")["operator"], "fixture-operator")
            console.post_json("/api/workload/attack", {"namespace": "voice", "action": "foothold"})
            console.stream_decisions(0.2, LIMITS)
        self.assertEqual(sink.requests, [])
        self.assertEqual([r["path"] for r in self.server.requests],
                         ["/api/version", "/api/workload/attack", "/api/live"])
        for command in self.transport.commands:
            words = shlex.split(command)
            self.assertEqual(words[:2], ["curl", "-q"], words)

    def test_curlrc_proxy_and_trace_settings_do_not_apply(self):
        sink = CF.FixtureConsole(key=self.key, grants={})
        self.addCleanup(sink.close)
        trace = Path(self.tmp.name, "trace.txt")
        home = self.curlrc(f'proxy = "{sink.base}"\ntrace = "{trace}"\nverbose\n')
        with clean_env(CURL_HOME=home):
            console = Console(self.transport, {"mode": "http", "base": self.server.base,
                                               "token_file": token_file(self.tmp.name, self.server.token(CI_SUBJECT))})
            self.assertEqual(console.get_json("/api/version")["operator"], "fixture-operator")
        self.assertEqual(sink.requests, [])
        self.assertFalse(trace.exists(), "the default configuration persisted the request")
        self.assertEqual(self.server.requests[-1]["authorization"], "Bearer " + console.token)


class InheritedProxyTests(FixtureCase):
    """R2: the loopback exception is a direct connection to the transport host's kernel, not a
    request handed to whatever proxy the environment names."""

    def test_proxy_variables_do_not_divert_the_loopback_request(self):
        sink = CF.FixtureConsole(key=self.key, grants={})
        self.addCleanup(sink.close)
        for variables in ({"http_proxy": sink.base}, {"HTTP_PROXY": sink.base},
                          {"ALL_PROXY": sink.base, "all_proxy": sink.base},
                          {"http_proxy": sink.base, "no_proxy": "example.com"}):
            with self.subTest(variables=variables):
                sink.requests.clear()
                self.server.requests.clear()
                with clean_env(**variables):
                    console = Console(self.transport, {"mode": "http", "base": self.server.base,
                                                       "token_file": token_file(self.tmp.name, self.server.token(CI_SUBJECT))})
                    self.assertEqual(console.get_json("/api/version")["operator"], "fixture-operator")
                    got = console.stream_decisions(0.2, LIMITS)
                self.assertEqual(sink.requests, [])
                self.assertEqual([r["path"] for r in self.server.requests], ["/api/version", "/api/live"])
                self.assertEqual(self.server.requests[0]["authorization"], "Bearer " + console.token)
                self.assertEqual(len(got.records), 1)
                words = shlex.split(self.transport.commands[-1])
                self.assertEqual(words[words.index("--noproxy") + 1], "*")


class StdinDeliveryTests(unittest.TestCase):
    """R4: the credential configuration is delivered inside the capture's own deadline — a
    child that never drains stdin, a pipe smaller than the input, or a child that exits
    first, are reported, never waited for or raised as BrokenPipeError."""

    PAYLOAD = 'header = "X-Fixture: ' + "x" * MAX_TOKEN_BYTES + '"\n'

    def small_pipe(self):
        original = subprocess.Popen

        def popen(*args, **kwargs):
            kwargs["pipesize"] = 4096
            return original(*args, **kwargs)
        return patch("transport.subprocess.Popen", side_effect=popen)

    def test_a_child_that_never_reads_cannot_hold_the_window_open(self):
        started = time.monotonic()
        with self.small_pipe():
            got = Transport({"kind": "local"}).capture_live(
                "exec sleep 0.8123", 0.1, CaptureLimits(65536, 100), stdin=self.PAYLOAD)
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 0.5, elapsed)
        self.assertFalse(got.complete)
        self.assertIn("never consumed its input", got.reason)
        self.assertEqual(subprocess.run(["pgrep", "-f", "sleep 0.8123"], capture_output=True,
                                        text=True).stdout.strip(), "")

    def test_the_whole_input_reaches_a_child_that_drains_it_through_a_small_pipe(self):
        code = ("import sys, time; d = sys.stdin.read(); print(': connected\\n', flush=True); "
                "print('data: {\"n\": %d}\\n' % len(d), flush=True); time.sleep(5)")
        fired = []
        with self.small_pipe():
            got = Transport({"kind": "local"}).capture_live(
                shlex.join(["python3", "-c", code]), 0.2, CaptureLimits(65536, 100),
                on_connected=lambda: fired.append(True), stdin=self.PAYLOAD)
        self.assertEqual(fired, [True])
        self.assertEqual([r["n"] for r in got.records], [len(self.PAYLOAD.encode())])
        self.assertTrue(got.complete, got.reason)

    def test_a_child_that_exits_before_reading_is_reported_not_raised(self):
        with self.small_pipe():
            got = Transport({"kind": "local"}).capture_live(
                "exit 22", 0.3, CaptureLimits(65536, 100), stdin=self.PAYLOAD)
        self.assertFalse(got.complete)
        self.assertIn("exited 22", got.reason)
        with self.small_pipe(), self.assertRaisesRegex(TransportError, "closed before observation"):
            Transport({"kind": "local"}).capture_live(
                "exit 22", 0.3, CaptureLimits(65536, 100), on_connected=lambda: None,
                stdin=self.PAYLOAD)

    def test_run_delivers_the_input_and_never_inherits_this_terminal(self):
        rc, out, _ = Transport({"kind": "local"}).run("wc -c", stdin=self.PAYLOAD)
        self.assertEqual((rc, out.strip()), (0, str(len(self.PAYLOAD.encode()))))
        rc, out, _ = Transport({"kind": "local"}).run("wc -c")
        self.assertEqual((rc, out.strip()), (0, "0"))


class SSHHostVerificationTests(unittest.TestCase):
    """R3: a password and a bearer go to whatever answers the SSH port, so that endpoint is
    verified against a provisioned host key on THIS machine — for every command the
    transport runs, and with no unknown/changed-key fallback."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def known_hosts(self, text="[jump.example]:22 ssh-ed25519 AAAAfixture\n", mode=0o600):
        return token_file(self.tmp.name, text, name="known_hosts", mode=mode)

    def transport(self, env=None, **cfg):
        config = {"kind": "ssh", "host": "jump.example", "user": "ci", "port": 2222}
        config.update(cfg)
        with clean_env(PHORVEX_SSH_PASSWORD="hunter2-fixture", **(env or {})):
            return Transport(config)

    def test_every_ssh_command_pins_the_host_and_verifies_strictly(self):
        path = self.known_hosts()
        transport = self.transport(known_hosts=path)
        for command in ("kubectl get pod -o json", "curl -q -sS -K - http://127.0.0.1:8095/api/version"):
            argv, env = transport._command(command)
            options = [argv[i + 1] for i, word in enumerate(argv) if word == "-o"]
            self.assertIn("StrictHostKeyChecking=yes", options)
            self.assertIn(f"UserKnownHostsFile={path}", options)
            self.assertIn("GlobalKnownHostsFile=/dev/null", options)
            self.assertIn("UpdateHostKeys=no", options)
            for option in options:
                self.assertNotIn("StrictHostKeyChecking=no", option)
                self.assertNotIn("accept-new", option)
                self.assertNotEqual(option, "UserKnownHostsFile=/dev/null")
            self.assertEqual(env["SSHPASS"], "hunter2-fixture")
            self.assertEqual(argv[-1], command)
        self.assertIn("host key pinned by", transport.describe())

    def test_the_known_hosts_file_comes_from_the_environment_or_config_and_is_required(self):
        path = self.known_hosts()
        self.assertEqual(self.transport(env={SSH_KNOWN_HOSTS_ENV: path}).known_hosts, path)
        with self.assertRaisesRegex(TransportError, "provisioned known_hosts"):
            self.transport()
        for text, mode, why in (("", 0o600, "non-empty"), ("x\n", 0o666, "writable by other users"),
                                ("x\n", 0o622, "writable by other users")):
            with self.subTest(mode=oct(mode), text=text), self.assertRaisesRegex(TransportError, why):
                self.transport(known_hosts=self.known_hosts(text, mode))
        with self.assertRaisesRegex(TransportError, "not readable"):
            self.transport(known_hosts=str(Path(self.tmp.name) / "absent"))
        with self.assertRaisesRegex(TransportError, "regular file"):
            self.transport(known_hosts=self.tmp.name)

    def test_publish_report_uses_the_same_pinned_host_identity(self):
        script = (Path(__file__).resolve().parents[1] / "publish-report.sh").read_text()
        self.assertNotIn("StrictHostKeyChecking=no", script)
        self.assertNotIn("UserKnownHostsFile=/dev/null", script)
        self.assertIn("StrictHostKeyChecking=yes", script)
        self.assertIn(SSH_KNOWN_HOSTS_ENV, script)


def sshd_binary():
    return shutil.which("sshd") or next((p for p in ("/usr/sbin/sshd", "/usr/local/sbin/sshd")
                                         if os.access(p, os.X_OK)), None)


def sshd_available():
    return sshd_binary() and all(shutil.which(tool) for tool in ("ssh", "ssh-keygen", "sshpass"))


@unittest.skipUnless(sshd_available(), "a local sshd, ssh, ssh-keygen and sshpass are needed")
class RealSSHHostKeyControlTests(unittest.TestCase):
    """The transport's ssh against an actual sshd on loopback: an unknown key fails before any
    authentication, a changed key fails, and only the provisioned key lets the credential
    configuration through — on stdin, end to end."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        d = Path(self.tmp.name)
        d.chmod(0o700)
        for name in ("hostkey", "clientkey", "otherkey"):
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(d / name)],
                           check=True, capture_output=True)
        (d / "authorized_keys").write_bytes((d / "clientkey.pub").read_bytes())
        # ssh resolves `~/.ssh` from the passwd entry, not $HOME, so the client key is offered
        # through a private agent instead; the transport's argv is exactly the production one.
        agent = subprocess.run(["ssh-agent", "-s", "-a", str(d / "agent.sock")],
                               check=True, capture_output=True, text=True).stdout
        self.agent_pid = int(re.search(r"SSH_AGENT_PID=(\d+)", agent).group(1))
        self.addCleanup(os.kill, self.agent_pid, signal.SIGTERM)
        self.agent_env = {"SSH_AUTH_SOCK": str(d / "agent.sock")}
        subprocess.run(["ssh-add", "-q", str(d / "clientkey")], check=True, capture_output=True,
                       env=dict(os.environ, **self.agent_env))
        import socket
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            self.port = probe.getsockname()[1]
        self.log = d / "sshd.log"
        log = self.log.open("wb")
        self.addCleanup(log.close)
        self.sshd = subprocess.Popen(
            [sshd_binary(), "-D", "-e", "-f", "/dev/null", "-h", str(d / "hostkey"), "-p", str(self.port),
             "-o", "ListenAddress=127.0.0.1", "-o", "PidFile=none", "-o", "UsePAM=no",
             "-o", "PasswordAuthentication=no", "-o", "StrictModes=no",
             "-o", f"AuthorizedKeysFile={d / 'authorized_keys'}", "-o", "LogLevel=VERBOSE"],
            stdout=subprocess.DEVNULL, stderr=log)
        self.addCleanup(self.sshd.wait, 5)
        self.addCleanup(self.sshd.terminate)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            with socket.socket() as probe:
                if probe.connect_ex(("127.0.0.1", self.port)) == 0:
                    break
            time.sleep(0.05)
        else:
            self.skipTest("local sshd did not start: " + self.log.read_text()[-300:])
        self.hostline = "[127.0.0.1]:%d %s\n" % (
            self.port, " ".join((d / "hostkey.pub").read_text().split()[:2]))

    def transport(self, known_hosts_text):
        path = token_file(self.tmp.name, known_hosts_text, name="known_hosts")
        with clean_env(PHORVEX_SSH_PASSWORD="unused-fixture-password"):
            transport = Transport({"kind": "ssh", "host": "127.0.0.1",
                                   "user": os.environ.get("USER") or os.getlogin(),
                                   "port": self.port, "known_hosts": path, "connect_timeout_sec": 5})
        return transport

    def run_with_home(self, transport, command, stdin=None):
        with patch.dict(os.environ, self.agent_env):
            return transport.run(command, timeout=20, stdin=stdin)

    def test_unknown_host_key_fails_before_any_authentication(self):
        # A provisioned file that names some other host: this host's key is unknown to it.
        rc, out, err = self.run_with_home(self.transport("[jump.example]:22 ssh-ed25519 AAAAfixture\n"),
                                          "echo reached")
        self.assertEqual(rc, 255, err)
        self.assertIn("Host key verification failed", err)
        self.assertNotIn("reached", out)
        self.assertNotIn("Accepted", self.log.read_text())

    def test_changed_host_key_fails(self):
        other = "[127.0.0.1]:%d %s\n" % (
            self.port, " ".join((Path(self.tmp.name) / "otherkey.pub").read_text().split()[:2]))
        rc, out, err = self.run_with_home(self.transport(other), "echo reached")
        self.assertEqual(rc, 255, err)
        self.assertIn("Host key verification failed", err)
        self.assertNotIn("reached", out)

    def test_the_provisioned_key_admits_the_command_and_its_stdin(self):
        transport = self.transport(self.hostline)
        rc, out, err = self.run_with_home(transport, "cat", stdin='header = "X: fixture"\n')
        self.assertEqual((rc, out), (0, 'header = "X: fixture"\n'), err)
        self.assertIn("Accepted publickey", self.log.read_text())


class RefusalProvenanceTests(FixtureCase):
    """R6: a refusal names what answered and what that does and does not prove."""

    class Proxy:
        kind = "local"

        def __init__(self, answers):
            self.answers, self.commands = answers, []

        def run(self, command, timeout=60, stdin=None):
            self.commands.append(command)
            for path, answer in self.answers.items():
                if path in command:
                    return answer
            raise AssertionError(command)

    LOGIN = (1, "", "error: You must be logged in to the server (the server has asked for "
                    "the client to provide credentials)\n")

    def test_a_proxied_401_is_attributed_by_the_same_path_health_read(self):
        proxy = self.Proxy({"/api/version": self.LOGIN, "/api/health": (0, '{"ok":true}\n', "")})
        with self.assertRaises(ConsoleAccessError) as caught:
            Console(proxy, {"mode": "kubectl-proxy"}).get_json("/api/version")
        message = str(caught.exception)
        self.assertIn("same-path public /api/health succeeded", message)
        self.assertIn("came from behind the proxy", message)
        self.assertIn("kubectl said: error: You must be logged in", message)
        self.assertNotIn("console authenticated", message)
        self.assertEqual(len([c for c in proxy.commands if "/api/health" in c]), 1)

    def test_a_proxied_401_with_failing_health_is_attributed_to_the_api_server_hop(self):
        proxy = self.Proxy({"/api/version": self.LOGIN, "/api/health": self.LOGIN})
        with self.assertRaises(ConsoleAccessError) as caught:
            Console(proxy, {"mode": "kubectl-proxy"}).get_json("/api/version")
        message = str(caught.exception)
        self.assertIn("also failed", message)
        self.assertIn("console's own answer is unknown", message)
        forbidden = (1, "", "Error from server (Forbidden): services \"phorvex-console:80\" is forbidden\n")
        proxy = self.Proxy({"/api/version": forbidden, "/api/health": forbidden})
        with self.assertRaisesRegex(ConsoleAccessError, "HTTP 403 on the kubectl-proxy path"):
            Console(proxy, {"mode": "kubectl-proxy"}).get_json("/api/version")

    def test_http_refusals_keep_endpoint_text_as_provenance_without_claiming_identity(self):
        console = self.console(token=self.server.token(CI_SUBJECT, ttl=-100))
        with self.assertRaises(ConsoleAccessError) as caught:
            console.get_json("/api/version")
        message = str(caught.exception)
        self.assertIn(f"HTTP 401 from {self.server.base}", message)
        self.assertIn("endpoint said: authentication required", message)
        self.assertIn("intermediary", message)
        console = self.console(subject="nobody-bound-me")
        with self.assertRaises(ConsoleAccessError) as caught:
            console.post_json("/api/workload/attack", {"namespace": "voice", "action": "foothold"})
        message = str(caught.exception)
        self.assertIn("HTTP 403", message)
        self.assertIn("not proof", message)
        self.assertNotIn("authenticated the caller", message)


class LongCredentialRedactionTests(unittest.TestCase):
    """R8: a credential reflected into any diagnostic is redacted BEFORE the text is bounded,
    so neither a prefix nor a suffix of it survives in what is retained."""

    def setUp(self):
        self.key = CF.RSAKey()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.transport = RecordingTransport()
        # Near the accepted maximum, and syntactically a token — never a real one.
        self.long_token = ("L" * 40 + ".") * (MAX_TOKEN_BYTES // 41 - 1)

    def console(self, server):
        with clean_env():
            return Console(self.transport, {"mode": "http", "base": server.base,
                                            "token_file": token_file(self.tmp.name, self.long_token)})

    def assert_no_fragment(self, text):
        self.assertNotIn(self.long_token, text)
        for fragment in fragments(self.long_token):
            self.assertNotIn(fragment, text)
        self.assertIn("[REDACTED]", text)

    def test_reflected_401_and_500_bodies_are_bounded_and_carry_no_fragment(self):
        server = CF.FixtureConsole(key=self.key, grants={}, reflect_credentials=True)
        self.addCleanup(server.close)
        console = self.console(server)
        with self.assertRaises(ConsoleAccessError) as caught:
            console.get_json("/api/version")               # a 401 whose body echoes the header
        self.assert_no_fragment(str(caught.exception))
        self.assertLess(len(str(caught.exception)), 900)
        server.grants = {CI_SUBJECT: CF.Grant(["operator"], ["voice"])}
        token_file(self.tmp.name, server.token(CI_SUBJECT))
        with self.assertRaises(TransportError) as caught:
            self.console(server).get_json("/api/echo-error")   # a 500 that reflects it
        self.assertNotIn(server.token(CI_SUBJECT)[:12], str(caught.exception))

    def test_reflected_stderr_carries_no_fragment(self):
        server = CF.FixtureConsole(key=self.key, grants={})
        self.addCleanup(server.close)
        console = self.console(server)
        noisy = ("x" * 400 + " " + self.long_token + " tail")
        with patch.object(self.transport, "run", return_value=(7, "", noisy)):
            with self.assertRaises(TransportError) as caught:
                console.get_json("/api/version")
        self.assert_no_fragment(str(caught.exception))
        # The stream path: a child that echoes its stdin configuration to stderr and dies.
        code = "import sys; sys.stderr.write('x' * 600 + sys.stdin.read() + ' tail'); sys.exit(22)"
        with self.assertRaises(TransportError) as caught:
            self.transport.capture_live(shlex.join(["python3", "-c", code]), 1, LIMITS,
                                        on_connected=lambda: None, stdin=console._stdin())
        self.assert_no_fragment(str(caught.exception))
        got = self.transport.capture_live(shlex.join(["python3", "-c", code]), 0.5, LIMITS,
                                          stdin=console._stdin())
        self.assertFalse(got.complete)
        self.assert_no_fragment(got.reason)


if __name__ == "__main__":
    unittest.main()
