#!/usr/bin/env python3
"""Resumable, fail-closed QA driver for the Console attack catalogue."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import stat
import sys
import threading
import time
from typing import Any, Mapping
from urllib.parse import quote, urlsplit


EXPECTED_CATALOGUE_SIZE = 192
TRIGGER_MODE = "reactive"
EXECUTION_MODE = "active"
TERMINAL_STATES = frozenset({"done", "error", "partial", "stopped", "cancelled"})
TOKEN_ENV = "PHORVEX_CONSOLE_TOKEN"
TOKEN_FILE_ENV = "PHORVEX_CONSOLE_TOKEN_FILE"
TOKEN_FD_ENV = "PHORVEX_CONSOLE_TOKEN_FD"
BASE_ENV = "PHORVEX_CONSOLE_BASE"
CA_ENV = "PHORVEX_CONSOLE_CA_FILE"
MAX_TOKEN_BYTES = 8192
MAX_RESPONSE_BYTES = 16 << 20
TOKEN_RE = re.compile(r"^[A-Za-z0-9._~+/-]+=*$")
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
DEFAULT_CATALOGUE = REPO_ROOT / "phorvex" / "internal" / "attackcatalog" / "catalog.json"


class QAError(RuntimeError):
    """A configuration, contract, or persistence error."""


class AccessError(QAError):
    """The Console rejected or could not safely receive the credential."""


class APIError(QAError):
    def __init__(self, message: str, *, status: int | None = None, response: Any = None):
        super().__init__(message)
        self.status = status
        self.response = response


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise QAError(f"invalid retained UTC timestamp {value!r}") from exc
    if parsed.tzinfo is None:
        raise QAError(f"retained timestamp {value!r} has no UTC offset")
    return parsed


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    raw = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        view = memoryview(raw)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def redact(value: Any, token: str) -> Any:
    """Keep server responses verbatim except for a reflected bearer credential."""
    if isinstance(value, str):
        return value.replace(token, "<redacted>") if token else value
    if isinstance(value, list):
        return [redact(item, token) for item in value]
    if isinstance(value, dict):
        return {
            (key.replace(token, "<redacted>") if token and isinstance(key, str) else key): redact(item, token)
            for key, item in value.items()
        }
    return value


def validate_token(raw: bytes | str, source: str) -> str:
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    if len(raw) > MAX_TOKEN_BYTES + 2:
        raise AccessError(f"Console token from {source} exceeds {MAX_TOKEN_BYTES} bytes")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise AccessError(f"Console token from {source} is not ASCII") from exc
    if text.endswith("\r\n"):
        text = text[:-2]
    elif text.endswith("\n"):
        text = text[:-1]
    if not text or "\n" in text or "\r" in text:
        raise AccessError(f"Console token from {source} must be exactly one non-empty line")
    if len(text) < 16 or not TOKEN_RE.fullmatch(text):
        raise AccessError(f"Console token from {source} is not a bounded RFC 6750 bearer value")
    return text


def read_private_token_file(path: str) -> str:
    expanded = Path(path).expanduser()
    try:
        info = expanded.stat()
    except OSError as exc:
        raise AccessError(f"Console token file {path} is not readable: {exc}") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        raise AccessError(f"Console token file {path} must be a private regular file (mode 0600)")
    if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
        raise AccessError(f"Console token file {path} is not owned by the current user")
    with expanded.open("rb") as stream:
        return validate_token(stream.read(MAX_TOKEN_BYTES + 3), f"file {path}")


def load_token(environ: Mapping[str, str]) -> tuple[str, str]:
    configured = [name for name in (TOKEN_ENV, TOKEN_FILE_ENV, TOKEN_FD_ENV) if environ.get(name)]
    if len(configured) != 1:
        raise AccessError(
            f"configure exactly one of {TOKEN_ENV}, {TOKEN_FILE_ENV}, or {TOKEN_FD_ENV}; "
            "the bearer value is never accepted on argv"
        )
    source = configured[0]
    if source == TOKEN_ENV:
        return validate_token(environ[source], f"${source}"), f"${source}"
    if source == TOKEN_FILE_ENV:
        return read_private_token_file(environ[source]), f"file from ${source}"
    try:
        fd_number = int(environ[source])
        duplicate = os.dup(fd_number)
    except (OSError, ValueError) as exc:
        raise AccessError(f"${source} must name an open readable file descriptor") from exc
    try:
        with os.fdopen(duplicate, "rb", closefd=True) as stream:
            raw = stream.read(MAX_TOKEN_BYTES + 3)
    except OSError as exc:
        raise AccessError(f"could not read Console token from fd {fd_number}: {exc}") from exc
    return validate_token(raw, f"fd from ${source}"), f"fd from ${source}"


@dataclass(frozen=True)
class HTTPResponse:
    status: int
    body: Any

    def retained(self) -> dict[str, Any]:
        return {"status": self.status, "body": self.body}


class ConsoleClient:
    def __init__(self, base: str, token: str, *, request_timeout: float, ca_file: str | None = None):
        try:
            parts = urlsplit(base)
            port = parts.port
        except ValueError as exc:
            raise QAError(f"invalid Console base URL: {exc}") from exc
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise QAError("Console base must be an HTTP(S) origin with an optional path prefix")
        if parts.username is not None or parts.password is not None or parts.query or parts.fragment:
            raise QAError("Console base must not contain userinfo, a query, or a fragment")
        if parts.scheme == "http":
            try:
                if not ipaddress.ip_address(parts.hostname).is_loopback:
                    raise QAError("plain HTTP is allowed only to a literal loopback address")
            except ValueError as exc:
                raise QAError("plain HTTP is allowed only to a literal loopback address") from exc
        self.scheme = parts.scheme
        self.host = parts.hostname
        self.port = port or (443 if parts.scheme == "https" else 80)
        self.prefix = parts.path.rstrip("/")
        self.token = token
        self.request_timeout = request_timeout
        self.ssl_context = ssl.create_default_context(cafile=ca_file) if parts.scheme == "https" else None

    def _connection(self) -> http.client.HTTPConnection:
        if self.scheme == "https":
            return http.client.HTTPSConnection(
                self.host, self.port, timeout=self.request_timeout, context=self.ssl_context
            )
        return http.client.HTTPConnection(self.host, self.port, timeout=self.request_timeout)

    def request(self, method: str, path: str, body: dict[str, Any] | None = None) -> HTTPResponse:
        if not path.startswith("/api/"):
            raise QAError(f"refusing non-API path {path!r}")
        raw_body = canonical_json(body) if body is not None else None
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.token}",
            "X-Phorvex-Lens": "operator",
        }
        if raw_body is not None:
            headers["Content-Type"] = "application/json"
        connection = self._connection()
        try:
            connection.request(method, self.prefix + path, body=raw_body, headers=headers)
            response = connection.getresponse()
            raw = response.read(MAX_RESPONSE_BYTES + 1)
        except (OSError, socket.timeout, http.client.HTTPException) as exc:
            raise APIError(f"{method} {path} failed before a complete HTTP response: {exc}") from exc
        finally:
            connection.close()
        if len(raw) > MAX_RESPONSE_BYTES:
            raise APIError(f"{method} {path} response exceeds {MAX_RESPONSE_BYTES} bytes", status=response.status)
        try:
            parsed = json.loads(raw) if raw else None
        except json.JSONDecodeError as exc:
            snippet = raw[:200].decode("utf-8", "replace").replace(self.token, "<redacted>")
            raise APIError(
                f"{method} {path} returned malformed JSON: {snippet!r}", status=response.status
            ) from exc
        parsed = redact(parsed, self.token)
        retained = HTTPResponse(response.status, parsed)
        if response.status in (401, 403):
            raise AccessError(f"{method} {path} was refused with HTTP {response.status}")
        if 300 <= response.status < 400:
            raise AccessError(f"{method} {path} returned redirect HTTP {response.status}; redirects are never followed")
        if response.status < 200 or response.status >= 300:
            raise APIError(
                f"{method} {path} returned HTTP {response.status}",
                status=response.status,
                response=retained.retained(),
            )
        if not isinstance(parsed, dict):
            raise APIError(f"{method} {path} must return one JSON object", status=response.status)
        return retained

    def catalog(self) -> HTTPResponse:
        return self.request("GET", "/api/catalog")

    def launch(self, catalogue_id: str) -> HTTPResponse:
        # Modes are server-owned preflight results, not caller-selected launch
        # fields. The strict terminal checks below bind them independently.
        return self.request("POST", "/api/catalog/launch", {"id": catalogue_id})

    def status(self, run_id: str) -> HTTPResponse:
        return self.request("GET", f"/api/runs/status?id={quote(run_id, safe='')}")

    def evidence(self, run_id: str) -> HTTPResponse:
        return self.request("GET", f"/api/runs/evidence?id={quote(run_id, safe='')}")

    def stop(self, run_id: str) -> HTTPResponse:
        return self.request("POST", "/api/runs/stop", {"id": run_id})


class OutputLock:
    def __init__(self, directory: Path):
        directory.mkdir(parents=True, exist_ok=True, mode=0o750)
        self.path = directory / ".lock"
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            os.close(self.fd)
            raise QAError(f"another QA driver owns {self.path}") from exc

    def close(self) -> None:
        if self.fd >= 0:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
            os.close(self.fd)
            self.fd = -1

    def __enter__(self) -> "OutputLock":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


class StateLedger:
    """Append raw observations first, then atomically materialize resumable state."""

    EVENT_TYPES = frozenset({
        "catalogue_snapshot",
        "attempt_started",
        "launch_response",
        "status_response",
        "evidence_response",
        "request_error",
        "cancellation_response",
        "attempt_finished",
    })
    MATERIALIZED_EVENT_TYPES = frozenset({
        "catalogue_snapshot",
        "attempt_started",
        "launch_response",
        "attempt_finished",
    })

    def __init__(self, directory: Path):
        self.directory = directory
        self.journal_path = directory / "attempts.jsonl"
        self.state_path = directory / "state.json"
        self.lock = threading.Lock()
        self.events = self._read_events()
        self.next_sequence = len(self.events) + 1
        self.state = self._rebuild()

    def _read_events(self) -> list[dict[str, Any]]:
        if not self.journal_path.exists():
            return []
        raw = self.journal_path.read_bytes()
        if raw and not raw.endswith(b"\n"):
            raise QAError(f"{self.journal_path} has an incomplete final JSONL record")
        events: list[dict[str, Any]] = []
        for line_number, line in enumerate(raw.splitlines(), 1):
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise QAError(f"{self.journal_path}:{line_number}: malformed JSON") from exc
            if not isinstance(event, dict) or event.get("sequence") != line_number:
                raise QAError(f"{self.journal_path}:{line_number}: non-contiguous event sequence")
            if (
                event.get("schema") != "phorvex.console-catalog-qa-event.v1"
                or event.get("type") not in self.EVENT_TYPES
                or not isinstance(event.get("at"), str)
            ):
                raise QAError(f"{self.journal_path}:{line_number}: unknown event schema or type")
            events.append(event)
        return events

    def _empty_state(self) -> dict[str, Any]:
        return {
            "schema": "phorvex.console-catalog-qa-state.v1",
            "updatedAt": utc_now(),
            "catalogue": {},
            "attempts": {},
        }

    def _rebuild(self) -> dict[str, Any]:
        state = self._empty_state()
        for event in self.events:
            try:
                self._apply(state, event)
            except (KeyError, TypeError, QAError) as exc:
                raise QAError(
                    f"{self.journal_path}:{event.get('sequence')}: invalid event payload: {exc}"
                ) from exc
        if self.events:
            atomic_json(self.state_path, state)
        return state

    @staticmethod
    def _find_attempt(state: dict[str, Any], catalogue_id: str, attempt_id: str) -> dict[str, Any]:
        for attempt in state["attempts"].get(catalogue_id, []):
            if attempt["attemptID"] == attempt_id:
                return attempt
        raise QAError(f"journal references unknown attempt {attempt_id} for {catalogue_id}")

    def _apply(self, state: dict[str, Any], event: dict[str, Any]) -> None:
        event_type = event.get("type")
        state["updatedAt"] = event["at"]
        if event_type == "catalogue_snapshot":
            catalogue = event["catalogue"]
            if not isinstance(catalogue, dict):
                raise QAError("catalogue snapshot is not an object")
            # The append-only journal retains the raw API response. Rewriting that
            # large response into state.json on every status poll would add no
            # resume information and would create avoidable I/O across 192 runs.
            state["catalogue"] = {key: value for key, value in catalogue.items() if key != "response"}
            return
        if event_type == "attempt_started":
            catalogue_id = event["catalogueID"]
            attempts = state["attempts"].setdefault(catalogue_id, [])
            if any(row["attemptID"] == event["attemptID"] for row in attempts):
                raise QAError(f"duplicate attempt ID {event['attemptID']}")
            attempts.append({
                "attemptID": event["attemptID"],
                "catalogueID": catalogue_id,
                "triggerMode": event["triggerMode"],
                "executionMode": event["executionMode"],
                "startedAt": event["at"],
                "phase": "starting",
                "runID": "",
                "launchVerified": False,
                "localVerdict": "",
                "reason": "",
                "retrySafe": False,
            })
            return
        if "catalogueID" not in event or "attemptID" not in event:
            return
        attempt = self._find_attempt(state, event["catalogueID"], event["attemptID"])
        if event_type == "launch_response":
            attempt.update({
                "phase": "polling",
                "runID": event["runID"],
                "launchedAt": event["at"],
                "launchVerified": event["verified"],
            })
        elif event_type == "status_response":
            attempt["lastStatusState"] = event.get("state", "")
        elif event_type == "attempt_finished":
            attempt.update({
                "phase": "finished",
                "finishedAt": event["at"],
                "localVerdict": event["localVerdict"],
                "reason": event["reason"],
                "retrySafe": event["retrySafe"],
                "bindings": event.get("bindings", {}),
            })

    def record(self, event_type: str, **fields: Any) -> dict[str, Any]:
        with self.lock:
            if event_type not in self.EVENT_TYPES:
                raise QAError(f"refusing unknown journal event type {event_type!r}")
            event = {
                "schema": "phorvex.console-catalog-qa-event.v1",
                "sequence": self.next_sequence,
                "at": utc_now(),
                "type": event_type,
                **fields,
            }
            raw = canonical_json(event) + b"\n"
            fd = os.open(self.journal_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                view = memoryview(raw)
                while view:
                    view = view[os.write(fd, view):]
                os.fsync(fd)
            finally:
                os.close(fd)
            self.events.append(event)
            self.next_sequence += 1
            self._apply(self.state, event)
            if event_type in self.MATERIALIZED_EVENT_TYPES:
                atomic_json(self.state_path, self.state)
            return event

    def attempts(self, catalogue_id: str) -> list[dict[str, Any]]:
        with self.lock:
            return json.loads(json.dumps(self.state["attempts"].get(catalogue_id, [])))


def load_repository_catalogue(path: Path) -> tuple[list[str], str]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise QAError(f"cannot read repository catalogue {path}: {exc}") from exc
    entries = document.get("entries") if isinstance(document, dict) else None
    if not isinstance(entries, list) or document.get("count") != EXPECTED_CATALOGUE_SIZE:
        raise QAError(f"repository catalogue must declare exactly {EXPECTED_CATALOGUE_SIZE} entries")
    ids: list[str] = []
    for position, entry in enumerate(entries, 1):
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str) or not entry["id"]:
            raise QAError(f"repository catalogue entry {position} has no exact ID")
        if entry.get("order") != position:
            raise QAError(f"repository catalogue entry {entry['id']} has order {entry.get('order')}, want {position}")
        ids.append(entry["id"])
    if len(ids) != EXPECTED_CATALOGUE_SIZE or len(set(ids)) != EXPECTED_CATALOGUE_SIZE:
        raise QAError(
            f"repository catalogue expected {EXPECTED_CATALOGUE_SIZE} unique IDs; "
            f"found {len(ids)} rows/{len(set(ids))} unique"
        )
    digest = hashlib.sha256(canonical_json(ids)).hexdigest()
    return ids, digest


def validate_api_catalogue(response: HTTPResponse, repository_ids: list[str]) -> dict[str, dict[str, Any]]:
    items = response.body.get("items") if isinstance(response.body, dict) else None
    if not isinstance(items, list):
        raise QAError("GET /api/catalog response has no items array")
    rows = [item for item in items if isinstance(item, dict) and item.get("launchKind") == "catalogue-entry"]
    ids = [row.get("catalogueID") for row in rows]
    if (
        len(rows) != EXPECTED_CATALOGUE_SIZE
        or any(not isinstance(value, str) or not value for value in ids)
        or len(set(ids)) != EXPECTED_CATALOGUE_SIZE
    ):
        raise QAError(
            f"Console catalogue expected {EXPECTED_CATALOGUE_SIZE} unique catalogue-entry IDs; "
            f"found {len(rows)} rows/{len(set(value for value in ids if isinstance(value, str)))} unique"
        )
    if any(
        not isinstance(row.get("catalogueOrder"), int)
        or isinstance(row.get("catalogueOrder"), bool)
        for row in rows
    ):
        raise QAError("Console catalogue orders must be integers in the exact range 1..192")
    ordered = sorted(rows, key=lambda row: row.get("catalogueOrder", 0))
    if [row.get("catalogueOrder") for row in ordered] != list(range(1, EXPECTED_CATALOGUE_SIZE + 1)):
        raise QAError("Console catalogue orders are not the exact contiguous range 1..192")
    api_ids = [row["catalogueID"] for row in ordered]
    if api_ids != repository_ids:
        missing = sorted(set(repository_ids) - set(api_ids))
        extra = sorted(set(api_ids) - set(repository_ids))
        raise QAError(f"repository/API catalogue ID mismatch (missing={missing}, extra={extra})")
    return {row["catalogueID"]: row for row in ordered}


def positive_prometheus_delta(metric: dict[str, Any], *, mode: str | None = None) -> bool:
    deltas = metric.get("deltas")
    if not isinstance(deltas, list):
        return False
    for delta in deltas:
        if not isinstance(delta, dict) or delta.get("finalPresent") is not True or delta.get("counterReset") is True:
            continue
        value = delta.get("delta")
        labels = delta.get("labels")
        if not isinstance(value, (int, float)) or value <= 0 or not isinstance(labels, dict):
            continue
        if mode is None or labels.get("mode") == mode:
            return True
    return False


def physical_oracle_valid(physical: Any, signal_row: Any) -> bool:
    if not isinstance(physical, dict) or physical.get("validated") is not True or len(physical) <= 1:
        return False
    if "podUID" in physical and not (
        isinstance(signal_row, dict)
        and bool(physical.get("podUID"))
        and physical.get("podUID") == signal_row.get("targetUID")
    ):
        return False

    if physical.get("kind") == "app-action-denied-two-sided":
        detail = physical.get("evidence")
        observations = physical.get("observations")
        return (
            physical.get("oracle") == "agent-action-deny-enforcement-v1"
            and physical.get("podRetained") is True
            and isinstance(detail, dict)
            and detail.get("schema") == "agent-action-deny-enforcement-v1"
            and detail.get("validated") is True
            and detail.get("deniedBefore") is False
            and detail.get("deniedAfter") is True
            and detail.get("benignAllowedAfter") is True
            and detail.get("surgicalAllowedAfter") is True
            and detail.get("servingSetRetained") is True
            and all(bool(detail.get(key)) for key in ("guardUID", "podUID", "serviceUID"))
            and detail.get("podUID") == physical.get("podUID")
            and isinstance(observations, list)
            and len(observations) >= 3
            and all(isinstance(row, dict) and row.get("passed") is True for row in observations)
            and {"abusive_action_blocked", "benign_action_preserved", "peer_unchanged"}
            <= {row.get("name") for row in observations}
        )

    if "oldServiceAccountUID" in physical or "newServiceAccountUID" in physical:
        if not (
            bool(physical.get("oldServiceAccountUID"))
            and bool(physical.get("newServiceAccountUID"))
            and physical.get("oldServiceAccountUID") != physical.get("newServiceAccountUID")
        ):
            return False
    if "credentialAuthenticatedBefore" in physical and physical.get("credentialAuthenticatedBefore") is not True:
        return False
    if "credentialAuthenticatedAfter" in physical and physical.get("credentialAuthenticatedAfter") is not False:
        return False
    if "podRetained" in physical and physical.get("podRetained") is not True:
        return False
    return True


def evaluate_strict_pass(
    catalogue_id: str,
    run_id: str,
    status: Any,
    evidence: Any,
) -> tuple[bool, list[str], dict[str, bool]]:
    reasons: list[str] = []
    bindings = {
        "exactCatalogueID": False,
        "exactRunID": False,
        "reactiveTriggerMode": False,
        "activeExecutionMode": False,
        "terminalConsoleResult": False,
        "prometheusEvidence": False,
        "physicalOracle": False,
        "verifiedCleanup": False,
    }
    if not isinstance(status, dict):
        return False, ["run status is not a JSON object"], bindings
    if status.get("id") == run_id and status.get("config") == catalogue_id:
        bindings["exactRunID"] = True
        bindings["exactCatalogueID"] = True
    else:
        reasons.append("terminal status does not bind the exact run and catalogue IDs")
    if status.get("state") != "done" or status.get("executionKind") != "catalogue-validation":
        reasons.append("run is not a done catalogue-validation terminal")
    if status.get("triggerMode") != TRIGGER_MODE:
        reasons.append("terminal status does not bind reactive trigger mode")
    if status.get("executionMode") != EXECUTION_MODE:
        reasons.append("terminal status does not bind active execution mode")
    if status.get("outcome") != "DEFENDED":
        reasons.append("Console terminal outcome is not DEFENDED")
    if status.get("unsafeToRetry") is True or status.get("cleanupStatus") != "verified":
        reasons.append("terminal status does not bind verified cleanup")

    if not isinstance(evidence, dict):
        return False, reasons + ["run evidence is not a JSON object"], bindings
    if evidence.get("id") != run_id or evidence.get("state") != "done":
        reasons.append("run evidence does not bind the exact done run")
    result = evidence.get("attackCatalogueResult")
    prometheus = evidence.get("prometheusEvidence")
    if not isinstance(result, dict):
        reasons.append("typed Console catalogue result is absent")
        result = {}
    if result.get("catalogueID") == catalogue_id and result.get("runID") == run_id:
        bindings["exactCatalogueID"] = bindings["exactCatalogueID"] and True
        bindings["exactRunID"] = bindings["exactRunID"] and True
    else:
        bindings["exactCatalogueID"] = False
        bindings["exactRunID"] = False
        reasons.append("typed Console result does not bind exact catalogue/run IDs")
    if result.get("triggerMode") == TRIGGER_MODE and result.get("reactiveOnly") is True:
        bindings["reactiveTriggerMode"] = True
    else:
        reasons.append("typed Console result does not independently bind reactive trigger mode")
    if result.get("executionMode") == EXECUTION_MODE:
        bindings["activeExecutionMode"] = True
    else:
        reasons.append("typed Console result does not independently bind active execution mode")
    if (
        result.get("schema") == "phorvex.attack-catalogue-result.v1"
        and result.get("visible") is True
        and result.get("available") is True
        and result.get("launched") is True
        and result.get("verdict") == "DEFENDED"
        and result.get("unsafeToRetry") is not True
    ):
        bindings["terminalConsoleResult"] = True
    else:
        reasons.append("typed Console result is not a strict available/launched DEFENDED result")
    signal_row = result.get("signal")
    decision = result.get("decision")
    actuator = result.get("actuator")
    expected_action = result.get("expectedAction")
    if not (
        isinstance(signal_row, dict)
        and signal_row.get("created") is True
        and signal_row.get("observed") is True
        and signal_row.get("uid")
        and signal_row.get("targetUID")
        and isinstance(decision, dict)
        and decision.get("observed") is True
        and decision.get("selected") is True
        and decision.get("feasible") is True
        and decision.get("dispatchOutcome") == "emitted"
        and expected_action
        and decision.get("action") == expected_action
        and isinstance(actuator, dict)
        and actuator.get("receiptObserved") is True
        and actuator.get("handler") == expected_action
    ):
        reasons.append("exact signal, selected decision, and actuator receipt chain is incomplete")
    if physical_oracle_valid(result.get("physicalValidation"), signal_row):
        bindings["physicalOracle"] = True
    else:
        reasons.append("physical oracle is absent or unvalidated")
    cleanup = result.get("cleanup")
    cleanup_ok = (
        isinstance(cleanup, dict)
        and cleanup.get("attempted") is True
        and cleanup.get("verified") is True
        and all(cleanup.get(key) is True for key in ("eventDeleted", "markerDeleted") if key in cleanup)
    )
    if cleanup_ok:
        bindings["verifiedCleanup"] = True
    else:
        reasons.append("exact cleanup was not attempted and verified")

    if not isinstance(prometheus, dict):
        reasons.append("Prometheus evidence is absent")
    else:
        metrics = prometheus.get("metrics")
        selected = next(
            (metric for metric in metrics or [] if isinstance(metric, dict) and metric.get("key") == "selected-action"),
            {},
        )
        accepted = next(
            (metric for metric in metrics or [] if isinstance(metric, dict) and metric.get("key") == "accepted-actuation"),
            {},
        )
        trusted = next(
            (metric for metric in metrics or [] if isinstance(metric, dict) and metric.get("key") == "trusted-events"),
            {},
        )
        prom_ok = (
            prometheus.get("schema") == "phorvex.prometheus-run-evidence.v1"
            and prometheus.get("runID") == run_id
            and prometheus.get("catalogueID") == catalogue_id
            and prometheus.get("triggerMode") == TRIGGER_MODE
            and prometheus.get("executionMode") == EXECUTION_MODE
            and prometheus.get("status") == "COMPLETE"
            and prometheus.get("errors") in (None, [])
            and prometheus.get("observedDecisionModes") == [EXECUTION_MODE]
            and positive_prometheus_delta(selected, mode=EXECUTION_MODE)
            and positive_prometheus_delta(accepted)
            and positive_prometheus_delta(trusted)
        )
        if prom_ok:
            bindings["prometheusEvidence"] = True
        else:
            reasons.append("Prometheus evidence is not complete, exact-mode, and positive-delta bound")
    return not reasons and all(bindings.values()), reasons, bindings


class Driver:
    def __init__(self, args: argparse.Namespace, client: ConsoleClient, ledger: StateLedger):
        self.args = args
        self.client = client
        self.ledger = ledger
        self.cancelled = threading.Event()

    def request_cancel(self) -> None:
        self.cancelled.set()

    def _finish(
        self,
        catalogue_id: str,
        attempt_id: str,
        verdict: str,
        reason: str,
        retry_safe: bool,
        bindings: dict[str, bool] | None = None,
    ) -> dict[str, Any]:
        self.ledger.record(
            "attempt_finished",
            catalogueID=catalogue_id,
            attemptID=attempt_id,
            localVerdict=verdict,
            reason=reason,
            retrySafe=retry_safe,
            bindings=bindings or {},
        )
        return self.ledger.attempts(catalogue_id)[-1]

    def _record_error(self, catalogue_id: str, attempt_id: str, phase: str, exc: Exception) -> None:
        fields: dict[str, Any] = {
            "catalogueID": catalogue_id,
            "attemptID": attempt_id,
            "phase": phase,
            "error": str(exc),
        }
        if isinstance(exc, APIError) and exc.response is not None:
            fields["response"] = exc.response
        self.ledger.record("request_error", **fields)

    def _stop(self, catalogue_id: str, attempt_id: str, run_id: str, cause: str) -> None:
        try:
            response = self.client.stop(run_id)
            self.ledger.record(
                "cancellation_response",
                catalogueID=catalogue_id,
                attemptID=attempt_id,
                runID=run_id,
                cause=cause,
                response=response.retained(),
            )
        except Exception as exc:  # retained as evidence; cancellation remains fail-closed
            self._record_error(catalogue_id, attempt_id, "stop", exc)

    @staticmethod
    def _retry_safe(status: Any, evidence: Any) -> bool:
        if isinstance(status, dict) and status.get("unsafeToRetry") is True:
            return False
        if isinstance(evidence, dict):
            result = evidence.get("attackCatalogueResult")
            if isinstance(result, dict):
                cleanup = result.get("cleanup")
                return (
                    result.get("unsafeToRetry") is not True
                    and isinstance(cleanup, dict)
                    and cleanup.get("verified") is True
                )
        return isinstance(status, dict) and status.get("cleanupStatus") == "verified"

    def _terminal_evidence(
        self,
        catalogue_id: str,
        attempt_id: str,
        run_id: str,
        deadline: datetime,
    ) -> Any:
        """Poll through transient evidence-read failures without extending the per-ID deadline."""
        first = True
        while first or datetime.now(timezone.utc) < deadline:
            first = False
            try:
                response = self.client.evidence(run_id)
                self.ledger.record(
                    "evidence_response",
                    catalogueID=catalogue_id,
                    attemptID=attempt_id,
                    runID=run_id,
                    response=response.retained(),
                )
                return response.body
            except AccessError:
                self.cancelled.set()
                raise
            except Exception as exc:
                self._record_error(catalogue_id, attempt_id, "evidence", exc)
            remaining = max(0.0, (deadline - datetime.now(timezone.utc)).total_seconds())
            if remaining <= 0:
                break
            self.cancelled.wait(min(self.args.poll_interval_seconds, remaining))
        return None

    def _poll(self, catalogue_id: str, attempt: dict[str, Any]) -> dict[str, Any]:
        attempt_id, run_id = attempt["attemptID"], attempt["runID"]
        launched_at = parse_time(attempt.get("launchedAt", attempt["startedAt"]))
        deadline = launched_at + timedelta(seconds=self.args.timeout_seconds)
        last_status: Any = None
        last_evidence: Any = None
        cause = ""
        while True:
            if self.cancelled.is_set():
                cause = "operator cancellation"
                break
            if datetime.now(timezone.utc) >= deadline:
                cause = f"per-ID timeout after {self.args.timeout_seconds:g}s"
                break
            try:
                response = self.client.status(run_id)
                last_status = response.body
                self.ledger.record(
                    "status_response",
                    catalogueID=catalogue_id,
                    attemptID=attempt_id,
                    runID=run_id,
                    state=last_status.get("state", ""),
                    response=response.retained(),
                )
                if last_status.get("id") != run_id:
                    self._stop(catalogue_id, attempt_id, run_id, "status run-ID mismatch")
                    return self._finish(
                        catalogue_id, attempt_id, "FAIL", "status returned a different run ID", False
                    )
                if last_status.get("state") in TERMINAL_STATES:
                    break
            except AccessError:
                self.cancelled.set()
                raise
            except Exception as exc:
                self._record_error(catalogue_id, attempt_id, "status", exc)
            remaining = max(0.0, (deadline - datetime.now(timezone.utc)).total_seconds())
            self.cancelled.wait(min(self.args.poll_interval_seconds, remaining))

        if cause:
            self._stop(catalogue_id, attempt_id, run_id, cause)
            cancel_deadline = time.monotonic() + self.args.cancel_grace_seconds
            while time.monotonic() < cancel_deadline:
                try:
                    response = self.client.status(run_id)
                    last_status = response.body
                    self.ledger.record(
                        "status_response",
                        catalogueID=catalogue_id,
                        attemptID=attempt_id,
                        runID=run_id,
                        state=last_status.get("state", ""),
                        response=response.retained(),
                    )
                    if last_status.get("state") in TERMINAL_STATES:
                        break
                except Exception as exc:
                    self._record_error(catalogue_id, attempt_id, "status-after-stop", exc)
                time.sleep(min(self.args.poll_interval_seconds, max(0.0, cancel_deadline - time.monotonic())))

        if isinstance(last_status, dict) and last_status.get("state") in TERMINAL_STATES:
            last_evidence = self._terminal_evidence(
                catalogue_id, attempt_id, run_id, deadline if not cause else datetime.now(timezone.utc)
            )

        retry_safe = self._retry_safe(last_status, last_evidence)
        if cause:
            verdict = "CANCELLED" if cause == "operator cancellation" else "TIMEOUT"
            return self._finish(catalogue_id, attempt_id, verdict, cause, retry_safe)
        passed, reasons, bindings = evaluate_strict_pass(catalogue_id, run_id, last_status, last_evidence)
        return self._finish(
            catalogue_id,
            attempt_id,
            "PASS" if passed else "FAIL",
            "strict terminal record passed" if passed else "; ".join(reasons),
            retry_safe,
            bindings,
        )

    def run_id(self, catalogue_id: str) -> dict[str, Any]:
        attempts = self.ledger.attempts(catalogue_id)
        if attempts and attempts[-1]["localVerdict"] == "PASS":
            return attempts[-1]
        if attempts and attempts[-1]["phase"] != "finished":
            active = attempts[-1]
            if not active.get("runID") or not active.get("launchVerified"):
                return self._finish(
                    catalogue_id,
                    active["attemptID"],
                    "BLOCKED",
                    "unfinished launch has no verified run identity; automatic replay could duplicate mutation",
                    False,
                )
            return self._poll(catalogue_id, active)
        if attempts and not attempts[-1].get("retrySafe", False):
            return attempts[-1]
        attempt_id = f"{catalogue_id}#{len(attempts) + 1:04d}"
        self.ledger.record(
            "attempt_started",
            catalogueID=catalogue_id,
            attemptID=attempt_id,
            triggerMode=TRIGGER_MODE,
            executionMode=EXECUTION_MODE,
        )
        if self.cancelled.is_set():
            return self._finish(catalogue_id, attempt_id, "CANCELLED", "operator cancellation", True)
        try:
            response = self.client.launch(catalogue_id)
        except AccessError:
            self.cancelled.set()
            raise
        except APIError as exc:
            self._record_error(catalogue_id, attempt_id, "launch", exc)
            if exc.status is not None and 400 <= exc.status < 500:
                return self._finish(
                    catalogue_id,
                    attempt_id,
                    "FAIL",
                    f"launch was rejected with HTTP {exc.status}",
                    True,
                )
            return self._finish(
                catalogue_id,
                attempt_id,
                "BLOCKED",
                "launch did not return a complete success response; mutation outcome is ambiguous",
                False,
            )
        except Exception as exc:
            self._record_error(catalogue_id, attempt_id, "launch", exc)
            return self._finish(
                catalogue_id,
                attempt_id,
                "BLOCKED",
                "launch did not return a complete response; mutation outcome is ambiguous",
                False,
            )
        body = response.body
        run_id = body.get("id") if isinstance(body, dict) else None
        verified = (
            isinstance(run_id, str)
            and bool(run_id)
            and body.get("catalogueID") == catalogue_id
        )
        self.ledger.record(
            "launch_response",
            catalogueID=catalogue_id,
            attemptID=attempt_id,
            runID=run_id or "",
            verified=verified,
            response=response.retained(),
        )
        if not verified:
            if isinstance(run_id, str) and run_id:
                self._stop(catalogue_id, attempt_id, run_id, "launch binding mismatch")
            return self._finish(
                catalogue_id,
                attempt_id,
                "FAIL",
                "launch response did not bind the exact catalogue and run IDs",
                False,
            )
        return self._poll(catalogue_id, self.ledger.attempts(catalogue_id)[-1])


def read_requested_ids(args: argparse.Namespace) -> list[str]:
    values = list(args.ids)
    for path in args.ids_file:
        try:
            lines = Path(path).read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise QAError(f"cannot read requested-ID file {path}: {exc}") from exc
        values.extend(line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#"))
    if not values:
        raise QAError("at least one explicit --id or --ids-file entry is required")
    if any(value.strip() != value or not value for value in values):
        raise QAError("requested catalogue IDs must be non-empty exact strings without outer whitespace")
    if len(values) != len(set(values)):
        raise QAError("requested catalogue IDs contain duplicates")
    return values


def latest_results(ledger: StateLedger, ids: list[str], dry_run: bool, availability: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for catalogue_id in ids:
        attempts = ledger.attempts(catalogue_id)
        if attempts:
            latest = attempts[-1]
            results.append({
                "catalogueID": catalogue_id,
                "localVerdict": latest["localVerdict"] or latest["phase"].upper(),
                "reason": latest.get("reason", ""),
                "attempts": len(attempts),
                "runID": latest.get("runID", ""),
                "retrySafe": latest.get("retrySafe", False),
                "bindings": latest.get("bindings", {}),
            })
        else:
            row = availability[catalogue_id]
            results.append({
                "catalogueID": catalogue_id,
                "localVerdict": "DRY_RUN" if dry_run and row.get("available") is True else "UNAVAILABLE",
                "reason": "would launch" if row.get("available") is True else row.get("unavailableReason", "not available"),
                "attempts": 0,
                "runID": "",
                "retrySafe": False,
                "bindings": {},
            })
    return results


def write_outputs(
    output: Path,
    *,
    requested: list[str],
    repository_digest: str,
    results: list[dict[str, Any]],
    dry_run: bool,
) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for result in results:
        counts[result["localVerdict"]] = counts.get(result["localVerdict"], 0) + 1
    summary = {
        "schema": "phorvex.console-catalog-qa-summary.v1",
        "generatedAt": utc_now(),
        "dryRun": dry_run,
        "catalogue": {
            "expected": EXPECTED_CATALOGUE_SIZE,
            "unique": EXPECTED_CATALOGUE_SIZE,
            "sha256": repository_digest,
            "repositoryAPIMatch": True,
        },
        "triggerMode": TRIGGER_MODE,
        "executionMode": EXECUTION_MODE,
        "requestedIDs": requested,
        "counts": counts,
        "allPassed": bool(results) and all(row["localVerdict"] == "PASS" for row in results),
        "results": results,
    }
    atomic_json(output / "summary.json", summary)
    lines = [
        "# Console catalogue QA report",
        "",
        f"Generated: `{summary['generatedAt']}`  ",
        f"Catalogue: `{EXPECTED_CATALOGUE_SIZE}` exact unique IDs (repository/API match)  ",
        f"Modes: trigger `{TRIGGER_MODE}`; execution `{EXECUTION_MODE}`  ",
        f"Result: `{'DRY RUN' if dry_run else ('PASS' if summary['allPassed'] else 'NOT PASSING')}`",
        "",
        "| Catalogue ID | Local verdict | Attempts | Run | Reason |",
        "|---|---:|---:|---|---|",
    ]
    for row in results:
        reason = str(row["reason"]).replace("|", "\\|").replace("\n", " ")
        lines.append(
            f"| `{row['catalogueID']}` | {row['localVerdict']} | {row['attempts']} | "
            f"`{row['runID'] or '-'}` | {reason} |"
        )
    lines.extend(["", "Raw server responses and every failed attempt are retained append-only in `attempts.jsonl`.", ""])
    report_path = output / "report.md"
    temporary = report_path.with_name(f".{report_path.name}.{os.getpid()}.tmp")
    temporary.write_text("\n".join(lines), encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, report_path)
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", help=f"Console base URL (or ${BASE_ENV})")
    parser.add_argument("--catalog-file", type=Path, default=DEFAULT_CATALOGUE)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--id", dest="ids", action="append", default=[], help="exact available catalogue ID; repeatable")
    parser.add_argument("--ids-file", action="append", default=[], help="newline-delimited exact IDs")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--timeout-seconds", type=float, default=600.0)
    parser.add_argument("--request-timeout-seconds", type=float, default=20.0)
    parser.add_argument("--poll-interval-seconds", type=float, default=2.0)
    parser.add_argument("--cancel-grace-seconds", type=float, default=30.0)
    parser.add_argument("--ca-file", help=f"private CA bundle (or ${CA_ENV})")
    return parser


def main(argv: list[str] | None = None, environ: Mapping[str, str] | None = None) -> int:
    environ = os.environ if environ is None else environ
    parser = build_parser()
    args = parser.parse_args(argv)
    if not 1 <= args.concurrency <= 16:
        parser.error("--concurrency must be between 1 and 16")
    for name in ("timeout_seconds", "request_timeout_seconds", "poll_interval_seconds", "cancel_grace_seconds"):
        if getattr(args, name) <= 0:
            parser.error(f"--{name.replace('_', '-')} must be positive")
    try:
        requested_input = read_requested_ids(args)
        repository_ids, digest = load_repository_catalogue(args.catalog_file.resolve())
        unknown = sorted(set(requested_input) - set(repository_ids))
        if unknown:
            raise QAError(f"requested IDs are absent from the exact repository catalogue: {unknown}")
        order = {catalogue_id: position for position, catalogue_id in enumerate(repository_ids)}
        requested = sorted(requested_input, key=order.__getitem__)
        token, _token_source = load_token(environ)
        base = args.base_url or environ.get(BASE_ENV)
        if not base:
            raise QAError(f"Console base URL is required via --base-url or ${BASE_ENV}")
        ca_file = args.ca_file or environ.get(CA_ENV)
        client = ConsoleClient(
            base,
            token,
            request_timeout=args.request_timeout_seconds,
            ca_file=ca_file,
        )
        output = args.output.resolve()
        with OutputLock(output):
            ledger = StateLedger(output)
            catalog_response = client.catalog()
            api_rows = validate_api_catalogue(catalog_response, repository_ids)
            ledger.record(
                "catalogue_snapshot",
                catalogue={
                    "count": EXPECTED_CATALOGUE_SIZE,
                    "unique": EXPECTED_CATALOGUE_SIZE,
                    "sha256": digest,
                    "repositoryPath": str(args.catalog_file.resolve()),
                    "repositoryAPIMatch": True,
                    "response": catalog_response.retained(),
                },
            )
            unavailable = [
                catalogue_id
                for catalogue_id in requested
                if api_rows[catalogue_id].get("available") is not True
                or api_rows[catalogue_id].get("reactiveCompatible") is not True
            ]
            if unavailable or args.dry_run:
                results = latest_results(ledger, requested, args.dry_run, api_rows)
                summary = write_outputs(
                    output,
                    requested=requested,
                    repository_digest=digest,
                    results=results,
                    dry_run=args.dry_run,
                )
                if unavailable:
                    print(f"selected IDs are not available for reactive launch: {', '.join(unavailable)}", file=sys.stderr)
                    return 2
                print(json.dumps({"dryRun": True, "requested": len(requested), "counts": summary["counts"]}, sort_keys=True))
                return 0

            driver = Driver(args, client, ledger)
            old_handlers: dict[int, Any] = {}
            if threading.current_thread() is threading.main_thread():
                def handle_signal(_signum: int, _frame: Any) -> None:
                    driver.request_cancel()

                for signum in (signal.SIGINT, signal.SIGTERM):
                    old_handlers[signum] = signal.getsignal(signum)
                    signal.signal(signum, handle_signal)
            try:
                with ThreadPoolExecutor(max_workers=min(args.concurrency, len(requested))) as pool:
                    futures = {pool.submit(driver.run_id, catalogue_id): catalogue_id for catalogue_id in requested}
                    for future in as_completed(futures):
                        catalogue_id = futures[future]
                        try:
                            result = future.result()
                            print(f"{catalogue_id}: {result.get('localVerdict') or result.get('phase')}", flush=True)
                        except AccessError:
                            driver.request_cancel()
                            raise
            finally:
                for signum, handler in old_handlers.items():
                    signal.signal(signum, handler)
            results = latest_results(ledger, requested, False, api_rows)
            summary = write_outputs(
                output,
                requested=requested,
                repository_digest=digest,
                results=results,
                dry_run=False,
            )
            print(json.dumps({"allPassed": summary["allPassed"], "counts": summary["counts"]}, sort_keys=True))
            if driver.cancelled.is_set() and not summary["allPassed"]:
                return 130
            return 0 if summary["allPassed"] else 2
    except (QAError, OSError) as exc:
        print(f"console-catalog-qa: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
