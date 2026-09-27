"""Read-only, Pod-local enforcement of exact revoked Voice memory notes.

The operator owns the projected rule. This module has no mutation HTTP surface.
An empty optional projection preserves the existing bot until a rule is installed.
The normal activated rollout requires a rule before serving memory, including on
replacement Pods with a fresh ledger. Missing, corrupt, or replayed policy then
fails closed for memory. The ledger lives on a Pod emptyDir across bot restarts.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import secrets
import stat
import threading
import time
from typing import Any

RULE_KEYS = frozenset({"version", "deploymentUID", "policyUID", "sourceSHA256", "revision", "operationId", "entries"})
ENTRY_KEYS = frozenset({"callerId", "noteSHA256", "operationId"})
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
CALLER = re.compile(r"\+[1-9][0-9]{1,14}\Z")
UID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
MAX_RULE_BYTES = 8192
MAX_REVISION = (1 << 53) - 1


class PolicyError(ValueError):
    pass


def canonical_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError("duplicate policy key")
        result[key] = value
    return result


def parse_rule(raw: bytes, source_sha: str) -> dict[str, Any]:
    if not raw or len(raw) > MAX_RULE_BYTES:
        raise PolicyError("invalid policy length")
    try:
        rule = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PolicyError("invalid policy JSON") from exc
    if not isinstance(rule, dict) or frozenset(rule) != RULE_KEYS or canonical_bytes(rule) != raw:
        raise PolicyError("noncanonical policy schema")
    if type(rule["version"]) is not int or rule["version"] != 1:
        raise PolicyError("invalid policy version")
    if type(rule["revision"]) is not int or not 0 <= rule["revision"] <= MAX_REVISION:
        raise PolicyError("invalid policy revision")
    if not all(isinstance(rule[k], str) and UID.fullmatch(rule[k]) for k in ("deploymentUID", "policyUID")):
        raise PolicyError("invalid owner UID")
    if rule["sourceSHA256"] != source_sha:
        raise PolicyError("source identity mismatch")
    if not isinstance(rule["entries"], list) or len(rule["entries"]) > 32:
        raise PolicyError("invalid entry count")
    if rule["revision"] == 0:
        if rule["operationId"] != "" or rule["entries"]:
            raise PolicyError("invalid initial policy")
    elif not isinstance(rule["operationId"], str) or not HEX64.fullmatch(rule["operationId"]) or not rule["entries"]:
        raise PolicyError("invalid activated policy")
    pairs: list[tuple[str, str]] = []
    for entry in rule["entries"]:
        if not isinstance(entry, dict) or frozenset(entry) != ENTRY_KEYS:
            raise PolicyError("invalid entry schema")
        caller, digest, operation = entry["callerId"], entry["noteSHA256"], entry["operationId"]
        if not isinstance(caller, str) or not CALLER.fullmatch(caller):
            raise PolicyError("invalid caller")
        if not isinstance(digest, str) or not HEX64.fullmatch(digest):
            raise PolicyError("invalid note digest")
        if not isinstance(operation, str) or not HEX64.fullmatch(operation):
            raise PolicyError("invalid entry operation")
        pairs.append((caller, digest))
    if pairs != sorted(set(pairs)):
        raise PolicyError("entries must be sorted and unique")
    if rule["revision"] > 0 and rule["operationId"] not in {e["operationId"] for e in rule["entries"]}:
        raise PolicyError("latest operation has no entry")
    return rule


def source_sha256(bot_path: pathlib.Path, module_path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    digest.update(bot_path.read_bytes())
    digest.update(b"\x00")
    digest.update(module_path.read_bytes())
    return digest.hexdigest()


def note_sha256(note: str) -> str:
    return hashlib.sha256(note.encode("utf-8")).hexdigest()


def authorization_status(token_file: pathlib.Path, supplied: str) -> int:
    """Return 200, 401, or 503 without revealing the mounted credential."""
    try:
        token = token_file.read_bytes()
    except OSError:
        return 503
    if len(token) < 32 or len(token) > 256 or any(c < 33 or c > 126 for c in token):
        return 503
    expected = "Bearer " + token.decode("ascii")
    return 200 if secrets.compare_digest(supplied, expected) else 401


class VoiceMemoryPolicy:
    def __init__(self, policy_dir: pathlib.Path, state_dir: pathlib.Path, source_sha: str, pod_uid: str,
                 required: bool = False):
        self.policy_dir = pathlib.Path(policy_dir)
        self.state_dir = pathlib.Path(state_dir)
        self.source_sha = source_sha
        self.pod_uid = pod_uid
        self.required = required
        self._lock = threading.Lock()
        self._seen = False

    def _ledger_path(self) -> pathlib.Path:
        return self.state_dir / "ledger.json"

    def _load_ledger(self) -> dict[str, Any] | None:
        path = self._ledger_path()
        try:
            info = path.lstat()
        except FileNotFoundError:
            return None
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_RULE_BYTES:
            raise PolicyError("invalid policy ledger")
        try:
            value = json.loads(path.read_bytes().decode("utf-8"), object_pairs_hook=_unique_object)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise PolicyError("invalid policy ledger") from exc
        if not isinstance(value, dict) or frozenset(value) != {"revision", "ruleSHA256", "entries", "deploymentUID", "policyUID"}:
            raise PolicyError("invalid policy ledger")
        if type(value["revision"]) is not int or not 0 <= value["revision"] <= MAX_REVISION:
            raise PolicyError("invalid policy ledger")
        if not isinstance(value["ruleSHA256"], str) or not HEX64.fullmatch(value["ruleSHA256"]):
            raise PolicyError("invalid policy ledger")
        if not isinstance(value["entries"], list) or not isinstance(value["deploymentUID"], str) or not isinstance(value["policyUID"], str):
            raise PolicyError("invalid policy ledger")
        return value

    def _save_ledger(self, value: dict[str, Any]) -> None:
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.state_dir.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077:
            raise PolicyError("insecure policy state directory")
        path = self.state_dir / f"ledger.{os.getpid()}.tmp"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb") as out:
                out.write(canonical_bytes(value))
                out.flush()
                os.fsync(out.fileno())
            os.replace(path, self._ledger_path())
            directory = os.open(self.state_dir, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            try:
                path.unlink()
            except FileNotFoundError:
                pass

    def _read(self) -> tuple[dict[str, Any] | None, bool]:
        """Return (rule, fail_closed); never return partially parsed policy."""
        with self._lock:
            try:
                ledger = self._load_ledger()
                # Kubernetes projected keys are symlinks. One open pins one complete version.
                try:
                    with (self.policy_dir / "rule.json").open("rb") as stream:
                        raw = stream.read(MAX_RULE_BYTES + 1)
                except FileNotFoundError:
                    return None, self.required or ledger is not None or self._seen
                rule = parse_rule(raw, self.source_sha)
                digest = hashlib.sha256(raw).hexdigest()
                if ledger is not None:
                    if rule["deploymentUID"] != ledger["deploymentUID"] or rule["policyUID"] != ledger["policyUID"]:
                        raise PolicyError("owner identity drift")
                    if rule["revision"] < ledger["revision"] or (rule["revision"] == ledger["revision"] and digest != ledger["ruleSHA256"]):
                        raise PolicyError("policy replay or same-revision drift")
                    old = {(e["callerId"], e["noteSHA256"], e["operationId"]) for e in ledger["entries"]}
                    new = {(e["callerId"], e["noteSHA256"], e["operationId"]) for e in rule["entries"]}
                    if not old.issubset(new):
                        raise PolicyError("policy removed a revoked note")
                if ledger is None or rule["revision"] > ledger["revision"]:
                    self._save_ledger({"revision": rule["revision"], "ruleSHA256": digest, "entries": rule["entries"],
                                       "deploymentUID": rule["deploymentUID"], "policyUID": rule["policyUID"]})
                self._seen = True
                return rule, False
            except (PolicyError, OSError, TypeError, KeyError, ValueError):
                return None, True

    def filter_notes(self, caller_id: str, notes: list[Any]) -> list[dict[str, Any]]:
        rule, closed = self._read()
        if closed:
            return []
        if rule is None:
            return [n for n in notes if isinstance(n, dict) and isinstance(n.get("note"), str)]
        revoked = {(e["callerId"], e["noteSHA256"]) for e in rule["entries"]}
        return [n for n in notes if isinstance(n, dict) and isinstance(n.get("note"), str)
                and (caller_id, note_sha256(n["note"])) not in revoked]

    def allow_write(self, caller_id: str, note: str) -> bool:
        rule, closed = self._read()
        if closed:
            return False
        if rule is None:
            return True
        return (caller_id, note_sha256(note)) not in {(e["callerId"], e["noteSHA256"]) for e in rule["entries"]}

    def state(self) -> tuple[int, dict[str, Any]]:
        rule, closed = self._read()
        if closed or rule is None:
            return 503, {"version": 1, "podUID": self.pod_uid, "sourceSHA256": self.source_sha, "ready": False}
        return 200, {"version": 1, "podUID": self.pod_uid, "deploymentUID": rule["deploymentUID"],
                     "policyUID": rule["policyUID"], "sourceSHA256": self.source_sha,
                     "ruleSHA256": hashlib.sha256(canonical_bytes(rule)).hexdigest(), "revision": rule["revision"],
                     "operationId": rule["operationId"], "entryCount": len(rule["entries"]), "ready": True}

    def record_context(self, call_sid: str, caller_id: str, notes: list[dict[str, Any]]) -> bool:
        """Retain a private digest-only receipt after the real /ws context load.

        The run-owned call SID is never used as a path component. A missing
        state mount does not interrupt an ordinary Voice call; an experiment
        requiring this oracle must refuse if the receipt is absent.
        """
        if not self.state_dir.is_dir() or not isinstance(call_sid, str) or len(call_sid) > 128:
            return False
        try:
            info = self.state_dir.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077:
                return False
            receipt = {"version": 1, "callSIDHash": hashlib.sha256(call_sid.encode("utf-8")).hexdigest(),
                       "callerSHA256": hashlib.sha256(caller_id.encode("utf-8")).hexdigest(),
                       "noteSHA256": [note_sha256(n["note"]) for n in notes],
                       "sourceSHA256": self.source_sha, "podUID": self.pod_uid,
                       "observedAtUnixMs": int(time.time() * 1000)}
            key = hashlib.sha256(call_sid.encode("utf-8")).hexdigest()
            path = self.state_dir / ("context-" + key + ".json")
            temp = self.state_dir / ("context-" + key + ".tmp")
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                with os.fdopen(fd, "wb") as out:
                    out.write(canonical_bytes(receipt))
                    out.flush()
                    os.fsync(out.fileno())
                # Link creation refuses a repeated call SID; never replace the
                # first observed context receipt with a later forged session.
                os.link(temp, path, follow_symlinks=False)
                directory = os.open(self.state_dir, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            finally:
                try:
                    temp.unlink()
                except FileNotFoundError:
                    pass
            return True
        except (OSError, TypeError, UnicodeError, KeyError):
            return False
