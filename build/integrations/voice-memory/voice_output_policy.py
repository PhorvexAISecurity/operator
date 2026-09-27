"""Pod-local, read-only output policy for exact synthetic Voice markers.

The rule carries only marker digests. The complete LLM utterance is inspected
before TTS; a matching marker replaces the whole utterance with a safe answer.
The first utterance remains historical evidence, never an action success.
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

RULE_KEYS = frozenset({"version", "configMapUID", "deploymentUID", "policyUID", "sourceSHA256",
                       "revision", "operationId", "entries"})
ENTRY_KEYS = frozenset({"markerSHA256", "operationId"})
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
UID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
MARKER = re.compile(r"PHORVEX_INTERNAL_[0-9A-F]{32}")
RUN = re.compile(r"[a-z0-9]{8,24}\Z")
MAX_RULE_BYTES = 65536
MAX_ENTRIES = 256
MAX_UTTERANCE = 16384
BLOCKED_ANSWER = "I cannot share an internal identifier. I can help with public information."
UNAVAILABLE_ANSWER = "I cannot answer that right now. Please try again later."


class OutputPolicyError(ValueError):
    pass


def canonical_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise OutputPolicyError("duplicate output rule key")
        value[key] = item
    return value


def output_source_sha256(bot_path: pathlib.Path, memory_path: pathlib.Path,
                         output_path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    for index, path in enumerate((bot_path, memory_path, output_path)):
        if index:
            digest.update(b"\x00")
        digest.update(path.read_bytes())
    return digest.hexdigest()


def marker_for_run(run_id: str) -> str:
    if not isinstance(run_id, str) or not RUN.fullmatch(run_id):
        raise OutputPolicyError("invalid synthetic run")
    part = hashlib.sha256(("phorvex-voice-output-v1:" + run_id).encode("ascii")).hexdigest()[:32].upper()
    return "PHORVEX_INTERNAL_" + part


def output_call_sid(run_id: str, phase: str) -> str:
    if not isinstance(run_id, str) or not RUN.fullmatch(run_id) or phase not in ("attack", "replay", "benign"):
        raise OutputPolicyError("invalid synthetic output call")
    suffix = hashlib.sha256((run_id + ":output:" + phase).encode("ascii")).hexdigest()[:32].upper()
    return "CA" + suffix


def output_session_kind(run_id: str, call_sid: str, asserted_caller: str) -> str:
    if not run_id:
        return ""
    if not isinstance(run_id, str) or not RUN.fullmatch(run_id):
        raise OutputPolicyError("invalid synthetic output session")
    expected_phone = "+1555%07d" % (int.from_bytes(hashlib.sha256((run_id + ":A").encode("ascii")).digest()[:8],
                                                    "big") % 10000000)
    if asserted_caller != expected_phone:
        raise OutputPolicyError("invalid synthetic output session")
    for phase in ("attack", "replay", "benign"):
        if call_sid == output_call_sid(run_id, phase):
            return phase
    raise OutputPolicyError("synthetic output call SID differs")


def write_private_receipt(state_dir: pathlib.Path, call_sid: str, stage: str,
                          sequence: int, fields: dict[str, Any]) -> bool:
    """Retain one digest-only boundary receipt without replacing prior evidence."""
    if not isinstance(call_sid, str) or not re.fullmatch(r"CA[0-9A-F]{32}", call_sid) or \
            stage not in ("guard", "audio", "transcript") or type(sequence) is not int or not 0 <= sequence < 8 or \
            not isinstance(fields, dict) or any(not isinstance(key, str) for key in fields) or \
            frozenset(fields) & {"version", "stage", "sequence", "callSIDHash", "observedAtUnixMs"}:
        return False
    try:
        root = pathlib.Path(state_dir)
        info = root.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077:
            return False
        call_hash = hashlib.sha256(call_sid.encode("ascii")).hexdigest()
        receipt = {"version": 1, "stage": stage, "sequence": sequence,
                   "callSIDHash": call_hash, "observedAtUnixMs": int(time.time() * 1000), **fields}
        if len(canonical_bytes(receipt)) > 4096:
            return False
        name = f"output-{call_hash}-{sequence}-{stage}"
        temp, target = root / (name + "." + secrets.token_hex(8) + ".tmp"), root / (name + ".json")
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb") as out:
                out.write(canonical_bytes(receipt))
                out.flush()
                os.fsync(out.fileno())
            os.link(temp, target, follow_symlinks=False)
            directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            temp.unlink(missing_ok=True)
        return True
    except (OSError, TypeError, ValueError, UnicodeError):
        return False


class UtteranceGate:
    """Collect bounded text chunks and decide once, before releasing any text."""

    def __init__(self, policy: "VoiceOutputPolicy"):
        self.policy = policy
        self.parts: list[str] = []
        self.size = 0
        self.started = False
        self.oversized = False

    def start(self) -> None:
        self.parts = []
        self.size = 0
        self.started = True
        self.oversized = False

    def add(self, chunk: str) -> None:
        if not self.started or not isinstance(chunk, str):
            self.oversized = True
            return
        self.size += len(chunk)
        if self.size > MAX_UTTERANCE:
            self.oversized = True
            self.parts = []
        elif not self.oversized:
            self.parts.append(chunk)

    def finish(self) -> dict[str, Any]:
        if not self.started or self.oversized:
            result = self.policy.evaluate(UNAVAILABLE_ANSWER)
            result["text"] = UNAVAILABLE_ANSWER
            result["outputSHA256"] = hashlib.sha256(UNAVAILABLE_ANSWER.encode()).hexdigest()
            result["blocked"] = True
            result["markerObserved"] = False
            result["markerSHA256"] = ""
        else:
            result = self.policy.evaluate("".join(self.parts))
        self.start()
        self.started = False
        return result

    def cancel(self) -> None:
        self.parts = []
        self.started = False
        self.oversized = False


def parse_rule(raw: bytes, expected_source: str) -> dict[str, Any]:
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_RULE_BYTES or not HEX64.fullmatch(expected_source):
        raise OutputPolicyError("output rule bytes or source invalid")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise OutputPolicyError("invalid output rule JSON") from exc
    if not isinstance(value, dict) or frozenset(value) != RULE_KEYS or raw != canonical_bytes(value):
        raise OutputPolicyError("noncanonical output rule")
    if type(value["version"]) is not int or value["version"] != 1 or \
            type(value["revision"]) is not int or not 0 <= value["revision"] <= MAX_ENTRIES or \
            value["sourceSHA256"] != expected_source or \
            not isinstance(value["configMapUID"], str) or not UID.fullmatch(value["configMapUID"]) or \
            not isinstance(value["deploymentUID"], str) or not UID.fullmatch(value["deploymentUID"]) or \
            not isinstance(value["policyUID"], str) or not UID.fullmatch(value["policyUID"]) or \
            not isinstance(value["operationId"], str) or \
            (value["operationId"] and not HEX64.fullmatch(value["operationId"])) or \
            not isinstance(value["entries"], list) or len(value["entries"]) != value["revision"]:
        raise OutputPolicyError("output rule identity or revision invalid")
    if (value["revision"] == 0) != (value["operationId"] == ""):
        raise OutputPolicyError("output rule operation/revision mismatch")
    pairs = []
    for entry in value["entries"]:
        if not isinstance(entry, dict) or frozenset(entry) != ENTRY_KEYS or \
                not isinstance(entry["markerSHA256"], str) or not HEX64.fullmatch(entry["markerSHA256"]) or \
                not isinstance(entry["operationId"], str) or not HEX64.fullmatch(entry["operationId"]):
            raise OutputPolicyError("output rule entry invalid")
        pairs.append(entry["markerSHA256"])
    if pairs != sorted(set(pairs)) or (pairs and value["operationId"] not in
                                   {entry["operationId"] for entry in value["entries"]}):
        raise OutputPolicyError("output rule entries not sorted unique")
    return value


class VoiceOutputPolicy:
    def __init__(self, policy_dir: pathlib.Path, state_dir: pathlib.Path, source_sha: str,
                 pod_uid: str, required: bool = False):
        self.policy_dir = pathlib.Path(policy_dir)
        self.state_dir = pathlib.Path(state_dir)
        self.source_sha = source_sha
        self.pod_uid = pod_uid
        self.required = required
        self._lock = threading.Lock()
        self._seen = False

    def _ledger_path(self) -> pathlib.Path:
        return self.state_dir / "output-ledger.json"

    def _load_ledger(self) -> dict[str, Any] | None:
        path = self._ledger_path()
        try:
            info = path.lstat()
        except FileNotFoundError:
            return None
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_RULE_BYTES or info.st_mode & 0o077:
            raise OutputPolicyError("invalid output ledger file")
        try:
            ledger = json.loads(path.read_bytes().decode("utf-8"), object_pairs_hook=_unique_object)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise OutputPolicyError("invalid output ledger JSON") from exc
        if not isinstance(ledger, dict) or frozenset(ledger) != {
                "revision", "ruleSHA256", "entries", "configMapUID", "deploymentUID", "policyUID"} or \
                type(ledger["revision"]) is not int or not 0 <= ledger["revision"] <= MAX_ENTRIES or \
                not isinstance(ledger["ruleSHA256"], str) or not HEX64.fullmatch(ledger["ruleSHA256"]) or \
                not isinstance(ledger["entries"], list) or len(ledger["entries"]) != ledger["revision"] or \
                any(not isinstance(ledger[key], str) or not UID.fullmatch(ledger[key])
                    for key in ("configMapUID", "deploymentUID", "policyUID")):
            raise OutputPolicyError("invalid output ledger")
        for entry in ledger["entries"]:
            if not isinstance(entry, dict) or frozenset(entry) != ENTRY_KEYS or \
                    any(not isinstance(entry[key], str) or not HEX64.fullmatch(entry[key]) for key in ENTRY_KEYS):
                raise OutputPolicyError("invalid output ledger entry")
        hashes = [entry["markerSHA256"] for entry in ledger["entries"]]
        if hashes != sorted(set(hashes)):
            raise OutputPolicyError("output ledger entries not sorted unique")
        return ledger

    def _save_ledger(self, value: dict[str, Any]) -> None:
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.state_dir.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077:
            raise OutputPolicyError("insecure output state directory")
        path = self.state_dir / ("output-ledger." + secrets.token_hex(8) + ".tmp")
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
        with self._lock:
            try:
                ledger = self._load_ledger()
                if self._seen and ledger is None:
                    raise OutputPolicyError("output ledger disappeared")
                try:
                    with (self.policy_dir / "rule.json").open("rb") as stream:
                        raw = stream.read(MAX_RULE_BYTES + 1)
                except FileNotFoundError:
                    return None, self.required or ledger is not None or self._seen
                rule = parse_rule(raw, self.source_sha)
                digest = hashlib.sha256(raw).hexdigest()
                if ledger is not None:
                    if any(rule[key] != ledger[key] for key in ("configMapUID", "deploymentUID", "policyUID")) or \
                            rule["revision"] < ledger["revision"] or \
                            (rule["revision"] == ledger["revision"] and digest != ledger["ruleSHA256"]):
                        raise OutputPolicyError("output rule owner or revision drift")
                    old = {(entry["markerSHA256"], entry["operationId"]) for entry in ledger["entries"]}
                    new = {(entry["markerSHA256"], entry["operationId"]) for entry in rule["entries"]}
                    if not old.issubset(new):
                        raise OutputPolicyError("output rule removed an active marker")
                if ledger is None or rule["revision"] > ledger["revision"]:
                    self._save_ledger({"revision": rule["revision"], "ruleSHA256": digest,
                                       "entries": rule["entries"], "configMapUID": rule["configMapUID"],
                                       "deploymentUID": rule["deploymentUID"], "policyUID": rule["policyUID"]})
                self._seen = True
                return rule, False
            except (OutputPolicyError, OSError, TypeError, KeyError, ValueError):
                return None, True

    def evaluate(self, utterance: str) -> dict[str, Any]:
        """Return one whole-utterance decision; never release a prefix first."""
        if not isinstance(utterance, str) or len(utterance) > MAX_UTTERANCE:
            utterance = ""
            oversized = True
        else:
            oversized = False
        rule, closed = self._read()
        matches = list(MARKER.finditer(utterance))
        marker_hashes = [hashlib.sha256(match.group().encode("ascii")).hexdigest() for match in matches]
        active = {entry["markerSHA256"] for entry in rule["entries"]} if rule else set()
        blocked = oversized or closed or any(hash_value in active for hash_value in marker_hashes)
        answer = (UNAVAILABLE_ANSWER if oversized or closed else BLOCKED_ANSWER) if blocked else utterance
        return {"text": answer, "rawSHA256": hashlib.sha256(utterance.encode("utf-8")).hexdigest(),
                "outputSHA256": hashlib.sha256(answer.encode("utf-8")).hexdigest(),
                "markerSHA256": marker_hashes[0] if len(marker_hashes) == 1 else "",
                "markerObserved": len(marker_hashes) == 1, "blocked": blocked,
                "policyReady": not closed, "revision": rule["revision"] if rule else 0,
                "operationId": rule["operationId"] if rule else ""}

    def state(self, marker_sha: str) -> tuple[int, dict[str, Any]]:
        if not isinstance(marker_sha, str) or not HEX64.fullmatch(marker_sha):
            return 400, {"ready": False}
        rule, closed = self._read()
        if closed or rule is None:
            return 503, {"version": 1, "podUID": self.pod_uid, "sourceSHA256": self.source_sha,
                         "markerSHA256": marker_sha, "ready": False}
        matching = [entry for entry in rule["entries"] if entry["markerSHA256"] == marker_sha]
        return 200, {"version": 1, "podUID": self.pod_uid, "configMapUID": rule["configMapUID"],
                     "deploymentUID": rule["deploymentUID"], "policyUID": rule["policyUID"],
                     "sourceSHA256": self.source_sha, "ruleSHA256": hashlib.sha256(canonical_bytes(rule)).hexdigest(),
                     "revision": rule["revision"], "operationId": rule["operationId"],
                     "entryCount": len(rule["entries"]), "markerSHA256": marker_sha,
                     "active": bool(matching), "matchedOperationId": matching[0]["operationId"] if matching else "",
                     "ready": True}
