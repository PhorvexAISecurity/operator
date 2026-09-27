"""Source-bound admission for the two installed Voice MCP tool descriptors.

The mounted rule can pin a reviewed known-good descriptor before it enters the
model context. The actual tool handler still calls the configured MCP server.
An invalid required projection withholds MCP tools and readiness; it never
silently restores an attacker-supplied description.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import stat
import threading
import re
from typing import Any

from voice_memory_policy import (HEX64, MAX_REVISION, PolicyError, UID,
                                 _unique_object, canonical_bytes)


RULE_KEYS = frozenset({"version", "deploymentUID", "policyUID", "sourceSHA256",
                       "revision", "operationId", "entries"})
ENTRY_KEYS = frozenset({"toolName", "goodDescriptorSHA256", "operationId"})
MAX_RULE_BYTES = 8192
MAX_ENTRIES = 2
TEST_RUN = re.compile(r"[a-z0-9]{8,24}\Z")
TEST_SIGNATURE = re.compile(r"[0-9a-f]{64}\Z")


def test_call_sid(run: str, phase: str) -> str:
    if not isinstance(run, str) or not TEST_RUN.fullmatch(run) or phase not in ("attack", "replay", "benign"):
        raise ValueError("invalid MCP test session")
    return "CA" + hashlib.sha256(f"voice-mcp:{run}:{phase}".encode()).hexdigest()[:32].upper()


def test_signature(token: bytes, run: str, phase: str, call_sid: str) -> str:
    return hmac.new(token, f"voice-mcp-descriptor-v1:{run}:{phase}:{call_sid}".encode(), hashlib.sha256).hexdigest()


def admit_test_session(token_file: Path, run: str, phase: str, call_sid: str, supplied: str) -> bool:
    try:
        if call_sid != test_call_sid(run, phase) or not isinstance(supplied, str) or \
                not TEST_SIGNATURE.fullmatch(supplied):
            return False
        token = token_file.read_bytes()
        return 32 <= len(token) <= 256 and all(33 <= value <= 126 for value in token) and \
            hmac.compare_digest(supplied, test_signature(token, run, phase, call_sid))
    except (OSError, ValueError):
        return False

# These are normalized FunctionSchema inputs, derived from the reviewed
# mcp-control/server.py store_directory and check_promotions declarations.
# The entire module is part of the Voice runtime source digest.
KNOWN_GOOD: dict[str, dict[str, Any]] = {
    "store_directory": {
        "name": "store_directory",
        "description": ("Look up store directory information: opening hours, store locations, or which\n"
                        "department handles a given topic. Valid topics include 'hours', 'locations', 'returns'."),
        "properties": {"topic": {"type": "string"}},
        "required": ["topic"],
    },
    "check_promotions": {
        "name": "check_promotions",
        "description": "Return the current promotions and any active discount codes.",
        "properties": {},
        "required": [],
    },
}


def descriptor_sha256(tool_name: str) -> str:
    return hashlib.sha256(canonical_bytes(KNOWN_GOOD[tool_name])).hexdigest()


def normalized_descriptor_sha256(item: dict[str, Any]) -> str:
    name = item["name"]
    if name not in KNOWN_GOOD:
        raise ValueError("unknown MCP tool")
    descriptor = {"name": name, "description": item["description"],
                  "properties": KNOWN_GOOD[name]["properties"],
                  "required": KNOWN_GOOD[name]["required"]}
    return hashlib.sha256(canonical_bytes(descriptor)).hexdigest()


def source_sha256(bot: Path, memory_policy: Path, mcp_policy: Path) -> str:
    digest = hashlib.sha256()
    for index, source in enumerate((bot, memory_policy, mcp_policy)):
        if index:
            digest.update(b"\x00")
        digest.update(source.read_bytes())
    return digest.hexdigest()


def parse_rule(raw: bytes, source_sha: str) -> dict[str, Any]:
    if not raw or len(raw) > MAX_RULE_BYTES:
        raise PolicyError("invalid MCP rule length")
    try:
        rule = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PolicyError("invalid MCP rule JSON") from exc
    if not isinstance(rule, dict) or frozenset(rule) != RULE_KEYS or canonical_bytes(rule) != raw:
        raise PolicyError("noncanonical MCP rule")
    if type(rule["version"]) is not int or rule["version"] != 1 or \
            type(rule["revision"]) is not int or not 0 <= rule["revision"] <= MAX_REVISION or \
            rule["sourceSHA256"] != source_sha or \
            not all(isinstance(rule[key], str) and UID.fullmatch(rule[key])
                    for key in ("deploymentUID", "policyUID")):
        raise PolicyError("invalid MCP rule identity")
    entries = rule["entries"]
    if not isinstance(entries, list) or len(entries) > MAX_ENTRIES or rule["revision"] != len(entries):
        raise PolicyError("invalid MCP entry count or revision")
    if rule["revision"] == 0:
        if rule["operationId"] != "" or entries:
            raise PolicyError("invalid initial MCP rule")
    elif not isinstance(rule["operationId"], str) or not HEX64.fullmatch(rule["operationId"]):
        raise PolicyError("invalid MCP operation")
    names: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict) or frozenset(entry) != ENTRY_KEYS:
            raise PolicyError("invalid MCP entry")
        name = entry["toolName"]
        if not isinstance(name, str) or name not in KNOWN_GOOD or \
                entry["goodDescriptorSHA256"] != descriptor_sha256(name) or \
                not isinstance(entry["operationId"], str) or not HEX64.fullmatch(entry["operationId"]):
            raise PolicyError("invalid MCP entry identity")
        names.append(name)
    if names != sorted(set(names)) or \
            (entries and rule["operationId"] not in {entry["operationId"] for entry in entries}):
        raise PolicyError("MCP entries are not ordered unique append-only intents")
    return rule


class VoiceMCPPolicy:
    def __init__(self, policy_dir: Path, state_dir: Path, source_sha: str,
                 pod_uid: str, required: bool = False):
        self.policy_dir = Path(policy_dir)
        self.state_dir = Path(state_dir)
        self.source_sha = source_sha
        self.pod_uid = pod_uid
        self.required = required
        self._lock = threading.Lock()
        self._seen = False

    def _ledger_path(self) -> Path:
        return self.state_dir / "mcp-ledger.json"

    def _load_ledger(self) -> dict[str, Any] | None:
        path = self._ledger_path()
        try:
            info = path.lstat()
        except FileNotFoundError:
            return None
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_RULE_BYTES:
            raise PolicyError("invalid MCP ledger file")
        try:
            value = json.loads(path.read_bytes().decode("utf-8"), object_pairs_hook=_unique_object)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise PolicyError("invalid MCP ledger JSON") from exc
        if not isinstance(value, dict) or frozenset(value) != {
                "revision", "ruleSHA256", "entries", "deploymentUID", "policyUID"} or \
                type(value["revision"]) is not int or not 0 <= value["revision"] <= MAX_ENTRIES or \
                not isinstance(value["ruleSHA256"], str) or not HEX64.fullmatch(value["ruleSHA256"]) or \
                not isinstance(value["deploymentUID"], str) or not UID.fullmatch(value["deploymentUID"]) or \
                not isinstance(value["policyUID"], str) or not UID.fullmatch(value["policyUID"]) or \
                not isinstance(value["entries"], list) or len(value["entries"]) != value["revision"]:
            raise PolicyError("invalid MCP ledger schema")
        for entry in value["entries"]:
            if not isinstance(entry, dict) or frozenset(entry) != ENTRY_KEYS:
                raise PolicyError("invalid MCP ledger entry")
            name = entry["toolName"]
            if not isinstance(name, str) or name not in KNOWN_GOOD or \
                    entry["goodDescriptorSHA256"] != descriptor_sha256(name) or \
                    not isinstance(entry["operationId"], str) or not HEX64.fullmatch(entry["operationId"]):
                raise PolicyError("invalid MCP ledger entry")
        return value

    def _save_ledger(self, value: dict[str, Any]) -> None:
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.state_dir.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077:
            raise PolicyError("insecure MCP state directory")
        path = self.state_dir / ("mcp-ledger." + secrets.token_hex(8) + ".tmp")
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
                    raise PolicyError("MCP ledger disappeared")
                try:
                    with (self.policy_dir / "rule.json").open("rb") as stream:
                        raw = stream.read(MAX_RULE_BYTES + 1)
                except FileNotFoundError:
                    return None, self.required or ledger is not None or self._seen
                rule = parse_rule(raw, self.source_sha)
                digest = hashlib.sha256(raw).hexdigest()
                if ledger is not None:
                    if rule["deploymentUID"] != ledger["deploymentUID"] or rule["policyUID"] != ledger["policyUID"] or \
                            rule["revision"] < ledger["revision"] or \
                            (rule["revision"] == ledger["revision"] and digest != ledger["ruleSHA256"]):
                        raise PolicyError("MCP rule owner or revision drift")
                    old = {(entry["toolName"], entry["goodDescriptorSHA256"], entry["operationId"])
                           for entry in ledger["entries"]}
                    new = {(entry["toolName"], entry["goodDescriptorSHA256"], entry["operationId"])
                           for entry in rule["entries"]}
                    if not old.issubset(new):
                        raise PolicyError("MCP rule removed an active pin")
                if ledger is None or rule["revision"] > ledger["revision"]:
                    self._save_ledger({"revision": rule["revision"], "ruleSHA256": digest,
                                       "entries": rule["entries"], "deploymentUID": rule["deploymentUID"],
                                       "policyUID": rule["policyUID"]})
                self._seen = True
                return rule, False
            except (PolicyError, OSError, TypeError, KeyError, ValueError):
                return None, True

    def selection(self, fetched: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], str, dict[str, Any] | None]:
        """Return complete model descriptors from one policy snapshot.

        A required-mode projection error yields no MCP tool, never a partial
        mixture of pinned and untrusted descriptors.
        """
        rule, closed = self._read()
        if closed:
            return [], "policy-unavailable", None
        if not isinstance(fetched, list) or len(fetched) != len(KNOWN_GOOD):
            return [], "source-unavailable", None
        names = [item.get("name") for item in fetched if isinstance(item, dict)]
        if len(names) != len(fetched) or set(names) != set(KNOWN_GOOD):
            return [], "source-unavailable", None
        pinned = {entry["toolName"] for entry in rule["entries"]} if rule else set()
        chosen: list[dict[str, Any]] = []
        for item in fetched:
            name = item["name"]
            props, required = item.get("properties"), item.get("required")
            if not isinstance(props, dict) or not isinstance(required, list):
                return [], "source-unavailable", None
            # This case concerns the description, not a changed function API.
            if name == "store_directory":
                if set(props) != {"topic"} or not isinstance(props["topic"], dict) or \
                        props["topic"].get("type") != "string" or required != ["topic"]:
                    return [], "source-unavailable", None
            elif props or required:
                return [], "source-unavailable", None
            description = item.get("description")
            if not isinstance(description, str) or not description or len(description) > 1024:
                return [], "source-unavailable", None
            chosen.append(json.loads(canonical_bytes(KNOWN_GOOD[name])) if name in pinned else item)
        metadata = {"policyRevision": rule["revision"],
                    "policyRuleSHA256": hashlib.sha256(canonical_bytes(rule)).hexdigest(),
                    "policyOperationId": rule["operationId"]} if rule else None
        return chosen, "pinned" if pinned else "observed", metadata

    def descriptors(self, fetched: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], str]:
        chosen, status, _ = self.selection(fetched)
        return chosen, status

    def state(self) -> tuple[int, dict[str, Any]]:
        rule, closed = self._read()
        if closed or rule is None:
            return 503, {"version": 1, "podUID": self.pod_uid,
                         "sourceSHA256": self.source_sha, "ready": False}
        return 200, {"version": 1, "podUID": self.pod_uid,
                     "deploymentUID": rule["deploymentUID"], "policyUID": rule["policyUID"],
                     "sourceSHA256": self.source_sha,
                     "ruleSHA256": hashlib.sha256(canonical_bytes(rule)).hexdigest(),
                     "revision": rule["revision"], "operationId": rule["operationId"],
                     "entryCount": len(rule["entries"]), "ready": True,
                     "goodDescriptorSHA256": descriptor_sha256("store_directory")}
