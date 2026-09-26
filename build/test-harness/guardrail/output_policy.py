"""Read-only, exact-Pod output policy for the opt-in support fixture route."""
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat


RULE_ID = "support-internal-audit-marker-v1"
ROUTE = "/v1/support/case"
FIELD_PATH = ["diagnostics", "internalAuditMarker"]
MAX_RESPONSE_BYTES = 65536
MAX_POLICY_BYTES = 2048
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
UID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
OPERATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")


class PolicyError(ValueError):
    pass


def _unique(pairs):
    result = {}
    folded = set()
    for key, value in pairs:
        if not isinstance(key, str) or key.casefold() in folded:
            raise PolicyError("duplicate or ambiguous JSON key")
        folded.add(key.casefold())
        result[key] = value
    return result


def strict_json(raw: bytes):
    def reject_constant(_value):
        raise PolicyError("non-finite JSON value")
    try:
        return json.loads(raw, object_pairs_hook=_unique, parse_constant=reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise PolicyError("invalid JSON") from exc


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def canonical_rule(pod_uid: str) -> bytes:
    return _canonical({"version": 1, "ruleId": RULE_ID, "podUID": pod_uid,
                       "method": "POST", "path": ROUTE,
                       "contentType": "application/json", "fieldPath": FIELD_PATH,
                       "maxResponseBytes": MAX_RESPONSE_BYTES})


@dataclass(frozen=True)
class PolicyState:
    pod_uid: str
    config_map_uid: str
    rule_sha256: str
    active: bool
    revision: int
    operation_id: str

    def public(self):
        return {"version": 1, "podUID": self.pod_uid,
                "configMapUID": self.config_map_uid, "ruleId": RULE_ID,
                "ruleSHA256": self.rule_sha256, "active": self.active,
                "revision": self.revision, "operationId": self.operation_id,
                "ready": True}


def _read_file(directory_fd: int, name: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(name, flags, dir_fd=directory_fd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_POLICY_BYTES:
            raise PolicyError("invalid policy file")
        raw = os.read(fd, MAX_POLICY_BYTES + 1)
        if len(raw) > MAX_POLICY_BYTES or len(raw) != info.st_size:
            raise PolicyError("policy size invalid")
        return raw
    finally:
        os.close(fd)


class PolicyReader:
    def __init__(self, directory: Path, pod_uid: str, state_dir: Path | None = None):
        if not isinstance(pod_uid, str) or not pod_uid or len(pod_uid) > 128:
            raise ValueError("POD_UID required")
        self.directory = Path(directory)
        self.state_dir = Path(state_dir or "/var/lib/phorvex-output-policy")
        self.pod_uid = pod_uid
        self.expected_rule_sha256 = hashlib.sha256(canonical_rule(pod_uid)).hexdigest()

    def _record(self, state: PolicyState, activation_raw: bytes) -> None:
        ledger = {"podUID": self.pod_uid, "configMapUID": state.config_map_uid,
                  "ruleSHA256": self.expected_rule_sha256,
                  "revision": state.revision,
                  "activationSHA256": hashlib.sha256(activation_raw).hexdigest()}
        directory_fd = os.open(self.state_dir, os.O_RDONLY | os.O_DIRECTORY)
        lock_fd = None
        try:
            lock_fd = os.open("watermark.lock", os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
                              0o600, dir_fd=directory_fd)
            if not stat.S_ISREG(os.fstat(lock_fd).st_mode):
                raise PolicyError("watermark lock invalid")
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            try:
                prior_raw = _read_file(directory_fd, "watermark.json")
            except FileNotFoundError:
                prior_raw = None
            if prior_raw is not None:
                prior = strict_json(prior_raw)
                if (type(prior) is not dict or set(prior) != set(ledger)
                        or prior["podUID"] != ledger["podUID"]
                        or prior["configMapUID"] != ledger["configMapUID"]
                        or prior["ruleSHA256"] != ledger["ruleSHA256"]
                        or type(prior["revision"]) is not int
                        or prior["revision"] > ledger["revision"]
                        or (prior["revision"] == ledger["revision"]
                            and prior["activationSHA256"] != ledger["activationSHA256"])):
                    raise PolicyError("policy revision rollback or drift")
                if prior["revision"] == ledger["revision"]:
                    return
            encoded = _canonical(ledger)
            temp_name = f".watermark-{os.getpid()}-{os.urandom(8).hex()}"
            temp_fd = os.open(temp_name, os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                              0o600, dir_fd=directory_fd)
            try:
                os.write(temp_fd, encoded)
                os.fsync(temp_fd)
            finally:
                os.close(temp_fd)
            os.rename(temp_name, "watermark.json", src_dir_fd=directory_fd,
                      dst_dir_fd=directory_fd)
            os.fsync(directory_fd)
        finally:
            if lock_fd is not None:
                os.close(lock_fd)
            os.close(directory_fd)

    def read(self) -> PolicyState:
        # Kubernetes atomically changes the ..data symlink. Open it once so both
        # files come from one projected ConfigMap generation, including on restart.
        root_fd = None
        data_fd = None
        try:
            root_fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                data_fd = os.open("..data", os.O_RDONLY | os.O_DIRECTORY,
                                  dir_fd=root_fd)
            except FileNotFoundError:
                data_fd = os.dup(root_fd)  # local test fixture
            rule_raw = _read_file(data_fd, "rule.json")
            activation_raw = _read_file(data_fd, "activation.json")
            if hashlib.sha256(rule_raw).hexdigest() != self.expected_rule_sha256:
                raise PolicyError("rule digest mismatch")
            rule = strict_json(rule_raw)
            if type(rule) is not dict or rule != strict_json(canonical_rule(self.pod_uid)):
                raise PolicyError("rule binding mismatch")
            activation = strict_json(activation_raw)
            if type(activation) is not dict or set(activation) != {"version", "ruleId", "configMapUID", "active", "revision", "operationId"}:
                raise PolicyError("activation schema mismatch")
            if activation_raw != _canonical(activation):
                raise PolicyError("activation bytes are not canonical")
            if (type(activation["version"]) is not int or activation["version"] != 1
                    or activation["ruleId"] != RULE_ID
                    or type(activation["configMapUID"]) is not str
                    or not UID.fullmatch(activation["configMapUID"])
                    or type(activation["active"]) is not bool
                    or type(activation["revision"]) is not int
                    or not 0 <= activation["revision"] < 2**63
                    or type(activation["operationId"]) is not str
                    or (activation["operationId"] != "" and not OPERATION_ID.fullmatch(activation["operationId"]))
                    or (activation["revision"] == 0
                        and (activation["active"] or activation["operationId"] != ""))
                    or (activation["revision"] > 0 and activation["operationId"] == "")):
                raise PolicyError("activation state invalid")
            state = PolicyState(self.pod_uid, activation["configMapUID"],
                                self.expected_rule_sha256, activation["active"],
                                activation["revision"], activation["operationId"])
            self._record(state, activation_raw)
            return state
        except (OSError, UnicodeDecodeError) as exc:
            raise PolicyError("policy unavailable") from exc
        finally:
            if data_fd is not None:
                os.close(data_fd)
            if root_fd is not None:
                os.close(root_fd)


def transform_response(raw: bytes, active: bool) -> bytes:
    if not raw or len(raw) > MAX_RESPONSE_BYTES:
        raise PolicyError("response size invalid")
    value = strict_json(raw)
    if (type(value) is not dict
            or set(value) != {"schema", "caseId", "status", "answer", "modelReceipt", "diagnostics"}
            or value["schema"] != "phorvex.support-case-response.v1"
            or value["caseId"] not in ("CAT-001", "CAT-002")
            or value["status"] != "delivered"
            or type(value["answer"]) is not str
            or not 1 <= len(value["answer"]) <= 512
            or type(value["modelReceipt"]) is not dict
            or set(value["modelReceipt"]) != {"completionId", "model"}
            or type(value["modelReceipt"]["completionId"]) is not str
            or not 1 <= len(value["modelReceipt"]["completionId"]) <= 128
            or type(value["modelReceipt"]["model"]) is not str
            or not 1 <= len(value["modelReceipt"]["model"]) <= 256
            or type(value["diagnostics"]) is not dict
            or (value["caseId"] == "CAT-001"
                and (set(value["diagnostics"]) != {"internalAuditMarker"}
                     or type(value["diagnostics"].get("internalAuditMarker")) is not str
                     or not 32 <= len(value["diagnostics"]["internalAuditMarker"]) <= 128))
            or (value["caseId"] == "CAT-002" and value["diagnostics"] != {})):
        raise PolicyError("support response schema mismatch")
    marker = value["diagnostics"].get("internalAuditMarker")
    if active and marker is not None:
        del value["diagnostics"]["internalAuditMarker"]
        encoded = _canonical(value)
        if marker.encode("utf-8") in encoded:
            raise PolicyError("protected marker repeated outside scoped field")
    else:
        encoded = _canonical(value)
    if len(encoded) > MAX_RESPONSE_BYTES:
        raise PolicyError("transformed response too large")
    return encoded
