"""Strict admission authority; reads one authoritative ConfigMap, never writes it."""

from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import ssl
import urllib.request

MAX_JSON_BYTES = 65536
MAX_VALUE_BYTES = 8192
POLICY_NAME = "voice-session-admission-policy"
WRAPPER_PATH = Path("/opt/voice-admission")
LEGACY_FILES = ("bot.py", "voice_memory_policy.py", "voice_output_policy.py", "voice_mcp_policy.py")
RULE_KEYS = frozenset(("version", "deploymentUID", "securityPolicyUID", "wrapperCMUID", "admissionSourceSHA256",
                       "legacyBundleSHA256", "authProfileSHA256", "revision", "mode", "operationId"))
PROFILE_KEYS = frozenset(("version", "deploymentUID", "publicHost", "websocketSigningURLs", "webhookSigningURL",
                          "twilioSecretName", "authTokenSHA256"))
HEX = re.compile(r"[0-9a-f]{64}\Z")
UID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")


class PolicyUnavailable(Exception):
    """A bounded, non-secret error; callers must fail closed."""


def require(condition):
    if not condition:
        raise PolicyUnavailable("admission-authority-invalid")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def parse(raw):
    require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_JSON_BYTES)
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                          parse_constant=lambda _: require(False))
    except (ValueError, UnicodeError, TypeError):
        raise PolicyUnavailable("admission-authority-invalid") from None


@dataclass(frozen=True)
class Pins:
    pod_uid: str
    deployment_uid: str
    security_policy_uid: str
    policy_cm_uid: str
    wrapper_cm_uid: str
    source_sha: str
    legacy_sha: str
    profile_sha: str

    def validate(self):
        require(all(isinstance(value, str) and UID.fullmatch(value) for value in
                    (self.pod_uid, self.deployment_uid, self.security_policy_uid, self.policy_cm_uid, self.wrapper_cm_uid)))
        require(all(isinstance(value, str) and HEX.fullmatch(value) for value in
                    (self.source_sha, self.legacy_sha, self.profile_sha)))


def load_profile(raw, pins, token):
    require(len(raw) <= MAX_VALUE_BYTES)
    profile = parse(raw)
    require(isinstance(profile, dict) and frozenset(profile) == PROFILE_KEYS and canonical(profile) == raw)
    require(type(profile["version"]) is int and profile["version"] == 1 and
            profile["deploymentUID"] == pins.deployment_uid and profile["publicHost"] == "voicebot.phorvex.ai" and
            profile["websocketSigningURLs"] == ["wss://voicebot.phorvex.ai/ws"] and
            profile["webhookSigningURL"] == "https://voicebot.phorvex.ai/" and
            profile["twilioSecretName"] == "voice-secrets" and
            isinstance(profile["authTokenSHA256"], str) and HEX.fullmatch(profile["authTokenSHA256"]) and
            isinstance(token, str) and 0 < len(token.encode()) <= 256 and
            hmac.compare_digest(profile["authTokenSHA256"], digest(token.encode())) and digest(raw) == pins.profile_sha)
    return profile


def source_digest(directory, filenames):
    return digest(b"\0".join((directory / name).read_bytes() for name in filenames))


class KubernetesReader:
    """Fixed GET-only route, verified API TLS, bounded response and timeout."""
    def __init__(self, service_account=Path("/var/run/secrets/kubernetes.io/serviceaccount")):
        self.service_account = service_account

    def __call__(self):
        try:
            token = (self.service_account / "token").read_text().strip()
            require(bool(token) and len(token) < 16384)
            context = ssl.create_default_context(cafile=str(self.service_account / "ca.crt"))
            request = urllib.request.Request("https://kubernetes.default.svc/api/v1/namespaces/voice/configmaps/" + POLICY_NAME,
                                             headers={"Authorization": "Bearer " + token, "Accept": "application/json"})
            # Cluster API access does not consult user-controlled proxy settings.
            class RefuseRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *args, **kwargs):
                    return None
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), RefuseRedirect(),
                                                urllib.request.HTTPSHandler(context=context))
            with opener.open(request, timeout=2) as response:
                require(response.status == 200)
                raw = response.read(MAX_JSON_BYTES + 1)
            return parse(raw)
        except Exception:
            raise PolicyUnavailable("admission-policy-unavailable") from None


class Authority:
    def __init__(self, pins, reader):
        pins.validate()
        self.pins, self.reader, self.current = pins, reader, None

    def read(self):
        try:
            obj = self.reader()
            meta = obj.get("metadata", {})
            require(obj.get("apiVersion") == "v1" and obj.get("kind") == "ConfigMap" and
                    meta.get("namespace") == "voice" and meta.get("name") == POLICY_NAME and
                    meta.get("uid") == self.pins.policy_cm_uid and
                    isinstance(meta.get("resourceVersion"), str) and meta["resourceVersion"].isdecimal() and
                    not meta.get("deletionTimestamp") and not obj.get("binaryData") and
                    set(obj.get("data", {})) == {"rule.json"})
            owners = meta.get("ownerReferences", [])
            require(len(owners) == 1 and owners[0].get("apiVersion") == "apps/v1" and
                    owners[0].get("kind") == "Deployment" and owners[0].get("name") == "voice-bot" and
                    owners[0].get("uid") == self.pins.deployment_uid and owners[0].get("controller") is True)
            raw = obj["data"]["rule.json"].encode("utf-8")
            require(len(raw) <= MAX_VALUE_BYTES)
            rule = parse(raw)
            require(isinstance(rule, dict) and frozenset(rule) == RULE_KEYS and canonical(rule) == raw and
                    type(rule["version"]) is int and rule["version"] == 1 and
                    rule["deploymentUID"] == self.pins.deployment_uid and
                    rule["securityPolicyUID"] == self.pins.security_policy_uid and
                    rule["wrapperCMUID"] == self.pins.wrapper_cm_uid and
                    rule["admissionSourceSHA256"] == self.pins.source_sha and
                    rule["legacyBundleSHA256"] == self.pins.legacy_sha and rule["authProfileSHA256"] == self.pins.profile_sha)
            require(type(rule["revision"]) is int and
                    ((rule["revision"] == 0 and rule["mode"] == "observe" and rule["operationId"] == "") or
                     (rule["revision"] == 1 and rule["mode"] == "require-twilio-signature" and
                      isinstance(rule["operationId"], str) and HEX.fullmatch(rule["operationId"]))))
            sha = digest(raw)
            if self.current:
                old, old_sha, old_rv = self.current
                require(int(meta["resourceVersion"]) >= int(old_rv) and rule["revision"] >= old["revision"] and
                        (rule["revision"] != old["revision"] or sha == old_sha))
            self.current = rule, sha, meta["resourceVersion"]
            return self.current
        except Exception:
            raise PolicyUnavailable("admission-policy-unavailable") from None


def environment_pins(directory=WRAPPER_PATH, legacy=Path("/app")):
    pins = Pins(os.environ["POD_UID"], os.environ["VOICE_ADMISSION_DEPLOYMENT_UID"],
                os.environ["VOICE_ADMISSION_SECURITY_POLICY_UID"], os.environ["VOICE_ADMISSION_POLICY_CM_UID"],
                os.environ["VOICE_ADMISSION_WRAPPER_CM_UID"], os.environ["VOICE_ADMISSION_SOURCE_SHA256"],
                os.environ["VOICE_ADMISSION_LEGACY_BUNDLE_SHA256"], os.environ["VOICE_ADMISSION_AUTH_PROFILE_SHA256"])
    pins.validate()
    require(source_digest(directory, ("entry.py", "policy.py")) == pins.source_sha and
            source_digest(legacy, LEGACY_FILES) == pins.legacy_sha and os.environ.get("PUBLIC_HOST") == "voicebot.phorvex.ai")
    return pins
