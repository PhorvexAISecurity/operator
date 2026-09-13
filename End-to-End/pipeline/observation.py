"""Explicit validity for everything the pipeline reads from outside itself.

The whole suite exists to answer "did the system really do that". Every answer it gives
rests on a read — of the cluster, of a policy, of a container log, of a metrics endpoint —
and each of those reads has four genuinely different outcomes that a bare return value
cannot tell apart:

    ok         the read succeeded. The value may legitimately be empty.
    partial    some of the requested scope was observed and some was not.
    unavailable  nothing was observed: RBAC denial, timeout, unreachable endpoint.
    malformed  something answered, but not in the shape the contract requires.

Collapsing those into `{}` / `None` / `""` is what turned a Forbidden pod list into
"the pod is gone, so the rotation succeeded" (M-165). A consumer that receives an
`Observation` cannot make that mistake by accident: it has to look at `.status`, and the
two helpers that read the value (`require` and `value_or`) both force the caller to say
what an unusable read means for its own verdict.

Nothing here logs or stores a secret: `redact` removes any environment value that looks
like a credential from a reason string before it can reach a report.
"""

import os
import time
from datetime import datetime, timezone

OK = "ok"
PARTIAL = "partial"
UNAVAILABLE = "unavailable"
MALFORMED = "malformed"

STATUSES = (OK, PARTIAL, UNAVAILABLE, MALFORMED)

# Why a read produced nothing usable. Kept as a small closed vocabulary so a report can
# group causes without parsing prose, and so "forbidden" never reads as "absent".
FORBIDDEN = "forbidden"
TIMEOUT = "timeout"
NOT_FOUND = "not-found"
UNREACHABLE = "unreachable"
INVALID = "invalid"
CAPPED = "capped"
TRUNCATED = "truncated"

_SECRET_WORDS = ("PASSWORD", "TOKEN", "SECRET", "SSHPASS", "APIKEY", "API_KEY")
_REASON_LIMIT = 400


def redact(text, limit=_REASON_LIMIT):
    """Strip credential-looking environment values out of a message we are about to keep."""
    text = str(text)
    for key, value in os.environ.items():
        if value and len(value) >= 4 and any(word in key.upper() for word in _SECRET_WORDS):
            text = text.replace(value, "[REDACTED]")
    return text[:limit]


class Observation:
    """One read, with the evidence needed to judge how much it is worth.

    `observed_at` is recorded on construction rather than passed in: a verdict that
    depends on an interval ("the successor appeared *after* the action") is only sound if
    the observation time comes from the observation itself.
    """

    __slots__ = ("status", "value", "reason", "reason_code", "source", "observed_at", "detail")

    def __init__(self, status, value=None, reason="", reason_code="", source="", detail=None):
        if status not in STATUSES:
            raise ValueError(f"unknown observation status: {status!r}")
        self.status = status
        self.value = value
        self.reason = redact(reason) if reason else ""
        self.reason_code = reason_code
        self.source = source
        self.observed_at = time.time()
        self.detail = detail or {}

    # ── constructors ──────────────────────────────────────────────────────
    @classmethod
    def observed(cls, value, source="", detail=None):
        return cls(OK, value, source=source, detail=detail)

    @classmethod
    def partial(cls, value, reason, source="", reason_code="", detail=None):
        return cls(PARTIAL, value, reason=reason, reason_code=reason_code,
                   source=source, detail=detail)

    @classmethod
    def unavailable(cls, reason, source="", reason_code=UNREACHABLE, detail=None):
        return cls(UNAVAILABLE, None, reason=reason, reason_code=reason_code,
                   source=source, detail=detail)

    @classmethod
    def malformed(cls, reason, source="", detail=None):
        return cls(MALFORMED, None, reason=reason, reason_code=INVALID,
                   source=source, detail=detail)

    # ── inspection ────────────────────────────────────────────────────────
    @property
    def ok(self):
        """The full requested scope was observed. Empty is still ok."""
        return self.status == OK

    @property
    def usable(self):
        """There is a value to read, but `partial` means it is not the whole picture."""
        return self.status in (OK, PARTIAL)

    @property
    def empty(self):
        """Observed successfully, and what was observed is genuinely nothing."""
        return self.status == OK and not self.value

    def value_or(self, fallback):
        """Read the value, naming the fallback at the call site.

        Deliberately not a default argument: every caller that is willing to proceed on an
        unusable read has to write down what it proceeds with.
        """
        return self.value if self.usable else fallback

    def require(self, what):
        """Value or ObservationUnavailable — for callers that must not guess."""
        if not self.usable:
            raise ObservationUnavailable(f"{what}: {self.describe()}")
        return self.value

    def describe(self):
        if self.status == OK:
            return f"{self.source or 'observation'} ok"
        code = f" ({self.reason_code})" if self.reason_code else ""
        return f"{self.source or 'observation'} {self.status}{code}: {self.reason or 'no reason recorded'}"

    def to_json(self):
        return {
            "status": self.status,
            "reason": self.reason,
            "reasonCode": self.reason_code,
            "source": self.source,
            "observedAt": datetime.fromtimestamp(self.observed_at, timezone.utc).isoformat(),
            "observedAtEpoch": self.observed_at,
            **({"detail": self.detail} if self.detail else {}),
        }

    def __repr__(self):
        return f"<Observation {self.describe()}>"


class ObservationUnavailable(RuntimeError):
    """Raised by `require` — a read the caller declared it cannot proceed without."""


# The exit code Transport.run reports for its own timeout, mirrored here so the classifier
# does not have to guess from stderr text alone.
TIMEOUT_RC = 124

_FORBIDDEN_MARKERS = ("forbidden", "unauthorized", "error from server (forbidden)",
                      "cannot list resource", "is not allowed")
_TIMEOUT_MARKERS = ("timeout", "timed out", "context deadline exceeded", "i/o timeout")
_NOT_FOUND_MARKERS = ("notfound", "not found")


def classify(rc, out, err, source, parser=None, absent_is_ok=False):
    """Turn one command result into an Observation.

    `absent_is_ok` is for reads of a single named object, where "the API server says this
    object does not exist" is a real observation rather than a failed read. It is off by
    default because for a *list* read the same message means the request itself failed.
    """
    text = (err or "").strip()
    lowered = text.lower()
    if rc != 0:
        if rc == TIMEOUT_RC or any(m in lowered for m in _TIMEOUT_MARKERS):
            return Observation.unavailable(text or f"command timed out (rc={rc})",
                                           source=source, reason_code=TIMEOUT)
        if any(m in lowered for m in _FORBIDDEN_MARKERS):
            return Observation.unavailable(text, source=source, reason_code=FORBIDDEN)
        if any(m in lowered for m in _NOT_FOUND_MARKERS):
            if absent_is_ok:
                return Observation(OK, None, reason=text, reason_code=NOT_FOUND, source=source)
            return Observation.unavailable(text, source=source, reason_code=NOT_FOUND)
        return Observation.unavailable(text or f"command failed (rc={rc})",
                                       source=source, reason_code=UNREACHABLE)
    if parser is None:
        return Observation.observed(out, source=source)
    try:
        return Observation.observed(parser(out), source=source)
    except ObservationUnavailable:
        raise
    except Exception as error:                       # any parse/shape failure, not just JSON
        return Observation.malformed(f"{type(error).__name__}: {error}", source=source)


def worst(observations):
    """The status a composite read may claim: the weakest of its parts."""
    seen = {o.status for o in observations}
    for status in (MALFORMED, UNAVAILABLE, PARTIAL):
        if status in seen:
            return status
    return OK
