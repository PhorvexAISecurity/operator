"""Bounded, incremental framing of the audit stream.

The previous reader accumulated every byte of the all-namespace decision stream into one
buffer and aborted the run when it reached its 16 MiB cap — on EKS that cap arrives inside
the 51 s live window, so the observation the pipeline most depends on was the one most
likely to die. Simply raising the cap trades a visible abort for an unbounded process.

So the stream is framed as it arrives. Lines are decoded one at a time, records outside the
declared capture scope are counted and dropped instead of retained, and what survives is
bounded by an explicit record count rather than by how much unrelated traffic the cluster
happened to produce. Three properties are non-negotiable:

  * Nothing is silently lost. Every byte lands in exactly one counter: accepted, filtered,
    malformed, or the incomplete tail. A truncated final frame is `incomplete`, not
    "a harmless artefact of the cut".
  * A cap is a failed observation, not a shorter one. Hitting the traffic or record limit
    raises, and the caller turns that into ABORTED — never into a pass over a partial window.
  * Scope is declared, not inferred. A result that filtered other namespaces says so, and
    a check that wants to claim cluster-wide coverage has to read that field first.
"""

import json

# SSE separates events with a blank line; every payload line we care about starts with
# "data: " and comment/heartbeat lines start with ":". See the console's /api/live handler.
DATA_PREFIX = "data: "
COMMENT_PREFIX = ":"
HEARTBEAT = "connected"


class CaptureOverflow(RuntimeError):
    """A hard resource limit was reached, so the window was NOT fully observed."""

    def __init__(self, limit, message):
        super().__init__(message)
        self.limit = limit


class CaptureScope:
    """What this capture claims to cover.

    `namespaces=None` is a genuine cluster-wide claim. Anything else is a scoped claim, and
    the run document records it so that a check counting "all decisions" cannot quietly mean
    "all decisions in one namespace".
    """

    def __init__(self, namespaces=None, note=""):
        self.namespaces = None if namespaces is None else frozenset(namespaces)
        self.note = note

    @property
    def is_global(self):
        return self.namespaces is None

    def admits(self, record):
        if self.namespaces is None:
            return True
        return record.get("namespace") in self.namespaces

    def describe(self):
        if self.is_global:
            return "all namespaces"
        return "namespace " + ", ".join(sorted(self.namespaces)) if self.namespaces else "no namespace"

    def to_json(self):
        return {"global": self.is_global,
                "namespaces": None if self.is_global else sorted(self.namespaces),
                "note": self.note}


class CaptureLimits:
    """Explicit resource bounds. All three are recorded next to the counters they bound."""

    def __init__(self, max_total_bytes, max_records, max_frame_bytes=1 << 20):
        self.max_total_bytes = int(max_total_bytes)
        self.max_records = int(max_records)
        self.max_frame_bytes = int(max_frame_bytes)

    def to_json(self):
        return {"maxTotalBytes": self.max_total_bytes, "maxRecords": self.max_records,
                "maxFrameBytes": self.max_frame_bytes}


class CaptureResult:
    """Records plus the full accounting of what did not become a record."""

    def __init__(self, records, counters, scope, limits, complete, reason=""):
        self.records = records
        self.counters = counters
        self.scope = scope
        self.limits = limits
        self.complete = complete
        self.reason = reason

    def to_json(self):
        return {"scope": self.scope.to_json(), "limits": self.limits.to_json(),
                "counters": dict(self.counters), "complete": self.complete,
                "reason": self.reason}

    def describe(self):
        c = self.counters
        return (f"{c['accepted']} accepted · {c['filtered']} out of scope · "
                f"{c['malformed']} malformed · {c['incompleteFrames']} incomplete · "
                f"{c['bytes']} bytes ({self.scope.describe()})")


class StreamCapture:
    """Feed it bytes; it yields accounting.

    The parser never holds more than one partial line plus the accepted records, so a
    namespace under heavy churn costs traffic but not memory.
    """

    def __init__(self, limits, scope=None):
        self.limits = limits
        self.scope = scope or CaptureScope()
        self.records = []
        self.connected = False
        self._buffer = bytearray()
        self._overflow = None
        self.counters = {"bytes": 0, "lines": 0, "dataFrames": 0, "heartbeats": 0,
                         "accepted": 0, "filtered": 0, "malformed": 0,
                         "incompleteFrames": 0, "other": 0}
        self.malformed_samples = []
        self.incomplete_samples = []

    # ── ingestion ─────────────────────────────────────────────────────────
    def feed(self, chunk):
        """Consume one read() worth of bytes. Raises CaptureOverflow at a hard limit."""
        if not chunk:
            return
        self.counters["bytes"] += len(chunk)
        if self.counters["bytes"] > self.limits.max_total_bytes:
            raise self._overflowed(
                "bytes", f"audit capture exceeded its byte cap "
                         f"({self.counters['bytes']} > {self.limits.max_total_bytes} bytes) "
                         f"before the observation window completed")
        self._buffer.extend(chunk)
        while True:
            index = self._buffer.find(b"\n")
            if index < 0:
                break
            line = bytes(self._buffer[:index])
            del self._buffer[:index + 1]
            self._line(line)
        # A single frame that never terminates is the other way an unbounded stream can
        # exhaust memory, so it is capped on its own.
        if len(self._buffer) > self.limits.max_frame_bytes:
            raise self._overflowed(
                "frame", f"a single audit frame exceeded {self.limits.max_frame_bytes} bytes "
                         f"without terminating")

    def _overflowed(self, limit, message):
        self._overflow = message
        return CaptureOverflow(limit, message)

    def _line(self, raw):
        text = raw.decode("utf-8", errors="replace").rstrip("\r")
        if not text.strip():
            return
        self.counters["lines"] += 1
        if text.startswith(COMMENT_PREFIX):
            self.counters["heartbeats"] += 1
            if text[1:].strip() == HEARTBEAT:
                self.connected = True
            return
        if not text.startswith(DATA_PREFIX):
            self.counters["other"] += 1
            return
        self.counters["dataFrames"] += 1
        payload = text[len(DATA_PREFIX):]
        try:
            record = json.loads(payload)
        except json.JSONDecodeError as error:
            # A frame that arrived whole and did not parse is a real defect in the
            # producer, distinct from the tail we cut ourselves.
            self.counters["malformed"] += 1
            if len(self.malformed_samples) < 5:
                self.malformed_samples.append(f"{error.msg}: {payload[:160]}")
            return
        if not isinstance(record, dict):
            self.counters["malformed"] += 1
            if len(self.malformed_samples) < 5:
                self.malformed_samples.append(f"non-object frame: {payload[:160]}")
            return
        if not self.scope.admits(record):
            self.counters["filtered"] += 1
            return
        if len(self.records) >= self.limits.max_records:
            raise self._overflowed(
                "records", f"audit capture reached its record cap "
                           f"({self.limits.max_records}) before the window completed")
        self.records.append(record)
        self.counters["accepted"] += 1

    # ── completion ────────────────────────────────────────────────────────
    def finish(self, complete=True, reason=""):
        """Close the capture, accounting for whatever is still in the buffer.

        A leftover partial line means the stream stopped mid-frame. That is a hole in the
        observation window with an unknown record behind it, so it is reported as
        `incompleteFrames` and marks the result incomplete.
        """
        tail = bytes(self._buffer).strip()
        self._buffer.clear()
        if tail:
            self.counters["incompleteFrames"] += 1
            self.incomplete_samples.append(
                tail.decode("utf-8", errors="replace")[:160])
            complete = False
            reason = reason or "the stream stopped in the middle of a frame"
        if self._overflow:
            complete, reason = False, self._overflow
        if self.counters["malformed"]:
            complete = False
            reason = reason or f"{self.counters['malformed']} frames did not parse"
        detail = dict(self.counters)
        if self.malformed_samples:
            detail["malformedSamples"] = list(self.malformed_samples)
        if self.incomplete_samples:
            detail["incompleteSamples"] = list(self.incomplete_samples)
        return CaptureResult(self.records, detail, self.scope, self.limits, complete, reason)
