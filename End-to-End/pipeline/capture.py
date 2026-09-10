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

# SSE framing: fields until a blank line, `:` starts a comment, and the `event:` field names
# the frame type. Reading only `data:` lines and ignoring `event:` is what let the console's
# own continuity notices be mistaken for decisions — and then, under a namespace scope,
# silently filtered as somebody else's traffic.
DATA_PREFIX = "data:"
EVENT_PREFIX = "event:"
COMMENT_PREFIX = ":"
HEARTBEAT = "connected"
DEFAULT_EVENT = "message"
NOTICE_EVENT = "notice"

# Every notice `internal/console/live.go` emits means records did not reach us or the source
# changed underneath the read: rotation, truncation, a failed read, an omitted oversized
# record, or a scan/replay budget cutting the history short. There is no benign one. The
# reason codes below are for reporting; an unrecognised notice is still treated as lost
# continuity, because a notice this reader does not know is not evidence of a full window.
NOTICE_REASONS = (
    ("replaced or truncated", "source-rotated"),
    ("changed while reading", "source-changed"),
    ("read failed", "source-read-failed"),
    ("was omitted", "record-omitted"),
    ("history is partial", "history-partial"),
    ("budget reached", "scan-budget-reached"),
    ("limited to", "replay-truncated"),
)
UNKNOWN_NOTICE = "source-notice-unrecognised"


def notice_reason(message):
    lowered = (message or "").lower()
    for marker, reason in NOTICE_REASONS:
        if marker in lowered:
            return reason
    return UNKNOWN_NOTICE


class CaptureOverflow(RuntimeError):
    """A hard resource limit was reached, so the window was NOT fully observed."""

    def __init__(self, limit, message, counters=None, records=()):
        super().__init__(message)
        self.limit = limit
        # What had been observed when the limit hit. A cap fails the run, but the evidence
        # collected up to it is still evidence and must not vanish with the exception.
        self.counters = dict(counters or {})
        self.records = list(records)


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
    """Explicit resource bounds. Every one is recorded next to the counters it bounds.

    `max_frame_bytes` bounds a whole SSE frame — every field line it is assembled from,
    not each line on its own. SSE lets one JSON payload span any number of `data:` lines,
    so a per-line bound is not a bound at all: three 60-byte lines hold 180 bytes.

    `max_retained_notices` and `max_notice_bytes` bound the memory the retained source
    notices occupy. They never bound the COUNTERS: every notice is counted and any notice
    still marks the window incomplete, whether or not its text was kept.
    """

    def __init__(self, max_total_bytes, max_records, max_frame_bytes=1 << 20,
                 max_retained_notices=50, max_notice_bytes=300):
        self.max_total_bytes = int(max_total_bytes)
        self.max_records = int(max_records)
        self.max_frame_bytes = int(max_frame_bytes)
        self.max_retained_notices = int(max_retained_notices)
        self.max_notice_bytes = int(max_notice_bytes)

    def to_json(self):
        return {"maxTotalBytes": self.max_total_bytes, "maxRecords": self.max_records,
                "maxFrameBytes": self.max_frame_bytes,
                "maxRetainedNotices": self.max_retained_notices,
                "maxNoticeBytes": self.max_notice_bytes}


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
                f"{c.get('notices', 0)} source notices · "
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
        self._event = DEFAULT_EVENT
        self._data = []
        # Wire bytes of the frame currently being assembled, across all its field lines.
        self._frame_bytes = 0
        self.counters = {"bytes": 0, "lines": 0, "dataFrames": 0, "heartbeats": 0,
                         "accepted": 0, "filtered": 0, "malformed": 0,
                         "incompleteFrames": 0, "other": 0, "notices": 0,
                         "noticesRetained": 0, "noticesDropped": 0}
        self.malformed_samples = []
        self.incomplete_samples = []
        # Source notices are kept whole and separately. They are the only evidence that the
        # window has a hole in it, so they are never filtered by scope and never counted as
        # somebody else's namespace traffic.
        self.notices = []
        self.continuity_lost = None

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
            self._line(line, wire_bytes=index + 1)
        # The frame under construction plus the partial line still in the buffer is what
        # this parser is holding right now, so that is what the bound applies to. Neither
        # a 2 MiB line without a newline nor a thousand small ones can grow past it.
        self._guard_frame_size(len(self._buffer))

    def _guard_frame_size(self, pending=0):
        """Bound the WHOLE frame being assembled, wherever the newlines happen to fall."""
        size = self._frame_bytes + pending
        if size > self.limits.max_frame_bytes:
            raise self._overflowed(
                "frame", f"an audit frame of {size} bytes exceeded the "
                         f"{self.limits.max_frame_bytes}-byte frame cap "
                         f"({len(self._data)} data line(s) accumulated)")

    def _overflowed(self, limit, message):
        self._overflow = message
        return CaptureOverflow(limit, message, self.counters, self.records)

    def _line(self, raw, wire_bytes=0):
        text = raw.decode("utf-8", errors="replace").rstrip("\r")
        if not text.strip():
            self._dispatch()                       # a blank line ends the frame
            return
        self.counters["lines"] += 1
        if text.startswith(COMMENT_PREFIX):
            # A comment is not part of any frame, so it costs nothing to accumulate.
            self.counters["heartbeats"] += 1
            if text[1:].strip() == HEARTBEAT:
                self.connected = True
            return
        # From here the line belongs to the frame under construction and is charged to it.
        # `event:` counts too: it is held until the blank line just like the data lines.
        self._frame_bytes += wire_bytes or (len(raw) + 1)
        self._guard_frame_size()
        if text.startswith(EVENT_PREFIX):
            self._event = text[len(EVENT_PREFIX):].strip() or DEFAULT_EVENT
            return
        if text.startswith(DATA_PREFIX):
            self._data.append(text[len(DATA_PREFIX):].lstrip(" "))
            return
        self.counters["other"] += 1

    def _dispatch(self):
        """Emit the accumulated frame, if there is one, and reset the frame fields."""
        event, data = self._event, self._data
        self._event, self._data, self._frame_bytes = DEFAULT_EVENT, [], 0
        if not data:
            return
        payload = "\n".join(data)
        if event == NOTICE_EVENT:
            self._notice(payload)
            return
        self.counters["dataFrames"] += 1
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

    def _notice(self, payload):
        """The console telling us the source moved, or that records did not reach us.

        Counting and retention are deliberately separate. A stream that emits a notice per
        tick must not be able to grow this list without limit, but the count and the
        incompleteness verdict must survive intact — dropping the TEXT of the fiftieth
        notice loses a sample, while dropping the FACT would lose the hole in the window.
        """
        self.counters["notices"] += 1
        try:
            message = json.loads(payload).get("message", payload)
        except (json.JSONDecodeError, AttributeError):
            message = payload
        message = str(message)[:self.limits.max_notice_bytes]
        reason = notice_reason(message)
        if len(self.notices) < self.limits.max_retained_notices:
            self.notices.append({"reason": reason, "message": message})
            self.counters["noticesRetained"] += 1
        else:
            self.counters["noticesDropped"] += 1
        if self.continuity_lost is None:
            self.continuity_lost = f"{reason}: {message}"

    # ── completion ────────────────────────────────────────────────────────
    def finish(self, complete=True, reason=""):
        """Close the capture, accounting for whatever is still in the buffer.

        A leftover partial line means the stream stopped mid-frame. That is a hole in the
        observation window with an unknown record behind it, so it is reported as
        `incompleteFrames` and marks the result incomplete.
        """
        tail = bytes(self._buffer).strip()
        self._buffer.clear()
        # A frame whose fields arrived but whose terminating blank line did not is also an
        # unfinished frame, not a frame we can dispatch.
        if self._data or tail:
            self.counters["incompleteFrames"] += 1
            sample = (tail.decode("utf-8", errors="replace")
                      or "\n".join(self._data))[:160]
            self.incomplete_samples.append(sample)
            complete = False
            reason = reason or "the stream stopped in the middle of a frame"
        self._data, self._event, self._frame_bytes = [], DEFAULT_EVENT, 0
        if self.continuity_lost:
            # The source rotated, was truncated, dropped a record or cut its own history.
            # Nothing here proves gap-free continuity across that, so the window is not a
            # complete observation — whatever it managed to collect on either side of it.
            complete = False
            reason = self.continuity_lost
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
        if self.notices:
            detail["sourceNotices"] = list(self.notices)
        return CaptureResult(self.records, detail, self.scope, self.limits, complete, reason)
