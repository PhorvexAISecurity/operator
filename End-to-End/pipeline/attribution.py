"""Binding an observed reaction to the signal we actually injected.

"An action happened in the target namespace after we fired" is not causality. The namespace
is under continuous operator control: a proactive-cadence rotation, another detector's
event, or a decision already in flight when the stream opened all produce exactly that
shape. A05 used to accept it, which is why an E2E run could report a defended attack it had
not caused.

What the deployed schema actually carries — read from the producers, not assumed:

  decisionTrace.assetUID   the UID of the Pod the decision is about (model/decision_trace.go
                           DecisionTraceV2.AssetUID). This is a real target identity and it
                           exists today.
  decisionTrace.policyUID  the owning policy, alongside assetNamespace / assetName.
  events[].name            the names of the SecurityEvents that fed this asset's evidence
                           (model.EventEvidence). Names only — the struct has no UID field.
  phoenix.eventUID         M-18's PhoenixForensics: the UID of the SecurityEvent the
                           ACTUATOR CREATED as its output. Its own doc comment says a
                           populated payload "establishes CORRELATION only" — correlation to
                           the Phoenix resources an investigator must inspect.

That last one is the trap. `phoenix.eventUID` is an OUTPUT identity: it names the event
Phorvex emitted, not the event our detector injected as the cause. Treating them as the
same thing would let a rotation triggered by anything at all correlate to our injection.
They are different objects with different UIDs.

So the honest position is: **no field in any inspected schema carries the injected
detector event's identity.** Detector-cause correlation is therefore genuinely unavailable,
and A05 reports that as a declared coverage gap. `INJECTED_EVENT_UID_PATHS` below is
deliberately empty of real paths; the hypothetical entry is marked as such and exists only
so the day a producer supplies one, the mechanism and its tests are already in place. It
must not be presented as M-18's format.
"""

# Real, verified paths. Each is (path tuple, what the source proves).
TARGET_UID_PATHS = (
    ("decisionTrace", "assetUID"),      # model/decision_trace.go:354 DecisionTraceV2.AssetUID
)
OUTPUT_EVENT_UID_PATHS = (
    ("phoenix", "eventUID"),            # model/types.go:729 PhoenixForensics.EventUID (M-18)
)
EVENT_NAME_PATHS = (
    ("events", "name"),                 # model/eventage.go:36 EventEvidence.Name
    ("phoenix", "eventName"),           # M-18, again the emitted event
)

# HYPOTHETICAL. No inspected producer writes this. It is the shape a field would need if a
# future change recorded the SecurityEvent that CAUSED a decision, and it is listed only so
# the correlation path is exercised. Do not cite it as an existing or planned schema.
HYPOTHETICAL_INJECTED_EVENT_UID_PATHS = (
    ("causeEventUID",),
    ("decisionTrace", "causeEventUID"),
)

FULL = "injected-event-uid"   # hypothetical: the cause's own identity is in the record
OUTPUT_ONLY = "output-event-uid"   # M-18: identifies what Phorvex emitted, not what caused it
NAME_ONLY = "event-name"      # names, which cannot survive recreation
NONE = "none"

CORRELATED = "correlated"
UNSUPPORTED = "unsupported"
UNAVAILABLE = "unavailable"


def _values(record, path):
    """Read a value at a nested path, or at a key inside each item of a list of objects."""
    if not isinstance(record, dict):
        return set()
    if len(path) == 1:
        value = record.get(path[0])
        return {value} if isinstance(value, str) and value else set()
    outer, inner = path
    node = record.get(outer)
    if isinstance(node, dict):
        value = node.get(inner)
        return {value} if isinstance(value, str) and value else set()
    found = set()
    for item in node or []:
        if isinstance(item, dict):
            value = item.get(inner)
            if isinstance(value, str) and value:
                found.add(value)
    return found


def _has_field(record, path):
    """Presence of the KEY, independent of its value — that is what feature detection is."""
    if not isinstance(record, dict):
        return False
    if len(path) == 1:
        return path[0] in record
    outer, inner = path
    node = record.get(outer)
    if isinstance(node, dict):
        return inner in node
    return any(isinstance(item, dict) and inner in item for item in node or [])


def _collect(record, paths):
    return set().union(set(), *(_values(record, p) for p in paths)) if record else set()


def injected_event_uids(record):
    return _collect(record, HYPOTHETICAL_INJECTED_EVENT_UID_PATHS)


def output_event_uids(record):
    return _collect(record, OUTPUT_EVENT_UID_PATHS)


def event_names(record):
    return _collect(record, EVENT_NAME_PATHS)


def target_uids(record):
    return _collect(record, TARGET_UID_PATHS)


def detect_support(records):
    """What this stream of records is capable of proving about cause.

    Only the injected event's own identity supports a causal claim. A target UID is
    necessary but not sufficient — it says which Pod, never which signal.
    """
    records = records or []
    has_target = any(_has_field(r, p) for r in records for p in TARGET_UID_PATHS)
    if has_target and any(_has_field(r, p) for r in records
                          for p in HYPOTHETICAL_INJECTED_EVENT_UID_PATHS):
        return FULL
    if any(_has_field(r, p) for r in records for p in OUTPUT_EVENT_UID_PATHS):
        return OUTPUT_ONLY
    if any(_has_field(r, p) for r in records for p in EVENT_NAME_PATHS):
        return NAME_ONLY
    return NONE


SUPPORT_REASON = {
    FULL: "the records carry the injected event's own identity and a target Pod UID",
    OUTPUT_ONLY: ("the records carry phoenix.eventUID, which identifies the SecurityEvent "
                  "the actuator EMITTED, not the detector event that caused the decision "
                  "(model/types.go PhoenixForensics establishes correlation to Phoenix "
                  "resources only); no inspected schema records the causing event"),
    NAME_ONLY: ("the records name events but carry no event UID; a name cannot survive "
                "recreation and is not a causal identity"),
    NONE: "the records carry no event or target identity at all",
}


class Correlator:
    """Decides, per record, whether it can be attributed to one injection.

    `injection` is what the detector kept from the CREATE response — the event's UID and
    name, the target namespace/pod/UID, and the server's creation timestamp.
    """

    def __init__(self, injection, records=()):
        self.injection = injection or {}
        self.support = detect_support(records)

    @property
    def supported(self):
        return self.support == FULL and bool(self.injection.get("eventUID"))

    def describe(self):
        if self.support == FULL and not self.injection.get("eventUID"):
            return ("the records support cause correlation but this run recorded no event "
                    "UID for its injection")
        return SUPPORT_REASON[self.support]

    def classify(self, record):
        """(status, detail) for one record. Never `correlated` without both identities."""
        if not self.supported:
            return UNSUPPORTED, self.describe()
        want_event = self.injection["eventUID"]
        if want_event not in injected_event_uids(record):
            found = sorted(injected_event_uids(record))
            return UNAVAILABLE, (
                f"this decision names causing event(s) {found or '—'}, not the injected "
                f"{want_event[:8]}")
        # The target UID is required, not optional: a decision bound to our event but about
        # a different Pod instance is not evidence about the Pod we aimed at.
        want_target = self.injection.get("targetUID")
        if not want_target:
            return UNAVAILABLE, ("this run recorded no target Pod UID, so a decision cannot "
                                 "be bound to the instance the event named")
        targets = target_uids(record)
        if want_target not in targets:
            return UNAVAILABLE, (
                f"the decision is bound to the injected event but to target UID(s) "
                f"{sorted(t[:8] for t in targets) or '—'}, not {want_target[:8]}")
        # Namespace and pod name are checked too: they are cheap, and a record that
        # disagrees with the UID on either is malformed rather than merely unrelated.
        for field, expected in (("namespace", self.injection.get("targetNamespace")),
                                ("pod", self.injection.get("targetPod"))):
            if expected and record.get(field) not in (None, expected):
                return UNAVAILABLE, (
                    f"the decision carries the injected target UID but {field}="
                    f"{record.get(field)!r} rather than {expected!r}")
        return CORRELATED, (f"bound to injected event {want_event[:8]} and target "
                            f"{want_target[:8]}")

    def correlated(self, records):
        return [r for r in records if self.classify(r)[0] == CORRELATED]

    def named(self, records):
        """Records naming the injected event. Evidence for a reader, not proof of cause."""
        name = self.injection.get("eventName")
        if not name:
            return []
        return [r for r in records if name in event_names(r)]

    def to_json(self):
        return {"support": self.support, "supported": self.supported,
                "reason": self.describe(), "injection": dict(self.injection)}
