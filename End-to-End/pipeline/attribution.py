"""Binding an observed reaction to the signal we actually injected.

"An action happened in the target namespace after we fired" is not causality. The namespace
is under continuous operator control: a proactive-cadence rotation, another detector's
event, or a decision already in flight when the stream opened all produce exactly that
shape. A05 used to accept it, which is why an E2E run could report a defended attack it had
not caused.

Causal attribution needs two identities inside the decision record itself:

  * the event identity — the UID of the SecurityEvent we created, not its name. A name can
    be recycled, and a name match cannot survive an event being recreated between runs.
  * the target identity — the UID of the Pod the decision is about, so a decision about a
    different instance under the same name cannot answer for ours.

Neither exists in `phorvex.audit.v2` today: the record carries `events[].name` and a Pod
*name*. PR171/M18 adds the forensic event UID. So this module feature-detects the fields
rather than assuming them, and when they are absent it reports `unsupported` — a declared
coverage gap. It never falls back to matching the target alone, because that fallback is
the defect.
"""

# Where a forensic event UID would appear. Top-level first, then inside the per-asset event
# evidence array the current schema already emits (model.EventEvidence).
EVENT_UID_PATHS = (("eventUID",), ("securityEventUID",), ("events", "uid"), ("events", "eventUID"))
EVENT_NAME_PATHS = (("events", "name"),)
TARGET_UID_PATHS = (("podUID",), ("targetUID",), ("assetUID",))

FULL = "event-uid"        # event UID and target UID are both present in the schema
NAME_ONLY = "event-name"  # the event is named but not UID-bound; not causal evidence
NONE = "none"             # no correlation field at all

CORRELATED = "correlated"
UNSUPPORTED = "unsupported"
UNAVAILABLE = "unavailable"


def _values(record, path):
    """Read a top-level key, or a key inside each item of a top-level list of objects."""
    if len(path) == 1:
        value = record.get(path[0])
        return {value} if isinstance(value, str) and value else set()
    outer, inner = path
    found = set()
    for item in record.get(outer) or []:
        if isinstance(item, dict):
            value = item.get(inner)
            if isinstance(value, str) and value:
                found.add(value)
    return found


def _has_field(record, path):
    """Presence of the KEY, independent of its value — that is what feature detection is."""
    if len(path) == 1:
        return path[0] in record
    outer, inner = path
    return any(isinstance(item, dict) and inner in item for item in record.get(outer) or [])


def event_uids(record):
    return set().union(*(_values(record, p) for p in EVENT_UID_PATHS)) if record else set()


def event_names(record):
    return set().union(*(_values(record, p) for p in EVENT_NAME_PATHS)) if record else set()


def target_uids(record):
    return set().union(*(_values(record, p) for p in TARGET_UID_PATHS)) if record else set()


def detect_support(records):
    """What this stream of records is capable of proving about cause."""
    records = records or []
    has_event_uid = any(_has_field(r, p) for r in records for p in EVENT_UID_PATHS)
    has_target_uid = any(_has_field(r, p) for r in records for p in TARGET_UID_PATHS)
    if has_event_uid and has_target_uid:
        return FULL
    if any(_has_field(r, p) for r in records for p in EVENT_NAME_PATHS):
        return NAME_ONLY
    return NONE


SUPPORT_REASON = {
    FULL: "the audit records carry a forensic event UID and a target Pod UID",
    NAME_ONLY: ("the audit records name the event but carry no forensic event UID and no "
                "target Pod UID (PR171/M18 supplies them); a name is not a causal identity"),
    NONE: "the audit records carry no event or target identity at all",
}


class Correlator:
    """Decides, per record, whether it can be attributed to one injection.

    `injection` is the record the detector kept from the CREATE response — event UID and
    name, target namespace/pod/UID, and the time the API server stamped on it.
    """

    def __init__(self, injection, records=()):
        self.injection = injection or {}
        self.support = detect_support(records)

    @property
    def supported(self):
        return self.support == FULL and bool(self.injection.get("eventUID"))

    def describe(self):
        if self.support == FULL and not self.injection.get("eventUID"):
            return ("the records support UID correlation but this run recorded no event UID "
                    "for its injection")
        return SUPPORT_REASON[self.support]

    def classify(self, record):
        """(status, detail) for one record. Never `correlated` without both UIDs."""
        if not self.supported:
            return UNSUPPORTED, self.describe()
        want_event = self.injection["eventUID"]
        want_target = self.injection.get("targetUID")
        uids = event_uids(record)
        if want_event not in uids:
            return UNAVAILABLE, (
                f"this decision carries event UID(s) {sorted(uids) or '—'}, not the injected "
                f"{want_event[:8]}")
        if want_target:
            targets = target_uids(record)
            if want_target not in targets:
                return UNAVAILABLE, (
                    f"the decision is bound to the injected event but to target UID(s) "
                    f"{sorted(t[:8] for t in targets) or '—'}, not {want_target[:8]}")
        return CORRELATED, (
            f"bound to injected event {want_event[:8]}"
            + (f" and target {want_target[:8]}" if want_target else ""))

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
