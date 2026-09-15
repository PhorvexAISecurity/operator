# Adapter integrity evidence

`phorvex.ai/lora-enabled` and a Pod's `phorvex.ai/lora-adapter` are workload
configuration. They do not assert poisoning. A detector creates a
`SecurityEvent` with `spec.rule.type: phorvex.attack.adapter`, an exact
`spec.targets` entry `namespace/pod`, and these event annotations:

- `phorvex.ai/adapter-name`: the adapter observed by the detector, 1–128 ASCII
  letters, digits, dots, underscores or hyphens.
- `phorvex.ai/target-pod-uid`: the UID of that exact Pod object.

The existing M94 creator stamp and deny binding authenticate the event creator;
only a configured external detector can contribute evidence. The event needs a
usable creation timestamp and remains active for less than 15 minutes. A fresh
snapshot clears the assertion when the event is deleted, expires, changes target,
or the Pod is recreated. Two valid events naming different adapters for the same
Pod suppress the assertion; equivalent observations choose the smallest event
name and UID for a stable provenance reference. A generic trusted event cannot
authenticate a Pod-provided adapter name.

The native adapter action requires that selected observation and rereads the
event through an authoritative uncached reader and current Pod identity before
calling the serving stack. Deleting or future-dated events refuse dispatch.
Direct/manual
adapter requests lacking the observation return unsupported without a serving
call. A successful unload is confirmed by the serving response; an absent adapter
is an already-met eviction goal. Neither the Pod's operational adapter name nor an
adapter epoch retires a still-live detector event. The detector must resolve or
remove its observation, or the 15-minute bound expires. Clean-source reload and
rollback remain separate questions; this change does not establish a clean
source or serving transport guarantee.
