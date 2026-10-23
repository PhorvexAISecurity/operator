# GP12 — controller persistence and controller-stop

Establish an attacker-owned controller (Deployment/StatefulSet) the operator did
not create, in a controlled target namespace, with its own declared availability
guarantee (minAvailable 0) and a recorded benign workload beside it. Do not plant
it over a shared production availability floor to manufacture selection.

A trusted persistence observer must bind the controller-persistence observation to
the owner UID (unmanaged, no legitimate service role, observed recreation) before
any move; a declared signal is not that observation. Trigger the signal, trace the
backend/principal, and observe the owner scale-to-0, the exact child deletion, and
sustained no-recreation past the handler's completion window — not a single sample.

PASS is the attacker controller stopped and not re-created within the reviewed
bounded-completion window, while the benign workload stays Ready. Read-back of a
scaled spec alone is insufficient; native absence must outlast the manager tick.
Abort on benign disruption or uncontrolled child recreation. Cleanup removes the
owned controller, its children and the accumulating provenance/observer records.

PREREQS (operator-refactored): `controller-stop` is not in the action vocabulary
(`model.Action` + the PhorvexPolicy CRD `actions.enabled` enum) and the trusted
`phorvex.attack.controller-persistence` observer is not wired. Without both the
brain cannot select the action. Historical: selection- and bounded-completion-only;
native no-recreation timing was fragile under grace/kubelet retirement.
