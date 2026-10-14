# Phorvex Verification Loop — Rev 5 handoff (read this first)

This is the complete, self-contained package for the verification loop and its attack-coverage library. Everything here supersedes the earlier Rev 4 / Rev 4.2 package. Do not mix in the old `Rev4.docx` or the old `WS-2-generator.md` — they are replaced here.

## What the system is (one paragraph)
Phorvex builds a reviewed library of attacker **end states** (from public threat frameworks), scans a customer stack to see which apply, then runs an adversarial competition on an isolated twin where Phorvex's own deterministic brain decides which actuator truly removes each end state — and, when none does, a design round synthesises a new actuator spec. Agents never author attacks; they select library entries and fit them to the stack. No LLM is ever in the decision path.

## Files, in reading order
1. **`Phorvex-Verification-Loop-Architecture-Rev5.docx`** — the spec to build to. The library is Appendix A, the Rev 5 change set is Appendix B, the new generator is Appendix C.
2. **`library/WS-8-attack-library.md`** — the attack-coverage library, human-readable, with the **actuator-gap table** (the build backlog) at the top.
3. **`library/phorvex-attack-library.csv`** / **`.yaml`** — the same library, machine-readable. Your code loads this. 700 entries (all six sources, complete).
4. **`workstreams/WS-2-generator-REV5.md`** — the generator as **select-and-fit** (replaces the old WS-2).
5. **`workstreams/WS-1,3,4,5,6,7`** — the Rev 4 workstream detail: scan, validator, consensus, brain-in-loop, RL hook, external SOTA.
6. **`sources/ATLAS-2026.09.yaml`** — the MITRE ATLAS data release, for rebuilding/refreshing the library.

## Precedence (so the files stay cohesive)
Where WS-1, WS-3 or WS-4 still describe the generator as *authoring* attacks (Rev 4 wording), the **Rev 5 docx + WS-2-generator-REV5.md win**: the generator selects library entries, it does not invent attacks (Rail 9). Everything else in WS-1/3/4/5/6/7 stands.

## The pipeline (what to build)
- **Stage 0 — build the library.** Load the six sources into the CSV schema. Humans/partner review entries; agents never write attacks.
- **Stage 1 — scan & select.** Scan the stack → facts. An entry applies when its `preconditions` hold. Selection agents bind applying entries to real workloads and fit parameters.
- **Loop — compete (unchanged, docx §3).** Per applied entry: stand up the end-state fixture on the twin → deterministic gate C1–C6 confirms it's real → validator proposes an actuator → the brain decides → G1 probe proves the end state is gone → seven-metric verdict → re-attack until STABLE or CANNOT-HELP.
- **Design round (docx §3.4).** A bucket-3 entry with no passing actuator triggers actuator synthesis, limited to the surfaces Phorvex can reach.

## The library at a glance (700 entries)
- Sources (ALL included, every technique bucketed): ATLAS 2026.09 (120+88 subs) · ATT&CK on Containers/IaaS/Linux (172 top-level + 233 subs) · Microsoft Threat Matrix for K8s (40) · OWASP LLM01-10/ASI01-10/MCP01-10 · NIST AI 100-2 (12) · AVID (5).
- Buckets: 148 covered · 100 after-effect · 12 design-stage · 440 out-of-scope (each with a reason).
- `actuator_status` vs the code's real `MutatingActions`: `exists` (rotate/quarantine), `partial` (label-only M-33, conditional M-35, PENDING-GPU / CRD M-2), `needs-build` (no actuator yet).

## Build priority (from the WS-8 actuator-gap table)
1. Finish `identity-rotate` / `route-rotate` (label-only today; ~21 techniques).
2. Build `registry-rollback` (~20) and `key-rotate` (~14).
3. Build the node actuator (cordon/drain/replace; ~9) and the serving-state restores (RAG/context/tool re-pin).
`rotate` and `quarantine` already work — they cover the ~50 `exists` entries today.

## Selection criterion (applied uniformly to ALL six sources)
Include EVERY technique from every source, then bucket each with ONE rule: does it leave an end state on infrastructure Phorvex can act on (k8s-api/cni/node/serving/identity/artifact/agent)?
- yes, an existing actuator removes it -> bucket 1
- yes, but only by rolling back/evicting the persisted state -> bucket 2
- yes, infra-reachable, but no actuator yet -> bucket 3 (design roster)
- no (in-request, off-system, host/cloud-level, training-time, knowledge-only) -> bucket 4, kept WITH its reason.
ATT&CK is scoped by platform tag {Containers, IaaS, Linux}; Windows/macOS/network/mobile techniques are out of Phorvex's universe and excluded by that tag, not by judgment.

## Two review gates BEFORE any build (do not skip)
1. **Zeinab (math/scope):** confirm the `bucket`, `actuator_status` and `preconditions` columns in the CSV. They are a first pass derived from the code and the CIS/NSA-CISA categories, not verified per entry.
2. **Library refresh at build time:** re-pull ATT&CK (STIX), the OWASP Agentic/MCP lists, the Microsoft matrix and NIST AI 100-2 from source, and confirm the ATLAS sub-technique mappings (they currently inherit their parent's bucket).
