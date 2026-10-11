#!/usr/bin/env python3
"""Compile the reviewed V4 sources into a portable, self-contained manual."""
from pathlib import Path
import hashlib
import json
import re


BASE = Path(__file__).resolve().parent
PARTS = [
    ("A", "Architecture and orchestration", "ARCHITECTURE-V4.md"),
    ("B", "Shared contract and complete role prompts", "PROMPTS-V4.md"),
    ("C", "Original-source requirements and traceability", "SOURCE-REQUIREMENTS-V4.md"),
    ("D", "Implementation readiness at the inspected source revision", "IMPLEMENTATION-READINESS-V4.md"),
    ("E", "Independent specification review and its limits", "REVIEW-V4.md"),
    ("F", "Independent readiness review and current-main compatibility", "READINESS-REVIEW-V4.md"),
]


def portable(text: str) -> str:
    """Keep meaning; remove server-specific navigation and deepen headings."""
    text = text.replace("/home/mehrdad/verification-loop", "the owner-supplied source package")
    text = re.sub(r"\[([^\]]+)\]\((?!https?://)[^\)]+\)", r"\1", text)
    return re.sub(r"(?m)^(#{1,5}) ", r"#\1 ", text)


def main() -> None:
    review = json.loads((BASE / "REVIEW-V4.json").read_text())
    expected = {
        Path(item["path"]).name: item["sha256"]
        for item in review["inputs"]
        if item["kind"] == "reviewed_specification"
    }
    readiness_review = json.loads((BASE / "READINESS-REVIEW-V4.json").read_text())
    for item in readiness_review["inputs"] + readiness_review["output_refs"]:
        name = Path(item["path"]).name
        if (BASE / name).is_file():
            expected[name] = item["sha256"]
    for item in review["output_refs"]:
        expected[Path(item["path"]).name] = item["sha256"]
    content = {}
    for _, _, name in PARTS:
        raw = (BASE / name).read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if name in expected and digest != expected[name]:
            raise ValueError(f"Accepted specification changed: {name}")
        content[name] = (raw.decode(), digest)

    head = """# Phorvex agentic verification workflow V4

This is the portable manual for running the boss's verification loop with agents.
It contains the agents, their full prompts, stage inputs and outputs, interactions,
tools, metrics, failure routes, adaptive rounds, actuator implementation path and
source traceability. It can be read independently of the author's server.

**Specification status: independently accepted. Runnable full-workflow status:
not yet established.** The specification review found no remaining design
blockers. It identified implementation and evidence prerequisites that must be
closed before a physical competition. Accepted design is not a passing test.

The original requirement package consists of the boss's architecture DOCX and
seven Markdown workstreams. The DOCX was supplied by the boss; this workflow did
not author or modify it. Part C records all eight original hashes, interpretation
conflicts and 46 individually traceable requirements.

The previous limited live loop was stopped at the owner's request. Its failures
and independently verified cleanup remain historical evidence. A new competition
uses new prospective scope, source pins, reviewed tools and leases; it does not
inherit an expired execution window or replace failed results with new wording.

## How to read and launch

For understanding the process, read Part A. For directing agents, apply Part B's
shared contract plus the assigned role prompt. Part C checks fidelity to the
original request. Part D distinguishes available code from proposed tools; it is
a dated source inspection, not current runtime admission. Part E explains the
independent design review and its explicit empirical limits. Part F preserves
the map's historical source pins and adds independently inspected compatibility
with the newly integrated main revision. Neither is runtime attestation.

An orchestrator must read the complete manual before assigning bounded worker
context. Workers need their role, applicable stage and gates, exact task envelope
and accepted dependency references. Giving every worker the full repository or
granting authority through workload text is neither necessary nor safe.

There are 13 logical roles. They are scheduled jobs, not 13 permanent processes.
Proposal, critique, read-only scan and independent twin analysis can fan out.
Physical actions sharing resources serialize. Additional agents improve coverage
only when the scheduler can supply distinct evidence-backed tasks and resources.
A 100-item catalogue is a coverage target to be measured, not a guaranteed result
from selecting a large agent count.

Copyable launch instruction:

> Act as ORCH for this manual. Bind the owner's current scope, repository and
> runtime access references without printing secrets. Verify the source revision
> and implemented tool descriptors. Create the trusted task registry and numeric
> resource, duration and cost budgets. Assign bounded roles from Part B, preserving
> author/reviewer/executor separation. Start S0 and close the actual readiness
> prerequisites before physical effects. Execute the complete S0–S10 competition
> with C1–C6, real baselines, unchanged brain choice, G1–G3 and measured scores,
> persistent winners, complete re-attack accounting, fresh reproduction and safe
> cleanup. Record original evidence and precise unavailable criteria. Do not call
> a partial trial complete, dispatch defended, unknown zero, or a vote truth. Do
> not implement LangGraph until the architecture has empirical acceptance.

## Exact compiled component revisions

This file is a generated reading copy of the editable sources below. The only
transformations are deeper headings, local link labels replacing navigation, and
the original server path replaced by a source-package description. Their full
substantive text is preserved. Original raw hashes identify source files before
those formatting transformations. Regenerate when a component changes.

| Part | Component | SHA-256 |
| --- | --- | --- |
"""
    for letter, _, name in PARTS:
        head += f"| {letter} | `{name}` | `{content[name][1]}` |\n"
    sections = [head]
    for letter, title, name in PARTS:
        sections.append(f"\n# Part {letter}: {title}\n\n" + portable(content[name][0]))
    rendered = "\n".join(sections).rstrip() + "\n"
    if "/home/mehrdad" in rendered:
        raise ValueError("Portable manual contains a server-specific path")
    (BASE / "WORKFLOW-V4.md").write_text(rendered)
    print(f"Compiled {len(PARTS)} complete parts; {len(rendered.encode())} bytes")


if __name__ == "__main__":
    main()
