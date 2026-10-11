#!/usr/bin/env python3
"""Compile complete V5 source-reviewed documents into one portable manual."""

from pathlib import Path
import hashlib
import json
import re


BASE = Path(__file__).resolve().parent
PARTS = (
    ("A", "Architecture, roles and orchestration", "ARCHITECTURE-V5.md"),
    ("B", "Complete agent prompts and handoff contracts", "PROMPTS-V5.md"),
    ("C", "Boss Revision 4 requirements and traceability", "SOURCE-REQUIREMENTS-V5.md"),
    ("D", "Independent architecture and prompt review", "REVIEW-ARCHITECTURE-V5.md"),
    ("E", "Independent requirements-map review", "REVIEW-SOURCE-REQUIREMENTS-V5.md"),
)
REVIEWS = ("REVIEW-ARCHITECTURE-V5.json", "REVIEW-SOURCE-REQUIREMENTS-V5.json")
REVIEW_PINS = {
    "REVIEW-ARCHITECTURE-V5.json": "9a7252df630686355114e73bc7a5c9116ab6802bc1e800d82f31f9ad29f8d4ea",
    "REVIEW-ARCHITECTURE-V5.md": "ebb8d01331de545335898d405bd1f934a3d753e062f4506ab0e09cc41e898e07",
    "REVIEW-SOURCE-REQUIREMENTS-V5.json": "f09c297acc6f6b15327b151a5acd1f598842e4ee4d396fd33810ec331b5ce336",
    "REVIEW-SOURCE-REQUIREMENTS-V5.md": "f16efa705f8298527fb2fc53aeed27d16ac59d4fc704bf7ba5394f5c81059615",
}


def portable(text):
    # Keep all substantive prose, tables and examples; remove local navigation.
    text = re.sub(r"\[([^\]]+)\]\(<[^>]+>\)", r"\1", text)
    text = re.sub(r"\[([^\]]+)\]\((?!https?://)[^\)]+\)", r"\1", text)
    text = text.replace("/home/mehrdad/verification-loop-rev4", "the owner-supplied Revision 4 source package")
    text = text.replace("/home/mehrdad/verification-loop", "the original owner-supplied source package")
    text = re.sub(r"(?m)^(#{1,5}) ", r"#\1 ", text)
    if "/home/mehrdad" in text:
        raise ValueError("Source contains an unhandled server-specific path")
    return text


def main():
    for name, pin in REVIEW_PINS.items():
        if hashlib.sha256((BASE / name).read_bytes()).hexdigest() != pin:
            raise ValueError("Independently accepted review changed: " + name)
    expected = {}
    for name in REVIEWS:
        review = json.loads((BASE / name).read_text())
        if review["disposition"] != "ACCEPT_DESIGN_SOURCE_CONFORMITY":
            raise ValueError("Required source-conformity acceptance missing: " + name)
        if review["reviewer"] == review["artifact_author"]:
            raise ValueError("Self-review cannot accept a manual component")
        for item in review["reviewed_artifacts"]:
            filename = Path(item["path"]).name
            if filename in expected and expected[filename] != item["sha256"]:
                raise ValueError("Conflicting reviewed component pins")
            expected[filename] = item["sha256"]
    required = {name for _, _, name in PARTS[:3]}
    if not required <= expected.keys():
        raise ValueError("Complete architecture, prompts and map are not independently accepted")
    content = {}
    for _, _, name in PARTS:
        raw = (BASE / name).read_bytes()
        sha = hashlib.sha256(raw).hexdigest()
        if name in expected and sha != expected[name]:
            raise ValueError("Reviewed specification changed: " + name)
        content[name] = (raw.decode(), sha)

    intro = """# Phorvex agentic verification workflow V5

This is the complete portable agentic architecture for the boss's **Revision 4**
verification-loop package. It includes roles, responsibilities, goals, full agent
prompts, stage inputs and outputs, scheduling, tools, interactions, failure routes,
the new actuator-design/engineering branch, seven metric fields and source
traceability. Boss Revision 4 and workflow V5 are different version identifiers.

**Specification status: independently accepted for source conformity.
Full current physical-loop completion: not established by this manual.**
The separate run report and independently reviewed original evidence establish
what was actually executed. A design review cannot prove defense or availability.

An orchestrator on another harness can read this file without the author's server.
Runtime access, actual implemented tool descriptors, reviewed source revisions,
scope, numeric budgets and independent actors must still be bound before launch.
Logical tool names in the architecture do not by themselves supply executable
adapters. LangGraph implementation remains the next engineering phase after
empirical validation; this manual is not a deployed LangGraph service.

## How to use the manual

Read Part A for orchestration and role assignment. Apply Part B's shared prompt
contract plus each bounded role prompt. Part C provides the 52 source requirements
and the interpretations of conflicting source wording. Parts D and E record exact
independent source-conformity reviews and their limits. Historical V4 documents
and failed experiments remain immutable evidence; do not substitute their results
for a new V5 run.

Copyable launch instruction:

> Act as ORCH for this manual. Bind current owner scope, repository/runtime access
> references, actual reviewed tool/source/configuration identities, numeric budgets
> and independent actor assignments. Read the full manual, then give each agent its
> shared contract, role prompt, exact bounded task and accepted dependencies. Run
> the complete competition: scan, prepare a persistent isolated twin, qualify and
> physically confirm the attack, obtain the unchanged brain's normal decision,
> execute only the selected reviewed response, measure G1–G3 and S1 with all seven
> metric fields present, preserve winners, and complete winner-conditioned
> re-attack and independent fresh reproduction with safe cleanup. If a genuinely
> confirmed attack exhausts the enabled responses, preserve that result and invoke
> spec-only DESIGN, separate ENGINEER implementation, independent review and a
> newly pinned competition re-entry without resetting budgets. Missing evidence
> is incomplete, not CANNOT_HELP or defense. Never force a winner, promote a vote,
> tune the brain to pass, reuse expired evidence, or report dispatch as mitigation.

## Exact compiled components

This generated reading copy preserves the complete substantive source text.
Only heading depth, local navigation and source-package path descriptions change.
The hashes below identify the original components before those transformations.

| Part | Component | SHA-256 |
| --- | --- | --- |
"""
    for letter, _, name in PARTS:
        intro += f"| {letter} | `{name}` | `{content[name][1]}` |\n"
    sections = [intro]
    for letter, title, name in PARTS:
        sections.append(f"\n# Part {letter}: {title}\n\n" + portable(content[name][0]))
    rendered = "\n".join(sections).rstrip() + "\n"
    (BASE / "WORKFLOW-V5.md").write_text(rendered)
    print(f"Compiled {len(PARTS)} complete reviewed parts; {len(rendered.encode())} bytes")


if __name__ == "__main__":
    main()
