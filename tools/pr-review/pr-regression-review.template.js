export const meta = {
  name: 'pr-regression-review',
  description: 'PHORVEXSEC-81 sub-ticket 5: review a PR for regressions, semantic conflicts and cross-module impact; every finding must cite evidence or it is dropped',
  whenToUse: 'After opening or updating a PR, to check the new commit did not break anything elsewhere.',
  phases: [
    { title: 'Scope', detail: 'read the diff and extract changed contracts' },
    { title: 'Find', detail: 'parallel reviewers, one per failure mode' },
    { title: 'Verify', detail: 'adversarial check — evidence or drop' },
    { title: 'Report', detail: 'structured verdict' },
  ],
}

const REPO = args?.repo ?? 'PhorvexSecurity/operator'
const PR = String(args?.pr ?? '')
const WD = args?.workdir ?? '.'
// The diff is fetched by the CALLER and passed in. Do NOT make agents fetch it: workflow
// subagents inherit the session cwd, so a bare `gh pr diff N` / `git diff` silently reviews
// whatever repo the session happens to sit in. (Learned the hard way — the first run reviewed
// the chat app's dirty working tree instead of this PR.)
const DIFF = args?.diff ?? ''
const FILES = args?.files ?? []
const CHANGES = (typeof TARGET !== "undefined" ? TARGET.changes : args?.changes) ?? []
const OVERLAP = (typeof TARGET !== "undefined" ? TARGET.overlap : args?.overlap) ?? {}

// FAIL FAST — never spawn reviewers against an empty/absent target. A reviewer that finds nothing
// because it was handed nothing is indistinguishable from a clean PR, which is the single most
// dangerous output this workflow could produce.
log(`args: pr=${JSON.stringify(PR)} workdir=${JSON.stringify(WD)} diff_chars=${DIFF.length} files=${FILES.length}`)
if (!PR) throw new Error('no PR number supplied (args.pr) — refusing to review')
if (!DIFF.trim()) throw new Error('empty diff supplied (args.diff) — refusing to review; an empty result would read as "clean"')
if (!WD || WD === '.') throw new Error(`workdir must be an absolute checkout path, got ${JSON.stringify(WD)} — agents inherit an unrelated session cwd`)
if (!FILES.length) throw new Error('no changed-file list supplied (args.files) — the wrong-repo guard cannot run without it')

const SCOPE_SCHEMA = {
  type: 'object',
  required: ['summary', 'changed_files', 'changed_contracts', 'risk_areas'],
  properties: {
    summary: { type: 'string', description: 'what this PR changes, 2-3 sentences' },
    changed_files: { type: 'array', items: { type: 'string' } },
    changed_contracts: {
      type: 'array',
      description: 'exported/shared things whose behaviour or shape changed: function signatures, sentinel errors, struct fields, config keys, label/annotation names, JSON schemas',
      items: {
        type: 'object',
        required: ['name', 'kind', 'where', 'what_changed'],
        properties: {
          name: { type: 'string' }, kind: { type: 'string' },
          where: { type: 'string', description: 'file:line' },
          what_changed: { type: 'string' },
        },
      },
    },
    risk_areas: { type: 'array', items: { type: 'string' }, description: 'concrete things a reviewer should check elsewhere in the repo' },
  },
}

const FINDINGS_SCHEMA = {
  type: 'object',
  required: ['findings'],
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        required: ['severity', 'component', 'description', 'evidence', 'suggested_fix'],
        properties: {
          severity: { type: 'string', enum: ['fail', 'warn', 'info'] },
          component: { type: 'string' },
          description: { type: 'string' },
          evidence: { type: 'string', description: 'CONCRETE: file:line plus the actual code/value. A finding without this is invalid.' },
          suggested_fix: { type: 'string' },
        },
      },
    },
  },
}

const VERDICT_SCHEMA = {
  type: 'object',
  required: ['stands', 'reason', 'checked'],
  properties: {
    stands: { type: 'boolean', description: 'true only if you could CONFIRM the finding by reading the code' },
    reason: { type: 'string' },
    checked: { type: 'string', description: 'what you actually looked at (file:line)' },
    corrected_severity: { type: 'string', enum: ['fail', 'warn', 'info'] },
  },
}

const CTX = `You are reviewing PR #${PR} of ${REPO}.

>>> THE ONLY REPOSITORY YOU MAY LOOK AT IS: ${WD}
Every path you read, grep or cite MUST be under ${WD}. Prefix every shell command with
\`cd ${WD} && \`. Your shell starts in a DIFFERENT, unrelated repository — if you run a bare
\`git diff\`, \`gh pr diff\` or \`grep\` you will silently review the wrong project. If a file you
expect is missing, you are in the wrong directory: re-run with the absolute path under ${WD}.
Sanity check before you start: \`cd ${WD} && git rev-parse --show-toplevel\` must print ${WD}.

${CHANGES.length > 1 ? `THIS IS A BATCH REVIEW OF ${CHANGES.length} CHANGES that are candidates to land together:
${CHANGES.map(c => `  PR #${c.pr}: ${c.title}`).join('\n')}
${Object.keys(OVERLAP).length ? `Files touched by more than one of them (the obvious interaction surface):
${Object.entries(OVERLAP).map(([f, prs]) => `  ${f}  <- PRs ${prs.join(', ')}`).join('\n')}` : 'No file is touched by more than one PR — interactions, if any, are BEHAVIOURAL rather than textual.'}
Judge them BOTH individually AND as a set.` : ''}

The full PR diff is included below — do NOT fetch it yourself.
Files changed by this PR (relative to ${WD}):
${FILES.length ? FILES.map(f => '  ' + f).join('\n') : '  (see diff)'}

--- BEGIN PR DIFF ---
${DIFF}
--- END PR DIFF ---

The merge base is origin/main. You may read any file under ${WD} and run read-only git/grep/go
commands there. Do NOT modify any file. Do NOT push. Do NOT comment on the PR.`

phase('Scope')
const scope = await agent(
  `${CTX}

Read the PR diff above and produce a precise scope map for downstream reviewers.

For changed_contracts, list ONLY things other code could depend on: exported/shared function
signatures, sentinel error values, struct fields, config keys, label/annotation string constants,
JSON/schema shapes, and error-classification behaviour. For each, give file:line and what changed.

For risk_areas, name CONCRETE things to check elsewhere (e.g. "other callers of X still use the old
classification"), not generic advice.`,
  { label: 'scope', schema: SCOPE_SCHEMA },
)

log(`scope: ${scope.changed_files.length} files, ${scope.changed_contracts.length} changed contracts`)

// GUARD: if the scope agent came back with files that are not in the PR, it looked at the wrong
// repo (the failure mode that wasted a whole run once). Fail loudly instead of reviewing fiction.
if (FILES.length) {
  const expected = new Set(FILES.map(f => f.split('/').pop()))
  const got = scope.changed_files.map(f => f.split('/').pop())
  const stray = got.filter(f => !expected.has(f))
  if (stray.length && stray.length === got.length) {
    throw new Error(`WRONG REPOSITORY: scope reported ${JSON.stringify(got.slice(0,5))} but this PR touches ${JSON.stringify(FILES)}. The agent read a different checkout.`)
  }
  if (stray.length) log(`warning: scope listed ${stray.length} file(s) not in the PR: ${stray.slice(0,3).join(', ')}`)
}

const contracts = scope.changed_contracts
  .map(c => `- ${c.kind} ${c.name} @ ${c.where}: ${c.what_changed}`).join('\n') || '(none identified)'

const BASE = `${CTX}

PR SUMMARY: ${scope.summary}

CHANGED CONTRACTS:
${contracts}

RULES:
- Every finding MUST cite concrete evidence: file:line plus the actual code or value. A finding you
  cannot evidence is not a finding — omit it.
- severity "fail" is ONLY for something you can PROVE is broken (a caller that will now misbehave, a
  contract used elsewhere and not updated, a test that would fail). Anything you merely suspect, or
  that is a matter of taste, is "warn" or "info".
- The PR being incomplete-by-design (e.g. deliberately out of scope, documented as such) is NOT a fail.
- Report nothing rather than pad the list.`

const INTERACTION_LENS = {
  key: 'cross-change-interaction',
  prompt: `${BASE}

LENS: CROSS-CHANGE INTERACTION — the reason these changes are reviewed together.

A change can be individually correct and still be unsafe to land ALONE or in the wrong ORDER. Look
for exactly that, across the ${CHANGES.length} changes:

- Does one change make a code path REACHABLE that another change is required to make safe? (A branch
  that was previously dead, or reached only via an error path, now executes in normal operation.)
- Does one change rely on a guarantee that another change introduces? What breaks if only the first
  lands?
- Do two changes edit the same file/function in ways that merge cleanly but combine wrongly?
- Do they both touch a shared contract (a sentinel error, an annotation, a metric, a record field)
  in ways that only make sense together?
- Follow the consumers: if change A alters WHEN a value is written, find who READS that value and
  check whether change B is what keeps their interpretation correct.

For every interaction, state explicitly: what happens if ONLY change X lands, and what the required
merge order is. Severity "fail" if landing one alone is provably harmful.` }

const LENSES = [
  { key: 'semantic-conflict', prompt: `${BASE}

LENS: SEMANTIC CONFLICT — changes that merge cleanly but break assumptions elsewhere.
For each changed contract, grep the whole repo for OTHER uses and check each one still holds.
Especially: sibling functions that are supposed to agree but now do not, callers relying on the old
error/return behaviour, string constants duplicated elsewhere, and config/label keys read in another
package.` },
  { key: 'cross-module-impact', prompt: `${BASE}

LENS: CROSS-MODULE IMPACT — for each changed interface, find EVERY call/usage site in the repo and
state whether the PR updated it. List any that were not updated and explain what will happen.
Follow the real call chain (runner -> decision -> cost/actuator -> ingest), do not guess.` },
  { key: 'correctness', prompt: `${BASE}

LENS: CORRECTNESS — bugs in the changed lines themselves. Off-by-one, inverted conditions, nil/NaN
handling, error paths that lose information, partial mutation followed by an error return, resources
left in an inconsistent state.` },
  { key: 'test-adequacy', prompt: `${BASE}

LENS: TEST ADEQUACY — does a test actually FAIL if this change is reverted? Identify the tests that
cover the changed behaviour and judge whether they would catch a regression. A change with no test
that can fail is a "warn" (or "fail" if it is a fix for a previously-shipped bug). Also flag tests
that assert only "no error" where the point of the change is a specific value.` },
  { key: 'contract-stability', prompt: `${BASE}

LENS: DATA/AUDIT CONTRACT — does the PR change anything observable to consumers: emitted metrics,
audit/decision record fields, JSON shapes, annotation/label names, or ordering that something else
hashes or diffs? Flag anything that would silently alter a downstream artefact.` },
]

if (CHANGES.length > 1) LENSES.unshift(INTERACTION_LENS)

phase('Find')
const perLens = await pipeline(
  LENSES,
  l => agent(l.prompt, { label: `find:${l.key}`, phase: 'Find', schema: FINDINGS_SCHEMA }),
  (res, lens) => {
    const fs = (res?.findings ?? []).map(f => ({ ...f, lens: lens.key }))
    if (!fs.length) return []
    return parallel(fs.map(f => () =>
      agent(`${CTX}

A reviewer raised this finding on PR #${PR}. Your job is to REFUTE it if you can.

  severity: ${f.severity}
  component: ${f.component}
  claim: ${f.description}
  evidence offered: ${f.evidence}

Go read the actual code. Decide whether the claim is TRUE as stated.
Set stands=false if: the evidence does not say what the reviewer claims, the behaviour is already
handled elsewhere, it is intentional and documented, or you cannot confirm it by reading code.
Default to stands=false when uncertain. Record in "checked" exactly what you read (file:line).`,
        { label: `verify:${f.component}`.slice(0, 40), phase: 'Verify', schema: VERDICT_SCHEMA })
        .then(v => ({ ...f, verdict: v }))
        .catch(() => null)
    ))
  },
)

const all = perLens.flat().filter(Boolean)
const confirmed = all.filter(f => f.verdict?.stands)
  .map(f => ({ ...f, severity: f.verdict.corrected_severity || f.severity }))
const dropped = all.filter(f => !f.verdict?.stands)

log(`${all.length} raised · ${confirmed.length} confirmed · ${dropped.length} refuted`)

phase('Report')
const fails = confirmed.filter(f => f.severity === 'fail')
const warns = confirmed.filter(f => f.severity === 'warn')
const infos = confirmed.filter(f => f.severity === 'info')

const summary = await agent(
  `${CTX}

Write a short reviewer-facing summary of PR #${PR}.

PR does: ${scope.summary}

CONFIRMED findings (each already survived an independent refutation attempt):
${confirmed.length ? confirmed.map(f => `[${f.severity}] (${f.lens}) ${f.component}: ${f.description}\n    evidence: ${f.evidence}\n    fix: ${f.suggested_fix}`).join('\n') : '(none)'}

REFUTED and dropped: ${dropped.length}
${dropped.slice(0, 8).map(f => `  - ${f.component}: ${f.description.slice(0, 90)} -> ${f.verdict?.reason?.slice(0, 110)}`).join('\n')}

Write plain markdown, no preamble. Lead with the verdict and WHY. Be concrete and brief. If there
are no confirmed findings, say so plainly and note what was checked — do not invent concerns.`,
  { label: 'summary', phase: 'Report' },
)

const interaction = confirmed.filter(f => f.lens === 'cross-change-interaction')

return {
  pr: PR,
  changes: CHANGES.map(c => `#${c.pr} ${c.title}`),
  merge_order_risk: interaction.length
    ? interaction.map(f => ({ severity: f.severity, what: f.description, evidence: f.evidence }))
    : (CHANGES.length > 1 ? 'none found — each change appears safe to land independently' : 'n/a (single change)'),
  status: fails.length ? 'fail' : (warns.length ? 'warn' : 'pass'),
  counts: { raised: all.length, confirmed: confirmed.length, refuted: dropped.length, fail: fails.length, warn: warns.length, info: infos.length },
  findings: confirmed.map(f => ({
    severity: f.severity, lens: f.lens, component: f.component,
    description: f.description, evidence: f.evidence, suggested_fix: f.suggested_fix,
    verified_by_reading: f.verdict?.checked,
  })),
  refuted: dropped.map(f => ({ component: f.component, claim: f.description, why_dropped: f.verdict?.reason })),
  summary,
}
