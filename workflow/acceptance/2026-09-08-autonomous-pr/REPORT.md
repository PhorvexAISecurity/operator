# Autonomous named-fix delivery

User instruction: start an issue and return an independently reviewed PR link without routine human
intervention, while preserving implementation quality. Standing authorization is retained in
operations/AUTONOMY.md and selected by operations/POLICY.yaml.

## Implemented

- New fixes inherit PR-opening scope; `start` records it for an existing selected fix. No merge/deploy
  scope is granted, and held work is not silently resumed. Current M6 has the new PR scope.
- Agents resolve conservative in-scope design/security choices. Named signoffs in older tickets do not
  block proposed code. Three-round escalation is removed; failed invariants still require correction.
- One concise current proposal/critique and a selected decision replace appended repeated summaries.
  Prior evidence/predictions remain retained. Common startup reading fell from 882 to 766 words versus
  committed HEAD (13.2%); maximum common startup plus a stage is 1147 words, within the 1250 budget.
- Implementers can configure only branch/base/head with full existing commit SHAs and ancestry checks;
  they cannot grant authority, change review roles or waive required checks. Configuration validates
  schema before any write, including rejection of the previously accepted unsupported approval keys.
- A changed implementation base requires independent `base_review` bound to both the new base and
  original analysis source, preserving the initial blind seal. This replaces the old unconditional
  baseline-equality rejection; it does not waive integration review. M6's already-reviewed base5a0fd3f
  was signed against its original source79c; the signed M6 design contract remains unchanged.
- AGREED briefs route to implementation/verification instructions. PR_READY leads directly to push/open,
  recording the URL and reviewed head, then IN_PR. Required post-deployment L3/L4 stay pending; IN_PR
  is delivery, not issue closure.
- The bus batches pending notifications and waits for acknowledgement before another wake; handlers drain
  the current inbox. Messages remain durable. The existing supervised adapter was restarted and is active.

## Validation

73 tests passed, including a synthetic complete fresh-fix cycle to IN_PR with recorded standing scope and
no additional approval reference; no real remote PR was created by that test. Negative tests preserve
self-review restrictions, missing/stale incident and P3 gates, source/hash validation, restricted author
configuration, rejection without partial writes, and absence of automatic merge/deploy authority.
Base-review source changes/tampering and bus burst/later-arrival handling are covered.
Deep doctor: zero errors, thirteen pre-existing migration/anatomy/release warnings. git diff --check passed.
After final documentation shortening, all 24 contract tests passed again, including the startup-context budget.

## Scope

No product code changed by this harness task. Claude continues M6 implementation. No blanket verification
waivers, accepted risk, shared-cluster changes or automatic merge were introduced. Missing access or required
evidence is reported honestly rather than converted into a misleading ready PR. This is not a claim that
all future issues are solvable unattended regardless of available infrastructure.
