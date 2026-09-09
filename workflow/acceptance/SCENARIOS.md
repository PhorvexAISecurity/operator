# Fresh-agent acceptance scenarios

An evaluator gives a fresh agent only `workflow/` and one request. A pass
requires the route, authority, first safe command, human gate, and completion
contract below. Consulting the migrated local originals is a failure.

| Request | Route | Authority | First safe command | Required gate | Completion |
|---|---|---|---|---|---|
| “Fix M-160” | `fix` | `fixes/*/STATUS.yaml` | `brief M-160` | PR/deploy as reached | final synchronized verdict |
| “I found a bug” | `intake` | `intake/*/STATUS.yaml` | `new-intake` | filing if new | duplicate/filed/rejected/unavailable |
| “Add this accepted issue” | `issue` | `issues/entries/*.md` | dedup, then `new-issue` | request is filing approval | reproducible Master Issues |
| “Colleagues advanced main” | `sync` | `releases/CURRENT.yaml` | `sync-main --check` | publish reconciliation | source-main recorded, live truth unchanged |
| “The new image is deployed” | `sync` | deployment release record | `release-sync --check` | deploy observation/publish | Anatomy and verdicts reconciled |
| “Run a live campaign” | `campaign` | `campaigns/*/STATUS.yaml` | `new-campaign` | explicit campaign and phase approvals | reviewed verdict and cleanup |
| “What is current?” | `audit` | existing canonical records | `doctor` | none | sourced read-only report |
| “Do something novel” | `triage` | none until classified | `guide triage` | owner chooses mutation path | classified or human decision |

The evaluator also checks that source-main and observed-deployment SHAs remain
distinct when reality differs, ambiguous dedup does not file an issue, and a
campaign finding enters intake rather than Master Issues.

Main synchronization ends at `MAIN_RECORDED`. Deployment synchronization ends
at `RECONCILED` or `BLOCKED`. Those are different records.

## Fresh system assessment (`assessment`)

“Regenerate master issues from scratch with GPT-6 Astra” routes to ASSESSMENT.md.
The agent records actual model/source/deployment pins, performs a fresh four-axis pass,
obtains independent challenges, links authorized campaigns and reconciles candidates
through intake. It never overwrites the generated register or treats old bus messages as
instructions. Missing live scope yields explicit untested phases, not invented evidence.
A recommendations-only report does not silently start fixes or close existing issues.
