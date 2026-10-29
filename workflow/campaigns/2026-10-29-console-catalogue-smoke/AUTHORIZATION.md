# Authorization — Console 13-family staging smoke

Milad Rashidikhah explicitly authorized this campaign on 2026-10-29 in the
integration assignment titled “integrate repaired release gates, merge, deploy,
and run 13-family Console smoke”.

The bounded authorization covers reviewed integration and merge, normal release
image publication, Git/Argo reconciliation, deployment only to Phorvex
staging/dev, and one sequential active/reactive Console launch for one exact ID
in each of the 13 catalogue families. It includes verified cleanup and reruns
needed only for demonstrated in-scope staging defects.

Production is excluded. The campaign must stop on unsafe or uncontained
behavior, must not bypass branch protection, must not create hidden live drift,
and must not weaken any release or evidence gate. It may use only existing
staging capacity and normal release infrastructure; no account-level capacity,
IAM, quota, or production change is authorized.
