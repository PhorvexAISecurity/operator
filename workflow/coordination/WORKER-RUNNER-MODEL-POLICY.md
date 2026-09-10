# User-directed model settings

Latest update, 2026-09-10 19:45 UTC: use `claude-opus-5` with **high**
reasoning for every future launch/resume. This supersedes the maximum-effort
instruction below, retained as history. The lead has updated all registrations
and queued jobs through the CLI. R4 changes the campaign default and
current usage documentation to high; keep explicit max supported and historical
receipts unchanged. Do not alter authentication or use a fallback model.

New instruction from the user, 2026-09-10: Claude agents must use Claude Opus 5
with maximum reasoning. Before acceptance, add persisted validated `--effort`
registration/configuration and pass it on every launch/resume. Defaults for this
campaign: explicit `claude-opus-5`, effort `max`; no floating alias or fallback.
Report requested settings and all observed model IDs, including a mismatch;
do not silently label a substituted model Opus 5. Add argv/status/resume tests.

Current in-progress turn may finish. The lead will resume this exact session
with `--model claude-opus-5 --effort max` for this follow-up if not incorporated
in the current turn. Keep all previous review requirements and no commit
attribution. Do not alter global Claude authentication/settings.
