# User-directed model settings

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
