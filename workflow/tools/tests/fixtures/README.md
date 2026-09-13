# Runner stream fixtures

`claude-stream-permission-denied.jsonl` mirrors the **event shapes** of a real
Claude CLI stream-json run that the runner mishandled on 2026-09-10: the CLI
emits `system` / `subtype=permission_denied` with `message` as a plain **string**
(plus `tool_name`, `tool_use_id`, `decision_reason`, `decision_reason_type`),
alongside `permission_denials` in the final `result` event. Reading `message` as
an object crashed reconciliation and turned a successful run into a failure.

`claude-stream-quota-synthetic.jsonl` mirrors the shapes of the real quota
failures seen on 2026-09-10: the CLI attributes its own error turn to the
placeholder model id `<synthetic>` and reports `is_error: true`,
`api_error_status: 429`, `terminal_reason: "api_error"` while still using
`subtype: "success"`. The placeholder is an error attribution, not a substituted
model; the run is still a failure. Tests derive their controls from this file by
changing only one field — the placeholder to a real other model (real mismatch)
or dropping the placeholder turn (error only).

Content is synthetic. Prompts, model output, session ids, tool arguments and
process records from the affected job stay private in the Git common directory
and are not copied here. `SESSION` is a placeholder the test replaces with the
session id it assigned. Also represented: `rate_limit_event`, dynamic
`system` status subtypes (`thinking_tokens`, `vcs_state_changed`,
`task_started`, `task_notification`), `thinking`/`text`/`tool_use` content
blocks, an errored `tool_result`, and `modelUsage` carrying an auxiliary helper
model beside the assigned one.
