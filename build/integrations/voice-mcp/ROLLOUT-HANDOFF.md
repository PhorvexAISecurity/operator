# Voice MCP and joint Voice source rollout handoff

This is an owner rollout checklist for the reviewed opt-in Voice cases. The
renderers write private files only. Neither the renderers nor the publisher
deploy an image or create a Kubernetes object.

1. After the combined source PR is reviewed and merged to `main`, dispatch
   `publish-voice-mcp-runtime.yml` **from main**. Retain its validated
   `voice-mcp-publish-receipt.json` artifact. Use `imageByDigest`, not the
   temporary tag, as `--approved-image` for the MCP renderer and as the
   manager's expected immutable MCP image. The receipt binds the merged Git
   SHA, server source SHA, base image, 71 locked wheels, recipe hashes, and
   published image digest. The workflow performs no rollout.
2. Obtain fresh, private API snapshots of the `voice/voice-bot` Deployment,
   `voice/voice-defense` PhorvexPolicy, all serving Voice Pods and imageIDs,
   `mcp/mcp-server` Deployment and Service, all serving MCP Pods and imageIDs,
   legacy `mcp/mcp-code` ConfigMap, all four Voice policy ConfigMaps, and
   protected Voice journals. Check Deployment and Policy UIDs, exact serving
   Pod owner chains and image IDs, and the sole Ready TCP:8000 MCP Service
   endpoint. The read-only snapshot at 2026-09-27 10:13:55 UTC found all four
   Voice policy ConfigMaps absent; it is historical evidence, not permission
   to assume they remain absent.
3. Prepare separate private 32–256-byte printable tokens for Voice state,
   MCP synthetic sessions, and Voice output synthetic sessions. Supply the
   **same MCP token bytes** to the MCP and Voice renderers. Keep token files
   owner-only and out of Git and public receipts. Render the MCP server
   source/Secret/Deployment patch with
   `build/integrations/voice-mcp/render_activation.py`, passing its fresh
   Deployment, Service, `mcp-code`, imageID, and UID pins plus the published
   `imageByDigest`. This replaces startup pip with the reviewed immutable
   runtime and immutable sole-key `server.py` ConfigMap
   `voice-mcp-source-85cbd0f201b9`.
4. Render the joint Voice activation with
   `build/integrations/voice-memory/render_activation.py`, passing the fresh
   Voice Deployment/Policy and serving imageID pins, actual bot UID and
   admission-stamped event creator, all four explicit current CM snapshots
   (`null` when absent), complete protected journal inventory, three private
   tokens, `--mcp-tool-enabled`, and `--output-enabled`. The existing Voice
   policy must list the memory, refund, MCP, and output actions as ordinary
   alternatives. Review every generated object and resource-version-tested
   patch before application. The immutable Voice source ConfigMap has exactly
   `bot.py`, `voice_memory_policy.py`, `voice_output_policy.py`, and
   `voice_mcp_policy.py`; its name is `voice-memory-source-e3cfcb87456b`.
   Memory/refund, MCP, and output source digests are independent projections
   of these same reviewed bytes, not competing source bundles.
5. The newly created `voice-output-policy` starts with empty `configMapUID`
   and is deliberately unready. Fetch its actual UID and resourceVersion,
   then use `build/integrations/voice-memory/bind_output_uid.py` for the
   compare-and-swap second phase. Wait for all serving Pods to report the
   expected source, rule revision, and authenticated private state before
   treating any native action as available. Independently verify the current
   MCP source/image/Service endpoint and the Voice `MCP_URL` pin. Run real
   attack and benign controls only after these admissions pass.

The joint Voice renderer refuses existing MCP/output rules, nonzero or
mismatched memory/refund rules, and pending protected journals. If any state
has appeared since the earlier absent-CM snapshot, preserve its entries and
journals and stop for an explicit lineage-preserving migration. Do not reset
or overwrite a prior rule to satisfy a fresh source pin. The current joint
renderer must also be kept in sync with native required-mode gates: both
test-token files are required for the intended MCP and output activation.
