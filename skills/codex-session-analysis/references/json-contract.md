# JSON Contract

The helper emits schema `2.0`. Treat a payload without `schema_version` as the legacy schema.

## Contents

- [Compatibility](#compatibility)
- [Collector Identity](#collector-identity)
- [Session Identity And Selection](#session-identity-and-selection)
- [Tool Activity](#tool-activity)
- [Privacy, Git, Notes, And Activity](#privacy-git-notes-and-activity)
- [Diagnostics](#diagnostics)

## Compatibility

Schema 2.0 keeps every legacy top-level section and the existing fields within `scope`, `range`, `paths`, `history`, `sessions`, `git_activity`, `notes`, and `work_time_estimate`. The following legacy aliases remain intentional:

- `sessions[].tool_calls` equals `sessions[].tool_activity.call_records`.
- `git_activity.*[].date` equals `git_activity.*[].committer.date`.
- `work_time_estimate` keeps its name, but represents non-additive activity coverage rather than elapsed human work.

Correct support for modern records can increase tool counts and add project-matching sessions compared with legacy output.

Collector releases through `2.0.0` used the former identity `codex-activity-report`. The rename to `codex-session-analysis` does not change schema `2.0`; consumers can treat both names as the same contract lineage.

## Collector Identity

Use these fields to identify the contract and exact collector implementation:

```json
{
  "schema_version": "2.0",
  "collector": {
    "name": "codex-session-analysis",
    "version": "2.1.0",
    "script_sha256": "<64 lowercase hexadecimal characters>",
    "generated_at_utc": "<ISO 8601 UTC timestamp>"
  }
}
```

The script hash is calculated from the helper that produced the payload. Use it to detect source/install drift; do not hardcode it in consumers.

## Session Identity And Selection

The first valid `session_meta` record is canonical; valid means its payload has a non-empty string `id`. Later metadata cannot replace the session ID, start time, or CWD. Parent and fork relationships remain separate:

- `parent_session_id` comes from `source.subagent.thread_spawn.parent_thread_id`.
- `forked_from_session_id` comes from the canonical metadata record.
- `identity_source` is `first_session_meta` or `filename_fallback`.
- `scope_match.reason` is `metadata_cwd`, `tool_workdir`, `session_id`, or `time_range`.
- `match_uncertain` is true for tool-workdir-only project attribution.

## Tool Activity

`sessions[].tool_activity` has this stable shape:

```json
{
  "call_records": 0,
  "invocations_estimate": 0,
  "invocations_estimate_kind": "syntactic_call_site_estimate",
  "unresolved_records": 0,
  "records_by_type": {
    "function_call": 0,
    "custom_tool_call": 0
  },
  "workdir_attribution": {
    "explicit_records": 0,
    "session_cwd_fallback_records": 0,
    "unresolved_records": 0,
    "paths": []
  }
}
```

`call_records` counts outer legacy and modern call records. `invocations_estimate` counts syntactically recognized nested tool-call sites in modern wrappers plus direct call records. It is not a runtime invocation count: conditions and loops can make it higher or lower than executed inner calls. Collector code parses but never executes tool input. Raw or complete tool arguments and inputs are never emitted; only extracted workdir paths and aggregate metadata are included.

The workdir counters partition call records:

```text
explicit_records + session_cwd_fallback_records + unresolved_records == call_records
```

## Privacy, Git, Notes, And Activity

- A history item with `secret_context: "yes"` always has `text: ""`, `preview_suppressed: true`, and `preview_suppression_reason: "secret_context"`.
- `git_activity` reports nested `author` and `committer` identity/date objects. Git commits are repository evidence and are never automatically attributed to Codex.
- Session scope does not scan notes: `notes` is empty, `scope.notes_mode` is `disabled`, and the notes diagnostic is `skipped` with reason `session_scope_unbound`.
- `work_time_estimate.non_additive` is true and `is_time_tracking` is false. Project rows can overlap and must not be summed.

## Diagnostics

`diagnostics.status` is `complete` or `partial`; `diagnostics.complete` is the corresponding boolean. The `sources` map always contains `history`, `sessions`, `rollout_summaries`, `git`, and `notes`, each with fixed status and counter fields. Allowed source statuses are `ok`, `partial`, `unavailable`, and `skipped`.

Every source entry has this shape:

```json
{
  "status": "ok",
  "files_considered": 0,
  "files_read": 0,
  "scan_passes": 0,
  "lines_seen": 0,
  "records_read": 0,
  "malformed_records": 0,
  "non_object_records": 0,
  "schema_errors": 0,
  "invalid_timestamps": 0,
  "unknown_records": 0,
  "io_errors": 0,
  "command_errors": 0,
  "timeouts": 0,
  "skipped_reason": "",
  "warnings": []
}
```

`scan_passes` counts collector passes; file and record-quality counters are deduplicated by source path.

Diagnostics expose aggregate counts and stable warning codes only. They never contain malformed source lines, prompt text, tool arguments, Git stderr, exception text, or secret values. A deliberately skipped source does not make overall coverage partial; malformed, unknown, unreadable, failed, or timed-out active sources do.
