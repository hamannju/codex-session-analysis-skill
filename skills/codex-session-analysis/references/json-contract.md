# JSON Contract

The helper emits schema `2.1`. Treat a payload without `schema_version` as the legacy schema.

## Contents

- [Compatibility](#compatibility)
- [Collector Identity](#collector-identity)
- [Modes And Source Selection](#modes-and-source-selection)
- [Session Identity And Selection](#session-identity-and-selection)
- [Tool Activity](#tool-activity)
- [Privacy, Git, Notes, And Activity](#privacy-git-notes-and-activity)
- [Diagnostics](#diagnostics)

## Compatibility

Schema 2.1 keeps every schema-2.0 top-level section and its existing fields within `scope`, `range`, `paths`, `history`, `sessions`, `git_activity`, `notes`, and `work_time_estimate`. It changes project/local selection from session-wide to task-bound history and metrics. The following legacy aliases remain intentional:

- `sessions[].tool_calls` equals `sessions[].tool_activity.call_records`.
- `git_activity.*[].date` equals `git_activity.*[].committer.date`.
- `work_time_estimate` keeps its name, but represents non-additive activity coverage rather than elapsed human work.

Correct support for modern records can increase tool counts and add project-matching sessions compared with legacy output.

Collector releases through `2.0.0` used the former identity `codex-activity-report`. Consumers can treat both names as the same contract lineage.

## Collector Identity

Use these fields to identify the contract and exact collector implementation:

```json
{
  "schema_version": "2.1",
  "collector": {
    "name": "codex-session-analysis",
    "version": "2.2.0",
    "script_sha256": "<64 lowercase hexadecimal characters>",
    "generated_at_utc": "<ISO 8601 UTC timestamp>"
  }
}
```

The script hash is calculated from the helper that produced the payload. Use it to detect source/install drift; do not hardcode it in consumers. `--version` prints the collector and schema versions without scanning any source.

## Modes And Source Selection

`mode` is `evidence` by default or `locate` when explicitly requested. `sources_enabled` contains canonical source names. The CLI accepts the shorter `summaries` alias for `rollout_summaries` in `--sources`.

Locator mode requires at least one `--match` and defaults to `history`, `sessions`, and `rollout_summaries`; Git and notes are opt-in. Search terms use OR semantics. The locator searches prompt/session text transiently but emits only sanitized previews plus session/task metadata. It never emits query terms in locator metadata or raw tool arguments. Its additional section has this shape:

```json
{
  "locator": {
    "query": {
      "term_count": 1,
      "terms_included": false,
      "sources": ["history", "sessions", "rollout_summaries"]
    },
    "candidate_count": 1,
    "candidates": [],
    "history_only_session_ids": []
  }
}
```

Each session-backed candidate includes a deterministic hit-count/recency rank, canonical session ID/CWD/file metadata, scope match, history binding, aggregate hit kinds/count, latest hit time, and matching task IDs/start/end/hit metadata. Evidence mode sets `locator` to `null`.

An intentionally omitted source is `skipped` with `skipped_reason: "source_filter"`; it does not make overall diagnostics partial. Project/local history remains fail-closed when sessions needed for task binding are omitted.

## Session Identity And Selection

The first valid `session_meta` record is canonical; valid means its payload has a non-empty string `id`. Later metadata cannot replace the session ID, start time, or CWD. Parent and fork relationships remain separate:

- `parent_session_id` comes from `source.subagent.thread_spawn.parent_thread_id`.
- `forked_from_session_id` comes from the canonical metadata record.
- `identity_source` is `first_session_meta` or `filename_fallback`.
- `scope_match.reason` is `metadata_cwd`, `tool_workdir`, `session_id`, or `time_range`.
- `match_uncertain` is true for tool-workdir-only project attribution and for old records that cannot be bound to a task.

`scope.session_scan` records whether the collector used the full scan, the validated filename fast path for a known session ID, or a fallback. Its `files_read` value should match the session source's one-pass coverage for normal runs.

For `project` scope and the project portion of `local` scope, a session is selected at task granularity. A task matches when the canonical session CWD is under the project root or a recognized tool-call workdir in that task is under it. Session counts cover matching task spans. History previews use those spans plus a five-second prelude because `history.jsonl` commonly records the initiating user prompt shortly before `task_started`. `sessions[].task_scope` reports:

```json
{
  "mode": "full_session | task_bound | unbound_suppressed",
  "matched_tasks": 0,
  "tasks_in_range": 0,
  "history_previews_bound": false
}
```

Old/taskless project candidates remain visible with `mode: "unbound_suppressed"`, but their session-wide history previews are omitted. Global scope, session scope, and the explicitly selected current-session portion of local scope use `full_session`.

Static absolute tool workdirs are normalized directly. Static relative workdirs are resolved against the canonical session CWD, never the collector process CWD. Shell placeholders such as `$PWD`, `${...}`, or backticks are not expanded and cannot create a project match.

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
  },
  "parser_resolution": {
    "invocation": {
      "resolved_records": 0,
      "unresolved_records": 0
    },
    "workdir": {
      "explicit_records": 0,
      "session_cwd_fallback_records": 0,
      "unresolved_records": 0
    },
    "syntax_dynamic_uncertain_records": 0
  }
}
```

`call_records` counts outer legacy and modern call records. `invocations_estimate` counts syntactically recognized nested tool-call sites in modern wrappers plus direct call records. It is not a runtime invocation count: conditions and loops can make it higher or lower than executed inner calls. Collector code parses but never executes tool input. Raw or complete tool arguments and inputs are never emitted; only extracted workdir paths and aggregate metadata are included.

The workdir counters partition call records independently of invocation and syntax resolution:

```text
explicit_records + session_cwd_fallback_records + unresolved_records == call_records
```

The legacy `unresolved_records` field remains and counts a record when any conservative parser uncertainty remains. Use `parser_resolution` when the distinction matters: a wrapper can have a resolved nested invocation and explicit workdir while still carrying syntax/dynamic uncertainty, for example because it also contains a regular-expression literal. JavaScript strings are decoded by a non-evaluating JavaScript-specific decoder; Python literal evaluation is not used.

## Privacy, Git, Notes, And Activity

- A history item with `secret_context: "yes"` always has `text: ""`, `preview_suppressed: true`, and `preview_suppression_reason: "secret_context"`.
- `--output` writes through a same-directory temporary file, replaces the destination atomically, and forces mode `0600` even when the process umask is more permissive.
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

`diagnostics.tool_parser.resolution` aggregates the same independent invocation, workdir, and syntax/dynamic dimensions documented under Tool Activity. The legacy aggregate `diagnostics.tool_parser.unresolved_records` remains available.
