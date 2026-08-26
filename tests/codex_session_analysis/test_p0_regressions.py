from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType, SimpleNamespace
from zoneinfo import ZoneInfo

import pytest

START = datetime(2026, 7, 31, 0, 0, tzinfo=timezone.utc)
END = datetime(2026, 8, 2, 0, 0, tzinfo=timezone.utc)
BERLIN = ZoneInfo("Europe/Berlin")


def report_args(
    module: ModuleType,
    layout: SimpleNamespace,
    *,
    scope: str = "global",
    cwd: Path | None = None,
    project_root: Path | None = None,
    session_id: str | None = None,
    repo_root: Path | None = None,
    mode: str = "evidence",
    match_terms: tuple[str, ...] = (),
    sources: str | None = None,
) -> object:
    cwd = cwd or layout.repo_root
    project_root = project_root or cwd
    argv = [
        "--scope",
        scope,
        "--mode",
        mode,
        "--start",
        "2026-07-31T00:00:00+00:00",
        "--end",
        "2026-08-02T00:00:00+00:00",
        "--now",
        "2026-08-01T12:00:00+00:00",
        "--timezone",
        "Europe/Berlin",
        "--home",
        str(layout.home),
        "--codex-home",
        str(layout.codex_home),
        "--cwd",
        str(cwd),
        "--project-root",
        str(project_root),
        "--repo-root",
        str(repo_root or layout.repo_root),
        "--notes-root",
        str(layout.notes),
        "--machine",
        "synthetic-host",
        "--format",
        "json",
    ]
    if session_id:
        argv.extend(["--session-id", session_id])
    for term in match_terms:
        argv.extend(["--match", term])
    if sources:
        argv.extend(["--sources", sources])
    return module.parse_args(argv)


def session_meta(
    session_id: str,
    cwd: Path,
    timestamp: str,
    *,
    source: object = "cli",
    forked_from_id: str = "",
) -> dict[str, object]:
    return {
        "timestamp": timestamp,
        "type": "session_meta",
        "payload": {
            "id": session_id,
            "timestamp": timestamp,
            "cwd": str(cwd),
            "source": source,
            "forked_from_id": forked_from_id,
        },
    }


def response_item(timestamp: str, payload: dict[str, object]) -> dict[str, object]:
    return {"timestamp": timestamp, "type": "response_item", "payload": payload}


def render_markdown(module: ModuleType, payload: dict[str, object]) -> str:
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        module.emit_markdown(payload)
    return output.getvalue()


def test_json_contract_has_stable_versions_hash_and_source_shape(
    activity_module: ModuleType,
    synthetic_layout: SimpleNamespace,
) -> None:
    payload = activity_module.build_payload(report_args(activity_module, synthetic_layout))

    expected_hash = hashlib.sha256(Path(activity_module.__file__).read_bytes()).hexdigest()
    assert payload["schema_version"] == "2.1"
    assert payload["collector"]["name"] == "codex-session-analysis"
    assert payload["collector"]["version"] == "2.2.0"
    assert payload["collector"]["script_sha256"] == expected_hash
    assert re.fullmatch(r"[0-9a-f]{64}", expected_hash)
    assert set(payload["diagnostics"]["sources"]) == {
        "history",
        "sessions",
        "rollout_summaries",
        "git",
        "notes",
    }
    for source in payload["diagnostics"]["sources"].values():
        assert {
            "status",
            "files_considered",
            "files_read",
            "scan_passes",
            "lines_seen",
            "records_read",
            "malformed_records",
            "non_object_records",
            "schema_errors",
            "invalid_timestamps",
            "unknown_records",
            "io_errors",
            "command_errors",
            "timeouts",
            "skipped_reason",
            "warnings",
        } <= set(source)


def test_first_session_meta_is_canonical_with_separate_parent_and_fork(
    activity_module: ModuleType,
    synthetic_layout: SimpleNamespace,
    jsonl_writer,
) -> None:
    child_id = "session-child-0001"
    parent_id = "session-parent-0001"
    fork_id = "session-fork-0001"
    child_project = synthetic_layout.repo_root / "child-project"
    later_project = synthetic_layout.repo_root / "later-project"
    child_project.mkdir()
    later_project.mkdir()
    source = {
        "unrelated": {"parent_thread_id": "wrong-unrelated-parent"},
        "subagent": {
            "thread_spawn": {"parent_thread_id": parent_id},
            "agent_path": "synthetic-child",
            "depth": "1",
        }
    }
    rows = [
        {
            "timestamp": "2026-08-01T07:59:00Z",
            "type": "session_meta",
            "payload": None,
        },
        {
            "timestamp": "2026-08-01T07:59:30Z",
            "type": "session_meta",
            "payload": {"timestamp": "2026-08-01T07:59:30Z"},
        },
        session_meta(
            child_id,
            child_project,
            "2026-08-01T08:00:00Z",
            source=source,
            forked_from_id=fork_id,
        ),
        {
            "timestamp": "2026-08-01T08:05:00Z",
            "type": "event_msg",
            "payload": {"type": "user_message", "message": "synthetic request"},
        },
        session_meta(parent_id, later_project, "2026-08-01T08:10:00Z"),
    ]
    jsonl_writer(synthetic_layout.sessions / "rollout-synthetic.jsonl", rows)

    sessions = activity_module.collect_sessions(
        synthetic_layout.codex_home, START, END, BERLIN
    )
    assert len(sessions) == 1
    session = sessions[0]
    assert session["session_id"] == child_id
    assert session["cwd"] == str(child_project)
    assert session["identity_source"] == "first_session_meta"
    assert session["session_meta_records"] == 2
    assert session["invalid_session_meta_records"] == 2
    assert session["parent_session_id"] == parent_id
    assert session["forked_from_session_id"] == fork_id

    activity = activity_module.collect_session_activity_events(
        synthetic_layout.codex_home, START, END
    )
    assert activity
    assert {event["session_id"] for event in activity} == {child_id}
    assert {event["cwd"] for event in activity} == {str(child_project)}


def test_build_payload_scans_each_session_file_once(
    activity_module: ModuleType,
    synthetic_layout: SimpleNamespace,
    jsonl_writer,
) -> None:
    project = synthetic_layout.repo_root / "single-pass-project"
    project.mkdir()
    for suffix in ("alpha", "beta"):
        session_id = f"session-single-pass-{suffix}"
        jsonl_writer(
            synthetic_layout.sessions / f"rollout-{session_id}.jsonl",
            [
                session_meta(session_id, project, "2026-08-01T08:00:00Z"),
                {
                    "timestamp": "2026-08-01T08:01:00Z",
                    "type": "event_msg",
                    "payload": {"type": "user_message", "message": "synthetic"},
                },
            ],
        )

    payload = activity_module.build_payload(
        report_args(activity_module, synthetic_layout, scope="global")
    )

    source = payload["diagnostics"]["sources"]["sessions"]
    assert source["files_read"] == 2
    assert source["scan_passes"] == 2
    assert payload["scope"]["session_scan"]["files_read"] == 2
    assert payload["scope"]["session_scan"]["strategy"] == "full_scan"


def test_explicit_session_id_uses_validated_filename_fast_path(
    activity_module: ModuleType,
    synthetic_layout: SimpleNamespace,
    jsonl_writer,
) -> None:
    project = synthetic_layout.repo_root / "fast-path-project"
    project.mkdir()
    selected_id = "session-fast-path-selected"
    other_id = "session-fast-path-other"
    for session_id in (selected_id, other_id):
        jsonl_writer(
            synthetic_layout.sessions / f"rollout-{session_id}.jsonl",
            [
                session_meta(session_id, project, "2026-08-01T08:00:00Z"),
                {
                    "timestamp": "2026-08-01T08:01:00Z",
                    "type": "event_msg",
                    "payload": {"type": "user_message", "message": "synthetic"},
                },
            ],
        )

    payload = activity_module.build_payload(
        report_args(
            activity_module,
            synthetic_layout,
            scope="session",
            cwd=project,
            project_root=project,
            session_id=selected_id,
        )
    )

    source = payload["diagnostics"]["sources"]["sessions"]
    assert source["files_read"] == 1
    assert source["scan_passes"] == 1
    assert [session["session_id"] for session in payload["sessions"]] == [selected_id]
    assert payload["scope"]["session_scan"] == {
        "strategy": "session_id_filename_fast_path",
        "files_available": 2,
        "files_read": 1,
        "fallback_used": False,
    }


def test_activity_inventory_uses_only_semantic_anchors(
    activity_module: ModuleType,
    synthetic_layout: SimpleNamespace,
    jsonl_writer,
) -> None:
    session_id = "session-anchors-0001"
    project = synthetic_layout.repo_root / "anchor-project"
    project.mkdir()
    jsonl_writer(
        synthetic_layout.sessions / f"rollout-{session_id}.jsonl",
        [
            session_meta(session_id, project, "2026-08-01T08:00:00Z"),
            {
                "timestamp": "2026-08-01T08:01:00Z",
                "type": "event_msg",
                "payload": {"type": "task_started", "turn_id": "turn-one"},
            },
            response_item(
                "2026-08-01T08:02:00Z",
                {"type": "reasoning", "summary": ["synthetic non-anchor"]},
            ),
            {
                "timestamp": "2026-08-01T08:03:00Z",
                "type": "event_msg",
                "payload": {"type": "user_message", "message": "synthetic"},
            },
            response_item(
                "2026-08-01T08:04:00Z",
                {"type": "message", "phase": "final_answer", "content": []},
            ),
            {
                "timestamp": "2026-08-01T08:05:00Z",
                "type": "event_msg",
                "payload": {"type": "task_complete", "turn_id": "turn-one"},
            },
        ],
    )

    events = activity_module.collect_session_activity_events(
        synthetic_layout.codex_home, START, END
    )

    assert [event["timestamp"] for event in events] == [
        "2026-08-01T08:01:00+00:00",
        "2026-08-01T08:03:00+00:00",
        "2026-08-01T08:04:00+00:00",
        "2026-08-01T08:05:00+00:00",
    ]


def test_locator_defaults_to_safe_sources_and_returns_task_candidates(
    activity_module: ModuleType,
    synthetic_layout: SimpleNamespace,
    jsonl_writer,
) -> None:
    project = synthetic_layout.repo_root / "locator-project"
    project.mkdir()
    selected_id = "session-locator-selected"
    unrelated_id = "session-locator-unrelated"
    for session_id, message in (
        (selected_id, "needle-locator synthetic request"),
        (unrelated_id, "UNRELATED_LOCATOR_SENTINEL"),
    ):
        jsonl_writer(
            synthetic_layout.sessions / f"rollout-{session_id}.jsonl",
            [
                session_meta(session_id, project, "2026-08-01T08:00:00Z"),
                {
                    "timestamp": "2026-08-01T08:01:00Z",
                    "type": "event_msg",
                    "payload": {"type": "task_started", "turn_id": f"turn-{session_id}"},
                },
                {
                    "timestamp": "2026-08-01T08:02:00Z",
                    "type": "event_msg",
                    "payload": {"type": "user_message", "message": message},
                },
                {
                    "timestamp": "2026-08-01T08:03:00Z",
                    "type": "event_msg",
                    "payload": {"type": "task_complete", "turn_id": f"turn-{session_id}"},
                },
            ],
        )
    jsonl_writer(
        synthetic_layout.codex_home / "history.jsonl",
        [
            {
                "ts": "2026-08-01T08:02:00Z",
                "session_id": selected_id,
                "text": "needle-locator synthetic request",
            },
            {
                "ts": "2026-08-01T08:02:00Z",
                "session_id": unrelated_id,
                "text": "UNRELATED_LOCATOR_SENTINEL",
            },
        ],
    )
    (synthetic_layout.summaries / "2026-08-01T08-30-00-locator.md").write_text(
        "needle-locator summary\n", encoding="utf-8"
    )
    (synthetic_layout.notes / "must-not-scan.md").write_text(
        "needle-locator note\n", encoding="utf-8"
    )

    payload = activity_module.build_payload(
        report_args(
            activity_module,
            synthetic_layout,
            scope="global",
            mode="locate",
            match_terms=("needle-locator",),
        )
    )

    assert payload["mode"] == "locate"
    assert payload["sources_enabled"] == ["history", "sessions", "rollout_summaries"]
    assert payload["locator"]["query"] == {
        "term_count": 1,
        "terms_included": False,
        "sources": ["history", "sessions", "rollout_summaries"],
    }
    assert payload["locator"]["candidate_count"] == 1
    candidate = payload["locator"]["candidates"][0]
    assert candidate["rank"] == 1
    assert candidate["session_id"] == selected_id
    assert candidate["hit_kinds"] == ["user_message"]
    assert candidate["tasks"][0]["turn_id"] == f"turn-{selected_id}"
    assert [item["session_id"] for item in payload["history"]] == [selected_id]
    assert len(payload["rollout_summaries"]) == 1
    assert payload["diagnostics"]["sources"]["git"]["skipped_reason"] == "source_filter"
    assert payload["diagnostics"]["sources"]["notes"]["skipped_reason"] == "source_filter"
    assert "UNRELATED_LOCATOR_SENTINEL" not in json.dumps(payload)

    markdown = render_markdown(activity_module, payload)
    assert "# Codex Session Locator" in markdown
    assert "--scope session --session-id <id>" in markdown
    assert "UNRELATED_LOCATOR_SENTINEL" not in markdown


def test_locator_source_override_and_required_match_validation(
    activity_module: ModuleType,
    synthetic_layout: SimpleNamespace,
) -> None:
    with pytest.raises(SystemExit):
        activity_module.parse_args(["--mode", "locate"])

    args = report_args(
        activity_module,
        synthetic_layout,
        scope="global",
        mode="locate",
        match_terms=("synthetic",),
        sources="sessions",
    )
    payload = activity_module.build_payload(args)
    assert payload["sources_enabled"] == ["sessions"]
    assert payload["diagnostics"]["sources"]["history"]["skipped_reason"] == "source_filter"
    assert payload["diagnostics"]["sources"]["sessions"]["status"] == "ok"


def test_version_reports_collector_and_schema(
    activity_module: ModuleType,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        activity_module.parse_args(["--version"])
    assert exc_info.value.code == 0
    assert capsys.readouterr().out.strip() == "codex-session-analysis 2.2.0 (schema 2.1)"


def test_legacy_and_modern_calls_separate_records_invocations_and_workdirs(
    activity_module: ModuleType,
    synthetic_layout: SimpleNamespace,
    jsonl_writer,
) -> None:
    session_id = "session-tools-0001"
    project = synthetic_layout.repo_root / "tool-project"
    nested_project = synthetic_layout.repo_root / "nested-project"
    project.mkdir()
    nested_project.mkdir()
    rows = [
        session_meta(session_id, project, "2026-08-01T08:00:00Z"),
        response_item(
            "2026-08-01T08:01:00Z",
            {
                "type": "function_call",
                "name": "exec_command",
                "arguments": json.dumps({"cmd": "synthetic-command", "workdir": str(project)}),
            },
        ),
        response_item(
            "2026-08-01T08:02:00Z",
            {
                "type": "custom_tool_call",
                "name": "exec",
                "input": (
                    "const first = await tools.alpha({workdir: "
                    + json.dumps(str(nested_project))
                    + "}); const second = await tools.beta({value: 2});"
                ),
            },
        ),
        response_item(
            "2026-08-01T08:03:00Z",
            {
                "type": "custom_tool_call",
                "name": "exec",
                "input": "const target = choosePath(); await tools.gamma({workdir: target});",
            },
        ),
    ]
    jsonl_writer(synthetic_layout.sessions / "rollout-tools.jsonl", rows)

    session = activity_module.collect_sessions(
        synthetic_layout.codex_home, START, END, BERLIN
    )[0]
    assert session["tool_calls"] == 3
    assert session["tool_call_records"] == 3
    assert session["tool_invocations_estimate"] == 4
    assert session["unresolved_tool_call_records"] == 1
    assert session["tool_activity"]["invocations_estimate_kind"] == "syntactic_call_site_estimate"
    assert session["tool_activity"]["records_by_type"] == {
        "function_call": 1,
        "custom_tool_call": 2,
    }
    attribution = session["tool_activity"]["workdir_attribution"]
    assert attribution["explicit_records"] == 2
    assert attribution["session_cwd_fallback_records"] == 0
    assert attribution["unresolved_records"] == 1
    assert attribution["paths"] == sorted([str(project), str(nested_project)])
    assert (
        attribution["explicit_records"]
        + attribution["session_cwd_fallback_records"]
        + attribution["unresolved_records"]
        == session["tool_call_records"]
    )
    assert session["tool_activity"]["parser_resolution"] == {
        "invocation": {"resolved_records": 3, "unresolved_records": 0},
        "workdir": {
            "explicit_records": 2,
            "session_cwd_fallback_records": 0,
            "unresolved_records": 1,
        },
        "syntax_dynamic_uncertain_records": 1,
    }


def test_session_scope_skips_unbound_notes(
    activity_module: ModuleType,
    synthetic_layout: SimpleNamespace,
    jsonl_writer,
) -> None:
    session_id = "session-notes-0001"
    project = synthetic_layout.repo_root / "notes-project"
    project.mkdir()
    jsonl_writer(
        synthetic_layout.sessions / "rollout-notes.jsonl",
        [
            session_meta(session_id, project, "2026-08-01T08:00:00Z"),
            {
                "timestamp": "2026-08-01T08:05:00Z",
                "type": "event_msg",
                "payload": {"type": "user_message", "message": "synthetic note query"},
            },
        ],
    )
    unrelated_note = synthetic_layout.notes / "unrelated.md"
    unrelated_note.write_text("Neutral synthetic note.\n", encoding="utf-8")

    args = report_args(
        activity_module,
        synthetic_layout,
        scope="session",
        cwd=project,
        project_root=project,
        session_id=session_id,
        repo_root=project,
    )
    payload = activity_module.build_payload(args)

    assert payload["scope"]["notes_mode"] == "disabled"
    assert payload["notes"] == []
    note_diagnostics = payload["diagnostics"]["sources"]["notes"]
    assert note_diagnostics["status"] == "skipped"
    assert note_diagnostics["skipped_reason"] == "session_scope_unbound"
    assert note_diagnostics["files_considered"] == 0
    assert str(unrelated_note) not in json.dumps(payload)


def test_javascript_scanner_binds_workdirs_to_tool_calls_and_avoids_lexical_traps(
    activity_module: ModuleType,
    synthetic_layout: SimpleNamespace,
) -> None:
    project_a = synthetic_layout.repo_root / "scanner-project-a"
    project_b = synthetic_layout.repo_root / "scanner-project-b"
    project_a.mkdir()
    project_b.mkdir()
    unbound_input = (
        "const sample = {workdir: "
        + json.dumps(str(project_b))
        + "}; await tools.exec_command({cmd: 'synthetic'});"
    )
    rows = [
        session_meta("session-scanner-0001", project_a, "2026-08-01T08:00:00Z"),
        response_item(
            "2026-08-01T08:01:00Z",
            {"type": "custom_tool_call", "name": "exec", "input": unbound_input},
        ),
    ]

    assert activity_module.javascript_wrapper_details(unbound_input) == (
        ["exec_command"],
        [],
        False,
    )
    assert activity_module.session_scope_match(rows, str(project_a), project_b, START, END) is None

    regex_input = (
        r"const pattern = /tools\.fake\(\)/; "
        "await tools.real({workdir: "
        + json.dumps(str(project_a))
        + "});"
    )
    names, workdirs, unresolved = activity_module.javascript_wrapper_details(regex_input)
    assert names == ["real"]
    assert workdirs == [str(project_a)]
    assert unresolved is True

    template_input = "`${tools.fake({workdir: '/synthetic-bad'})}`"
    assert activity_module.javascript_wrapper_details(template_input) == ([], [], True)

    comment_input = (
        "await tools /* synthetic */ ?. real ?. ({workdir: "
        + json.dumps(str(project_a))
        + "});"
    )
    assert activity_module.javascript_wrapper_details(comment_input) == (
        ["real"],
        [str(project_a)],
        False,
    )

    indirect_input = "const args = {cmd: 'synthetic'}; await tools.exec_command(args);"
    assert activity_module.javascript_wrapper_details(indirect_input) == (
        ["exec_command"],
        [],
        True,
    )

    shorthand_input = "await tools.exec_command({cmd: 'synthetic', workdir});"
    assert activity_module.javascript_wrapper_details(shorthand_input) == (
        ["exec_command"],
        [],
        True,
    )

    spread_input = "await tools.exec_command({cmd: 'synthetic', ...options});"
    assert activity_module.javascript_wrapper_details(spread_input) == (
        ["exec_command"],
        [],
        True,
    )

    division_input = (
        "const half = count / 2; await tools.exec_command({cmd: 'synthetic', workdir: "
        + json.dumps(str(project_b))
        + "});"
    )
    assert activity_module.javascript_wrapper_details(division_input) == (
        ["exec_command"],
        [str(project_b)],
        False,
    )

    post_control_regex_input = (
        r'if (ok) /tools.fake({workdir:"\x2ftmp\x2fsynthetic-bad"})/.test(value); '
        "await tools.real({workdir: "
        + json.dumps(str(project_a))
        + "});"
    )
    assert activity_module.javascript_wrapper_details(post_control_regex_input) == (
        ["real"],
        [str(project_a)],
        True,
    )

    post_call_division_input = (
        "const half = calculate() / 2; await tools.real({workdir: "
        + json.dumps(str(project_b))
        + "});"
    )
    assert activity_module.javascript_wrapper_details(post_call_division_input) == (
        ["real"],
        [str(project_b)],
        False,
    )

    qualified_tools_input = (
        "other /* synthetic */ . tools.fake({workdir: "
        + json.dumps(str(project_b))
        + "}); await tools.real({workdir: "
        + json.dumps(str(project_a))
        + "});"
    )
    assert activity_module.javascript_wrapper_details(qualified_tools_input) == (
        ["real"],
        [str(project_a)],
        False,
    )


def test_javascript_strings_decode_without_python_syntax_warnings(
    activity_module: ModuleType,
) -> None:
    source = (
        r"await tools.real({workdir: 'C:\ synthetic\x2fproject'}); "
        r"await tools.other({workdir: '\u002ftmp\u002fsecond'});"
    )
    with warnings.catch_warnings():
        warnings.simplefilter("error", SyntaxWarning)
        names, workdirs, unresolved = activity_module.javascript_wrapper_details(source)

    assert names == ["real", "other"]
    assert workdirs == ["C: synthetic/project", "/tmp/second"]
    assert unresolved is True


def test_tool_parser_reports_independent_resolution_dimensions(
    activity_module: ModuleType,
) -> None:
    explicit_path = "/tmp/synthetic-explicit"
    parsed = activity_module.parse_tool_record(
        {
            "type": "custom_tool_call",
            "name": "exec",
            "input": (
                r"const pattern = /synthetic/; await tools.real({workdir: "
                + json.dumps(explicit_path)
                + "});"
            ),
        }
    )

    assert parsed is not None
    assert parsed["resolved"] is False
    assert parsed["invocation_resolved"] is True
    assert parsed["workdir_attribution"] == "explicit"
    assert parsed["syntax_dynamic_uncertain"] is True

    dynamic = activity_module.parse_tool_record(
        {
            "type": "custom_tool_call",
            "name": "exec",
            "input": "const target = choose(); await tools.real({workdir: target});",
        }
    )
    assert dynamic is not None
    assert dynamic["invocation_resolved"] is True
    assert dynamic["workdir_attribution"] == "unresolved"
    assert dynamic["syntax_dynamic_uncertain"] is True


def test_private_output_is_atomic_and_mode_0600_under_umask_022(
    activity_module: ModuleType,
    tmp_path: Path,
) -> None:
    output = tmp_path / "evidence.json"
    previous_umask = os.umask(0o022)
    try:
        activity_module.write_private_output(output, "json", {"synthetic": True})
    finally:
        os.umask(previous_umask)

    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert json.loads(output.read_text(encoding="utf-8")) == {"synthetic": True}
    assert list(tmp_path.glob(".evidence.json.*.tmp")) == []


def test_modern_tool_workdir_drives_project_match_with_provenance(
    activity_module: ModuleType,
    synthetic_layout: SimpleNamespace,
    jsonl_writer,
) -> None:
    session_id = "session-cross-project-0001"
    project_a = synthetic_layout.repo_root / "project-a"
    project_b = synthetic_layout.repo_root / "project-b"
    for project in (project_a, project_b):
        project.mkdir()
        (project / ".git").mkdir()
    rows = [
        session_meta(session_id, project_a, "2026-08-01T08:00:00Z"),
        response_item(
            "2026-08-01T08:01:00Z",
            {
                "type": "custom_tool_call",
                "name": "exec",
                "input": (
                    "await tools.exec_command({cmd: 'synthetic-command', workdir: "
                    + json.dumps(str(project_b))
                    + "});"
                ),
            },
        ),
    ]
    jsonl_writer(synthetic_layout.sessions / "rollout-cross-project.jsonl", rows)

    sessions = activity_module.collect_sessions(
        synthetic_layout.codex_home,
        START,
        END,
        BERLIN,
        cwd_root=project_b,
    )
    assert len(sessions) == 1
    assert sessions[0]["scope_match"] == {
        "reason": "tool_workdir",
        "matched_path": str(project_b),
    }
    assert sessions[0]["match_reason"] == "tool_workdir"
    assert sessions[0]["matched_workdirs"] == [str(project_b)]
    assert sessions[0]["match_uncertain"] is True

    activity = activity_module.collect_session_activity_events(
        synthetic_layout.codex_home,
        START,
        END,
        cwd_root=project_b,
    )
    assert activity == [
        {
            "timestamp": "2026-08-01T08:01:00+00:00",
            "session_id": session_id,
            "source": "session",
            "project": "project-b",
            "cwd": str(project_b),
        }
    ]


def test_project_scope_binds_history_and_metrics_to_matching_tasks(
    activity_module: ModuleType,
    synthetic_layout: SimpleNamespace,
    jsonl_writer,
) -> None:
    session_id = "session-task-gating-0001"
    home_project = synthetic_layout.repo_root / "home-project"
    target_project = synthetic_layout.repo_root / "target-project"
    for project in (home_project, target_project):
        project.mkdir()
        (project / ".git").mkdir()
    rows = [
        session_meta(session_id, home_project, "2026-08-01T08:00:00Z"),
        {
            "timestamp": "2026-08-01T08:01:00Z",
            "type": "event_msg",
            "payload": {"type": "task_started", "turn_id": "target-task"},
        },
        {
            "timestamp": "2026-08-01T08:02:00Z",
            "type": "event_msg",
            "payload": {"type": "user_message", "message": "target prompt"},
        },
        response_item(
            "2026-08-01T08:03:00Z",
            {
                "type": "custom_tool_call",
                "name": "exec",
                "input": (
                    "await tools.exec_command({cmd: 'synthetic', workdir: "
                    + json.dumps(str(target_project))
                    + "});"
                ),
            },
        ),
        {
            "timestamp": "2026-08-01T08:04:00Z",
            "type": "event_msg",
            "payload": {"type": "task_complete", "turn_id": "target-task"},
        },
        {
            "timestamp": "2026-08-01T09:01:00Z",
            "type": "event_msg",
            "payload": {"type": "task_started", "turn_id": "unrelated-task"},
        },
        {
            "timestamp": "2026-08-01T09:02:00Z",
            "type": "event_msg",
            "payload": {"type": "user_message", "message": "unrelated prompt"},
        },
        response_item(
            "2026-08-01T09:03:00Z",
            {
                "type": "function_call",
                "name": "exec_command",
                "arguments": json.dumps({"cmd": "synthetic", "workdir": str(home_project)}),
            },
        ),
        {
            "timestamp": "2026-08-01T09:04:00Z",
            "type": "event_msg",
            "payload": {"type": "task_complete", "turn_id": "unrelated-task"},
        },
    ]
    jsonl_writer(synthetic_layout.sessions / f"rollout-{session_id}.jsonl", rows)
    jsonl_writer(
        synthetic_layout.codex_home / "history.jsonl",
        [
            {"ts": "2026-08-01T08:00:58Z", "session_id": session_id, "text": "target prompt"},
            {
                "ts": "2026-08-01T08:00:50Z",
                "session_id": session_id,
                "text": "PRELUDE_TOO_EARLY_SENTINEL",
            },
            {
                "ts": "2026-08-01T09:02:00Z",
                "session_id": session_id,
                "text": "UNRELATED_PRIVATE_SENTINEL",
            },
        ],
    )

    payload = activity_module.build_payload(
        report_args(
            activity_module,
            synthetic_layout,
            scope="project",
            cwd=target_project,
            project_root=target_project,
            repo_root=target_project,
        )
    )

    assert [item["text"] for item in payload["history"]] == ["target prompt"]
    assert "UNRELATED_PRIVATE_SENTINEL" not in json.dumps(payload)
    assert "PRELUDE_TOO_EARLY_SENTINEL" not in json.dumps(payload)
    assert len(payload["sessions"]) == 1
    session = payload["sessions"][0]
    assert session["events"] == 4
    assert session["user_events"] == 1
    assert session["tool_call_records"] == 1
    assert session["task_scope"] == {
        "mode": "task_bound",
        "matched_tasks": 1,
        "tasks_in_range": 2,
        "history_previews_bound": True,
    }


def test_project_scope_suppresses_unbound_legacy_history(
    activity_module: ModuleType,
    synthetic_layout: SimpleNamespace,
    jsonl_writer,
) -> None:
    session_id = "session-unbound-legacy-0001"
    project = synthetic_layout.repo_root / "legacy-project"
    project.mkdir()
    jsonl_writer(
        synthetic_layout.sessions / f"rollout-{session_id}.jsonl",
        [
            session_meta(session_id, project, "2026-08-01T08:00:00Z"),
            {
                "timestamp": "2026-08-01T08:02:00Z",
                "type": "event_msg",
                "payload": {"type": "user_message", "message": "legacy prompt"},
            },
        ],
    )
    jsonl_writer(
        synthetic_layout.codex_home / "history.jsonl",
        [
            {
                "ts": "2026-08-01T08:02:00Z",
                "session_id": session_id,
                "text": "LEGACY_PRIVATE_SENTINEL",
            }
        ],
    )

    payload = activity_module.build_payload(
        report_args(
            activity_module,
            synthetic_layout,
            scope="project",
            cwd=project,
            project_root=project,
            repo_root=project,
        )
    )

    assert payload["history"] == []
    assert len(payload["sessions"]) == 1
    assert payload["sessions"][0]["task_scope"] == {
        "mode": "unbound_suppressed",
        "matched_tasks": 0,
        "tasks_in_range": 0,
        "history_previews_bound": False,
    }
    assert "LEGACY_PRIVATE_SENTINEL" not in json.dumps(payload)


def test_tool_workdirs_resolve_against_session_cwd_not_collector_cwd(
    activity_module: ModuleType,
    synthetic_layout: SimpleNamespace,
    jsonl_writer,
) -> None:
    project_a = synthetic_layout.repo_root / "relative-project-a"
    project_b = synthetic_layout.repo_root / "relative-project-b"
    project_a.mkdir()
    project_b.mkdir()
    session_id = "session-relative-workdir-0001"
    jsonl_writer(
        synthetic_layout.sessions / f"rollout-{session_id}.jsonl",
        [
            session_meta(session_id, project_a, "2026-08-01T08:00:00Z"),
            {
                "timestamp": "2026-08-01T08:01:00Z",
                "type": "event_msg",
                "payload": {"type": "task_started", "turn_id": "relative-task"},
            },
            response_item(
                "2026-08-01T08:02:00Z",
                {
                    "type": "function_call",
                    "name": "exec_command",
                    "arguments": json.dumps(
                        {"cmd": "synthetic", "workdir": "../relative-project-b"}
                    ),
                },
            ),
            {
                "timestamp": "2026-08-01T08:03:00Z",
                "type": "event_msg",
                "payload": {"type": "task_complete", "turn_id": "relative-task"},
            },
        ],
    )

    sessions = activity_module.collect_sessions(
        synthetic_layout.codex_home,
        START,
        END,
        BERLIN,
        cwd_root=project_b,
    )
    assert len(sessions) == 1
    assert sessions[0]["scope_match"] == {
        "reason": "tool_workdir",
        "matched_path": str(project_b),
    }
    assert activity_module.resolve_tool_workdir("$PWD", str(project_a)) is None
    assert activity_module.resolve_tool_workdir("${PROJECT_ROOT}", str(project_a)) is None


def test_berlin_dst_day_lengths_and_invalid_naive_clock_times(
    activity_module: ModuleType,
) -> None:
    spring_start = activity_module.parse_dt("2026-03-29", BERLIN, is_end=False)
    spring_end = activity_module.parse_dt("2026-03-29", BERLIN, is_end=True)
    autumn_start = activity_module.parse_dt("2026-10-25", BERLIN, is_end=False)
    autumn_end = activity_module.parse_dt("2026-10-25", BERLIN, is_end=True)

    assert spring_end - spring_start + timedelta(microseconds=1) == timedelta(hours=23)
    assert autumn_end - autumn_start + timedelta(microseconds=1) == timedelta(hours=25)

    with pytest.raises(SystemExit, match="does not exist.*explicit UTC offset"):
        activity_module.parse_dt("2026-03-29 02:30", BERLIN, is_end=False)
    with pytest.raises(SystemExit, match="ambiguous.*explicit UTC offset"):
        activity_module.parse_dt("2026-10-25 02:30", BERLIN, is_end=False)

    summer_fold = activity_module.parse_dt("2026-10-25T02:30:00+02:00", BERLIN, is_end=False)
    winter_fold = activity_module.parse_dt("2026-10-25T02:30:00+01:00", BERLIN, is_end=False)
    assert winter_fold - summer_fold == timedelta(hours=1)


def test_secret_context_preview_is_empty_and_absent_from_markdown(
    activity_module: ModuleType,
    synthetic_layout: SimpleNamespace,
    jsonl_writer,
) -> None:
    source_fragment = "synthetic-placeholder-value"
    jsonl_writer(
        synthetic_layout.codex_home / "history.jsonl",
        [
            {
                "ts": "2026-08-01T08:00:00Z",
                "session_id": "session-secret-0001",
                "text": f"Inspect token: {source_fragment}",
            }
        ],
    )

    payload = activity_module.build_payload(report_args(activity_module, synthetic_layout))
    assert payload["history"][0]["text"] == ""
    assert payload["history"][0]["preview_suppressed"] is True
    assert payload["history"][0]["preview_suppression_reason"] == "secret_context"
    assert payload["privacy"]["secret_context_previews_suppressed"] == 1
    assert source_fragment not in json.dumps(payload)

    markdown = render_markdown(activity_module, payload)
    assert source_fragment not in markdown
    assert "Inspect token" not in markdown
    assert "[secret-context; preview suppressed]" in markdown


def test_git_author_committer_and_repository_evidence_caveat(
    activity_module: ModuleType,
    synthetic_layout: SimpleNamespace,
) -> None:
    repository = synthetic_layout.repo_root / "git-attribution"
    repository.mkdir()
    subprocess.run(
        ["git", "init", "--quiet", str(repository)],
        check=True,
        text=True,
        capture_output=True,
    )
    (repository / "synthetic.txt").write_text("synthetic evidence\n", encoding="utf-8")
    subprocess.run(
        ["git", "-C", str(repository), "add", "synthetic.txt"],
        check=True,
        text=True,
        capture_output=True,
    )
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_AUTHOR_NAME": "Synthetic Author",
            "GIT_AUTHOR_EMAIL": "author@example.invalid",
            "GIT_AUTHOR_DATE": "2026-08-01T09:00:00+02:00",
            "GIT_COMMITTER_NAME": "Synthetic Committer",
            "GIT_COMMITTER_EMAIL": "committer@example.invalid",
            "GIT_COMMITTER_DATE": "2026-08-01T09:05:00+02:00",
        }
    )
    subprocess.run(
        ["git", "-C", str(repository), "commit", "--quiet", "-m", "Synthetic commit"],
        check=True,
        text=True,
        capture_output=True,
        env=environment,
    )

    payload = activity_module.build_payload(
        report_args(
            activity_module,
            synthetic_layout,
            cwd=repository,
            project_root=repository,
            repo_root=repository,
        )
    )
    commit = payload["git_activity"][str(repository)][0]
    assert commit["author"] == {
        "name": "Synthetic Author",
        "email": "author@example.invalid",
        "date": "2026-08-01T09:00:00+02:00",
    }
    assert commit["committer"] == {
        "name": "Synthetic Committer",
        "email": "committer@example.invalid",
        "date": "2026-08-01T09:05:00+02:00",
    }
    assert commit["date"] == commit["committer"]["date"]
    assert payload["git_attribution"]["codex_attribution_inferred"] is False
    assert "not automatically attributable to Codex" in payload["git_attribution"]["message"]

    markdown = render_markdown(activity_module, payload)
    assert "Synthetic Author <author@example.invalid>" in markdown
    assert "Synthetic Committer <committer@example.invalid>" in markdown
    assert "not automatically attributable to Codex" in markdown


def test_diagnostics_count_malformed_input_once_and_report_partial(
    activity_module: ModuleType,
    tmp_path: Path,
) -> None:
    source_path = tmp_path / "synthetic-history.jsonl"
    source_path.write_text(
        '{"ts":"2026-08-01T08:00:00Z","text":"synthetic"}\n'
        "{malformed-synthetic-record}\n"
        '["synthetic-non-object"]\n',
        encoding="utf-8",
    )
    unreadable_as_file = tmp_path / "synthetic-directory"
    unreadable_as_file.mkdir()
    diagnostics = activity_module.CollectorDiagnostics()

    first = activity_module.read_jsonl(source_path, diagnostics, "history")
    second = activity_module.read_jsonl(source_path, diagnostics, "history")
    activity_module.read_jsonl(unreadable_as_file, diagnostics, "history")
    result = activity_module.finalize_diagnostics(diagnostics, [])
    history = result["sources"]["history"]

    assert first == second
    assert history["files_considered"] == 2
    assert history["files_read"] == 1
    assert history["scan_passes"] == 3
    assert history["records_read"] == 1
    assert history["malformed_records"] == 1
    assert history["non_object_records"] == 1
    assert history["io_errors"] == 1
    assert history["status"] == "partial"
    assert result["status"] == "partial"
    assert result["complete"] is False
    assert {warning["code"] for warning in result["warnings"]} == {"history_partial"}
    assert "malformed-synthetic-record" not in json.dumps(result)


def test_activity_coverage_is_non_additive_and_flags_extreme_days(
    activity_module: ModuleType,
) -> None:
    start = datetime(2026, 1, 15, 0, 0, tzinfo=timezone.utc)
    events = []
    for hour in range(22):
        timestamp = (start + timedelta(hours=hour)).isoformat()
        events.append({"timestamp": timestamp, "project": "synthetic-alpha"})
        events.append({"timestamp": timestamp, "project": "synthetic-beta"})

    estimate = activity_module.estimate_work_time(events, BERLIN, gap_minutes=60)

    assert estimate["metric_name"] == "codex_activity_coverage_estimate"
    assert estimate["non_additive"] is True
    assert estimate["is_time_tracking"] is False
    assert estimate["warning_flags"]["project_totals_non_additive"] is True
    assert estimate["warning_flags"]["extreme_day_count"] == 1
    assert estimate["warning_flags"]["extreme_days"] == ["2026-01-15"]
    assert {warning["code"] for warning in estimate["warnings"]} == {
        "activity_coverage_non_additive",
        "activity_coverage_extreme_day",
    }
    assert sum(row["active_hours_estimate"] for row in estimate["by_project"]) > estimate[
        "by_day"
    ][0]["active_hours_estimate"]


def test_unknown_session_record_type_is_counted_without_echoing_value(
    activity_module: ModuleType,
    tmp_path: Path,
) -> None:
    unknown_type = "SYNTHETIC_UNKNOWN_PRIVATE_SENTINEL"
    source_path = tmp_path / "synthetic-session.jsonl"
    source_path.write_text(
        json.dumps(
            {
                "timestamp": "2026-08-01T08:00:00Z",
                "type": unknown_type,
                "payload": {},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    diagnostics = activity_module.CollectorDiagnostics()

    activity_module.read_jsonl(source_path, diagnostics, "sessions")
    result = activity_module.finalize_diagnostics(diagnostics, [])

    assert result["sources"]["sessions"]["unknown_records"] == 1
    assert result["sources"]["sessions"]["status"] == "partial"
    assert unknown_type not in json.dumps(result)
