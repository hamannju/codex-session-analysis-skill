#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import contextlib
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, time, timezone
from itertools import pairwise
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

SCHEMA_VERSION = "2.0"
COLLECTOR_VERSION = "2.1.0"
SCRIPT_PATH = Path(__file__).resolve()
SOURCE_NAMES = ("history", "sessions", "rollout_summaries", "git", "notes")
KNOWN_SESSION_RECORD_TYPES = {
    "compacted",
    "event_msg",
    "inter_agent_communication_metadata",
    "response_item",
    "session_meta",
    "turn_context",
    "world_state",
}

SECRET_CONTEXT_RE = re.compile(
    r"(?i)\b(password|passwd|token|secret|api[_-]?key|bearer|credential|private[_-]?key|pat)\b"
)
SECRET_VALUE_RE = re.compile(
    r"(?i)\b(password|passwd|token|secret|api[_-]?key|bearer|pat)\s*[:=]\s*[^\s,;]+"
)
TOKEN_RE = re.compile(
    r"\b(?:glpat|ghp|github_pat|sk|xoxb|xoxp|hf)_[A-Za-z0-9_\-]{12,}\b|"
    r"\b(?:glpat|ghp|sk|hf)-[A-Za-z0-9_\-]{12,}\b"
)
LONG_SECRET_RE = re.compile(r"\b[A-Za-z0-9_.\-+=]{64,}\b")
@dataclass
class SourceDiagnostic:
    status: str = "ok"
    scan_passes: int = 0
    lines_seen: int = 0
    records_read: int = 0
    malformed_records: int = 0
    non_object_records: int = 0
    schema_errors: int = 0
    invalid_timestamps: int = 0
    unknown_records: int = 0
    io_errors: int = 0
    command_errors: int = 0
    timeouts: int = 0
    skipped_reason: str = ""
    warnings: list[str] = field(default_factory=list)
    _files_considered: set[str] = field(default_factory=set)
    _files_read: set[str] = field(default_factory=set)

    def consider(self, path: Path) -> None:
        self.scan_passes += 1
        self._files_considered.add(str(path))

    def read(self, path: Path) -> None:
        self._files_read.add(str(path))
        if self.status == "unavailable":
            self.status = "partial"

    def warn(self, message: str) -> None:
        if message not in self.warnings:
            self.warnings.append(message)

    def unavailable(self, message: str) -> None:
        self.status = "partial" if self._files_read else "unavailable"
        self.warn(message)

    def skip(self, reason: str) -> None:
        self.status = "skipped"
        self.skipped_reason = reason

    def as_dict(self) -> dict[str, Any]:
        status = self.status
        if status == "ok" and (
            self.malformed_records
            or self.non_object_records
            or self.schema_errors
            or self.invalid_timestamps
            or self.unknown_records
            or self.io_errors
            or self.command_errors
            or self.timeouts
        ):
            status = "partial"
        return {
            "status": status,
            "files_considered": len(self._files_considered),
            "files_read": len(self._files_read),
            "scan_passes": self.scan_passes,
            "lines_seen": self.lines_seen,
            "records_read": self.records_read,
            "malformed_records": self.malformed_records,
            "non_object_records": self.non_object_records,
            "schema_errors": self.schema_errors,
            "invalid_timestamps": self.invalid_timestamps,
            "unknown_records": self.unknown_records,
            "io_errors": self.io_errors,
            "command_errors": self.command_errors,
            "timeouts": self.timeouts,
            "skipped_reason": self.skipped_reason,
            "warnings": self.warnings,
        }


class CollectorDiagnostics:
    def __init__(self) -> None:
        self._sources = {name: SourceDiagnostic() for name in SOURCE_NAMES}
        self.jsonl_diagnosed_paths: set[Path] = set()

    def source(self, name: str) -> SourceDiagnostic:
        return self._sources[name]

    def as_dict(self) -> dict[str, Any]:
        return {"sources": {name: item.as_dict() for name, item in self._sources.items()}}


def non_negative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return parsed


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be one or greater")
    return parsed


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract a sanitized evidence pack for a Codex Session Analysis."
    )
    parser.add_argument("--start", help="Start date/time, e.g. 2026-05-15 or 2026-05-15 08:00")
    parser.add_argument("--end", help="End date/time, e.g. 2026-05-18 17:40. Defaults to now")
    parser.add_argument("--timezone", default="Europe/Berlin", help="Timezone for naive date/time input")
    parser.add_argument(
        "--scope",
        choices=("local", "session", "project", "global"),
        default="local",
        help="Report scope. local is the default and combines current session plus current project",
    )
    parser.add_argument("--session-id", help="Limit to this Codex session ID. Prefixes are accepted")
    parser.add_argument("--cwd", default=str(Path.cwd()), help="Current working directory for local/project scope")
    parser.add_argument("--project-root", help="Project root for project/local scope. Defaults to git root of --cwd")
    parser.add_argument(
        "--default-range",
        choices=("today-yesterday", "today", "last-7-days"),
        default="today-yesterday",
        help="Date range used when --start is omitted",
    )
    parser.add_argument("--now", help="Override current time for deterministic tests, e.g. 2026-05-18 17:53")
    parser.add_argument("--home", default=str(Path.home()), help="Home directory to inspect")
    parser.add_argument("--codex-home", help="Codex data directory. Defaults to <home>/.codex")
    parser.add_argument(
        "--repo-root",
        action="append",
        default=[],
        help="Directory containing git repositories. May be passed multiple times. Defaults to <home>/gitlab and <home>/github",
    )
    parser.add_argument("--notes-root", help="Obsidian/Markdown notes root. Defaults to <home>/Obsidian")
    parser.add_argument("--machine", default=platform.node() or "unknown", help="Machine label to include in the evidence pack")
    parser.add_argument("--output", help="Write output to this file instead of stdout")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--prompt-preview-chars", type=non_negative_int, default=420)
    parser.add_argument(
        "--activity-gap-minutes",
        type=positive_int,
        default=30,
        help="Maximum gap contributing to the non-additive activity-coverage estimate",
    )
    return parser.parse_args(argv)


def parse_dt(value: str, tz: ZoneInfo, *, is_end: bool) -> datetime:
    raw = value.strip()
    try:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw):
            day = datetime.fromisoformat(raw).date()
            dt = datetime.combine(day, time.max if is_end else time.min)
        else:
            normalized = raw.replace("Z", "+00:00")
            dt = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise SystemExit(f"error: invalid date/time {raw!r}") from exc

    if dt.tzinfo is None:
        fold_zero = dt.replace(tzinfo=tz, fold=0)
        fold_one = dt.replace(tzinfo=tz, fold=1)
        valid_zero = fold_zero.astimezone(timezone.utc).astimezone(tz).replace(tzinfo=None) == dt
        valid_one = fold_one.astimezone(timezone.utc).astimezone(tz).replace(tzinfo=None) == dt
        if not valid_zero and not valid_one:
            raise SystemExit(
                f"error: local time {raw!r} does not exist in {tz.key}; provide an explicit UTC offset"
            )
        if valid_zero and valid_one and fold_zero.utcoffset() != fold_one.utcoffset():
            raise SystemExit(
                f"error: local time {raw!r} is ambiguous in {tz.key}; provide an explicit UTC offset"
            )
        dt = fold_zero if valid_zero else fold_one
    return dt.astimezone(timezone.utc)


def parse_now(value: str | None, tz: ZoneInfo) -> datetime:
    if not value:
        return datetime.now(tz).astimezone(timezone.utc)
    return parse_dt(value, tz, is_end=False)


def default_start_for_range(default_range: str, end: datetime, tz: ZoneInfo) -> datetime:
    local_end = end.astimezone(tz)
    local_day = local_end.date()
    if default_range == "today":
        start_day = local_day
    elif default_range == "last-7-days":
        start_day = local_day.fromordinal(local_day.toordinal() - 6)
    else:
        start_day = local_day.fromordinal(local_day.toordinal() - 1)
    return datetime.combine(start_day, time.min, tzinfo=tz).astimezone(timezone.utc)


def parse_event_ts(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, timezone.utc)
        except (OSError, OverflowError, ValueError):
            return None
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
        except ValueError:
            return None
    return None


def redact(text: str) -> str:
    text = SECRET_VALUE_RE.sub(lambda m: m.group(0).split("=", 1)[0].split(":", 1)[0] + "=<redacted>", text)
    text = TOKEN_RE.sub("<redacted-token>", text)
    return LONG_SECRET_RE.sub("<redacted-long-value>", text)


def preview(text: str, limit: int) -> str:
    text = redact(" ".join(text.split()))
    if len(text) <= limit:
        return text
    if limit <= 3:
        return "." * limit
    return text[: limit - 3].rstrip() + "..."


def read_jsonl(
    path: Path,
    diagnostics: CollectorDiagnostics | None = None,
    source: str = "sessions",
) -> list[dict[str, Any]]:
    resolved = normalize_path(path)
    source_diagnostic = diagnostics.source(source) if diagnostics else None
    record_diagnostics = False
    if source_diagnostic:
        source_diagnostic.consider(resolved)
        record_diagnostics = resolved not in diagnostics.jsonl_diagnosed_paths
        diagnostics.jsonl_diagnosed_paths.add(resolved)

    rows: list[dict[str, Any]] = []
    try:
        with resolved.open("r", encoding="utf-8", errors="replace") as handle:
            if source_diagnostic and record_diagnostics:
                source_diagnostic.read(resolved)
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                if source_diagnostic and record_diagnostics:
                    source_diagnostic.lines_seen += 1
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    if source_diagnostic and record_diagnostics:
                        source_diagnostic.malformed_records += 1
                    continue
                if isinstance(obj, dict):
                    rows.append(obj)
                    if source_diagnostic and record_diagnostics:
                        source_diagnostic.records_read += 1
                        timestamp_value = obj.get("ts") if source == "history" else obj.get("timestamp")
                        if timestamp_value is not None and parse_event_ts(timestamp_value) is None:
                            source_diagnostic.invalid_timestamps += 1
                        if source == "sessions":
                            record_type = str(obj.get("type") or "<missing>")
                            if record_type not in KNOWN_SESSION_RECORD_TYPES:
                                source_diagnostic.unknown_records += 1
                            elif record_type == "session_meta":
                                payload = obj.get("payload")
                                if not (
                                    isinstance(payload, dict)
                                    and isinstance(payload.get("id"), str)
                                    and bool(payload["id"])
                                ):
                                    source_diagnostic.schema_errors += 1
                elif source_diagnostic and record_diagnostics:
                    source_diagnostic.non_object_records += 1
    except OSError:
        if source_diagnostic and record_diagnostics:
            source_diagnostic.io_errors += 1
            source_diagnostic.unavailable("one or more source files could not be read")
        return []
    return rows


def iso_utc(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).isoformat(timespec="seconds")


def in_range(ts: datetime | None, start: datetime, end: datetime) -> bool:
    return bool(ts and start <= ts <= end)


def normalize_path(path: Path) -> Path:
    return path.expanduser().resolve(strict=False)


def path_is_under(path: str | Path, root: Path) -> bool:
    try:
        normalize_path(Path(path)).relative_to(normalize_path(root))
        return True
    except (OSError, ValueError):
        return False


def find_git_root(path: Path) -> Path | None:
    cmd = ["git", "-C", str(path), "rev-parse", "--show-toplevel"]
    try:
        proc = subprocess.run(
            cmd,
            check=False,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=6,
        )
    except (OSError, subprocess.TimeoutExpired):
        proc = None
    if proc and proc.returncode == 0:
        root = proc.stdout.strip()
        if root:
            return normalize_path(Path(root))

    current = normalize_path(path)
    for candidate in (current, *current.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


def session_matches(value: str, session_ids: set[str]) -> bool:
    if not session_ids:
        return False
    return any(value == session_id or value.startswith(session_id) or session_id.startswith(value) for session_id in session_ids)


def canonical_session_metadata(rows: list[dict[str, Any]]) -> dict[str, Any]:
    meta_records: list[dict[str, Any]] = []
    invalid_meta_records = 0
    for obj in rows:
        if obj.get("type") != "session_meta":
            continue
        payload = obj.get("payload")
        if isinstance(payload, dict) and isinstance(payload.get("id"), str) and payload["id"]:
            meta_records.append(payload)
        else:
            invalid_meta_records += 1

    canonical = meta_records[0] if meta_records else {}
    source = canonical.get("source")
    spawn: dict[str, Any] = {}
    if isinstance(source, dict):
        subagent = source.get("subagent")
        if isinstance(subagent, dict) and isinstance(subagent.get("thread_spawn"), dict):
            spawn = subagent["thread_spawn"]
    parent_session_id = str(spawn.get("parent_thread_id") or "")
    thread_source = ""
    if isinstance(source, str):
        thread_source = source
    elif isinstance(source, dict):
        thread_source = str(source.get("type") or next(iter(source), ""))

    return {
        "canonical": canonical,
        "session_meta_records": len(meta_records),
        "invalid_session_meta_records": invalid_meta_records,
        "parent_session_id": parent_session_id,
        "forked_from_id": str(canonical.get("forked_from_id") or ""),
        "thread_source": thread_source,
        "agent_path": str(spawn.get("agent_path") or ""),
        "spawn_depth": spawn.get("depth"),
    }


def decode_literal(value: str) -> str:
    try:
        parsed = ast.literal_eval(value)
    except (SyntaxError, ValueError):
        return ""
    return parsed if isinstance(parsed, str) else ""


def javascript_wrapper_details(source: str) -> tuple[list[str], list[str], bool]:
    tool_names: list[str] = []
    workdirs: list[str] = []
    unresolved = False
    length = len(source)

    def scan_string(position: int, limit: int = length) -> tuple[str, int]:
        nonlocal unresolved
        quote = source[position]
        cursor = position + 1
        while cursor < limit:
            if source[cursor] == "\\":
                cursor += 2
                continue
            if quote == "`" and source.startswith("${", cursor):
                unresolved = True
            if source[cursor] == quote:
                literal = source[position : cursor + 1]
                if quote in {"'", '"'}:
                    return decode_literal(literal), cursor + 1
                return "", cursor + 1
            cursor += 1
        unresolved = True
        return "", limit

    def skip_trivia(position: int, limit: int = length) -> int:
        nonlocal unresolved
        while position < limit:
            if source[position].isspace():
                position += 1
                continue
            if source.startswith("//", position):
                newline = source.find("\n", position + 2, limit)
                position = limit if newline < 0 else newline + 1
                continue
            if source.startswith("/*", position):
                closing = source.find("*/", position + 2, limit)
                if closing < 0:
                    unresolved = True
                    return limit
                position = closing + 2
                continue
            break
        return position

    def previous_significant_char(position: int) -> str:
        cursor = position - 1
        while cursor >= 0:
            while cursor >= 0 and source[cursor].isspace():
                cursor -= 1
            if cursor >= 1 and source[cursor - 1 : cursor + 1] == "*/":
                opening = source.rfind("/*", 0, cursor - 1)
                if opening < 0:
                    return ""
                cursor = opening - 1
                continue
            return source[cursor] if cursor >= 0 else ""
        return ""

    def skip_regex(position: int, limit: int = length) -> int:
        nonlocal unresolved
        unresolved = True
        cursor = position + 1
        in_character_class = False
        while cursor < limit:
            char = source[cursor]
            if char == "\\":
                cursor += 2
                continue
            if char == "[":
                in_character_class = True
            elif char == "]":
                in_character_class = False
            elif char == "/" and not in_character_class:
                cursor += 1
                while cursor < limit and source[cursor].isalpha():
                    cursor += 1
                return cursor
            cursor += 1
        return limit

    def regex_literal_end(position: int, limit: int = length) -> int | None:
        if source.startswith("/=", position):
            return None
        cursor = position + 1
        in_character_class = False
        while cursor < limit:
            char = source[cursor]
            if char in "\r\n":
                return None
            if char == "\\":
                cursor += 2
                continue
            if char == "[":
                in_character_class = True
            elif char == "]":
                in_character_class = False
            elif char == "/" and not in_character_class:
                cursor += 1
                flags: set[str] = set()
                while cursor < limit and source[cursor].isalpha():
                    flag = source[cursor]
                    if flag not in "dgimsuvy" or flag in flags:
                        return None
                    flags.add(flag)
                    cursor += 1
                return cursor
            cursor += 1
        return None

    def slash_begins_regex(position: int) -> bool:
        """Use a conservative lexical heuristic to separate regex from division."""
        cursor = position - 1
        while cursor >= 0 and source[cursor].isspace():
            cursor -= 1
        if cursor < 0:
            return True
        previous = source[cursor]
        if previous in ")}":
            # After a control condition or block, `/.../` may begin a valid
            # expression statement. Only classify it as such if a complete,
            # lexically valid regex literal is present; otherwise keep
            # scanning it as division.
            return regex_literal_end(position) is not None
        if previous in "]'\"`" or previous.isdigit():
            return False
        if previous.isalpha() or previous in "_$":
            end = cursor + 1
            while cursor >= 0 and (source[cursor].isalnum() or source[cursor] in "_$"):
                cursor -= 1
            keyword = source[cursor + 1 : end]
            return keyword in {
                "await",
                "case",
                "delete",
                "do",
                "else",
                "in",
                "instanceof",
                "new",
                "return",
                "throw",
                "typeof",
                "void",
                "yield",
            }
        return not (previous in "+-" and cursor > 0 and source[cursor - 1] == previous)

    def parse_workdir_value(position: int, limit: int) -> int:
        nonlocal unresolved
        cursor = skip_trivia(position, limit)
        if cursor < limit and source[cursor] in {"'", '"'}:
            value, cursor = scan_string(cursor, limit)
            if value:
                workdirs.append(value)
            else:
                unresolved = True
            return cursor
        unresolved = True
        return cursor

    def extract_call_workdirs(start: int, end: int) -> None:
        nonlocal unresolved
        argument_start = skip_trivia(start, end)
        if argument_start >= end:
            return
        if source[argument_start] != "{":
            # An identifier, function result, or another indirect argument may
            # contain a workdir that static inspection cannot attribute.
            unresolved = True
            return

        cursor = start
        brace_depth = 0
        bracket_depth = 0
        parenthesis_depth = 0
        expect_property_key = False
        object_end: int | None = None
        while cursor < end:
            after_trivia = skip_trivia(cursor, end)
            if after_trivia != cursor:
                cursor = after_trivia
                continue
            if cursor >= end:
                break
            char = source[cursor]
            if char in {"'", '"', "`"}:
                string_value, after_string = scan_string(cursor, end)
                after_key = skip_trivia(after_string, end)
                if (
                    brace_depth == 1
                    and bracket_depth == 0
                    and parenthesis_depth == 0
                    and expect_property_key
                    and string_value == "workdir"
                    and after_key < end
                    and source[after_key] == ":"
                ):
                    cursor = parse_workdir_value(after_key + 1, end)
                    expect_property_key = False
                else:
                    if (
                        brace_depth == 1
                        and bracket_depth == 0
                        and parenthesis_depth == 0
                        and expect_property_key
                    ):
                        expect_property_key = False
                    cursor = after_string
                continue
            if char == "/":
                cursor = skip_regex(cursor, end) if slash_begins_regex(cursor) else cursor + 1
                continue
            if char == "{":
                brace_depth += 1
                if brace_depth == 1:
                    expect_property_key = True
                cursor += 1
                continue
            if char == "}":
                if brace_depth == 1:
                    object_end = cursor + 1
                    brace_depth = 0
                    cursor += 1
                    break
                brace_depth = max(0, brace_depth - 1)
                cursor += 1
                continue
            at_property_level = (
                brace_depth == 1 and bracket_depth == 0 and parenthesis_depth == 0
            )
            if at_property_level and expect_property_key and source.startswith("...", cursor):
                unresolved = True
                expect_property_key = False
                cursor += 3
                continue
            if char == "[":
                if at_property_level and expect_property_key:
                    # A computed key may evaluate to "workdir".
                    unresolved = True
                    expect_property_key = False
                bracket_depth += 1
                cursor += 1
                continue
            if char == "]":
                bracket_depth = max(0, bracket_depth - 1)
                cursor += 1
                continue
            if char == "(":
                parenthesis_depth += 1
                cursor += 1
                continue
            if char == ")":
                parenthesis_depth = max(0, parenthesis_depth - 1)
                cursor += 1
                continue
            if at_property_level and char == ",":
                expect_property_key = True
                cursor += 1
                continue
            identifier_match = re.match(r"[A-Za-z_$][\w$]*", source[cursor:])
            if not identifier_match:
                cursor += 1
                continue
            identifier = identifier_match.group(0)
            after_identifier = cursor + len(identifier)
            if identifier == "workdir" and at_property_level and expect_property_key:
                after_key = skip_trivia(after_identifier, end)
                if after_key < end and source[after_key] == ":":
                    cursor = parse_workdir_value(after_key + 1, end)
                    expect_property_key = False
                    continue
                # `{workdir}` is shorthand for a dynamic value.
                unresolved = True
                expect_property_key = False
            elif at_property_level and expect_property_key:
                expect_property_key = False
            cursor = after_identifier

        if object_end is None:
            unresolved = True
            return
        if skip_trivia(object_end, end) != end:
            # Additional positional arguments are outside the supported
            # one-object tool-call schema and may affect attribution.
            unresolved = True

    def closing_parenthesis(opening: int) -> int | None:
        nonlocal unresolved
        depth = 1
        cursor = opening + 1
        while cursor < length:
            after_trivia = skip_trivia(cursor)
            if after_trivia != cursor:
                cursor = after_trivia
                continue
            if cursor >= length:
                break
            char = source[cursor]
            if char in {"'", '"', "`"}:
                _, cursor = scan_string(cursor)
                continue
            if char == "/":
                cursor = skip_regex(cursor) if slash_begins_regex(cursor) else cursor + 1
                continue
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    return cursor
            cursor += 1
        unresolved = True
        return None

    cursor = 0
    while cursor < length:
        after_trivia = skip_trivia(cursor)
        if after_trivia != cursor:
            cursor = after_trivia
            continue
        if cursor >= length:
            break
        char = source[cursor]
        if char in {"'", '"', "`"}:
            _, cursor = scan_string(cursor)
            continue
        if char == "/":
            cursor = skip_regex(cursor) if slash_begins_regex(cursor) else cursor + 1
            continue
        identifier_match = re.match(r"[A-Za-z_$][\w$]*", source[cursor:])
        if not identifier_match:
            cursor += 1
            continue
        identifier = identifier_match.group(0)
        after_identifier = cursor + len(identifier)
        if identifier == "tools" and previous_significant_char(cursor) != ".":
            position = skip_trivia(after_identifier)
            optional_member = False
            if source.startswith("?.", position):
                position = skip_trivia(position + 2)
                optional_member = True
            tool_name = ""
            if optional_member:
                method_match = re.match(r"[A-Za-z_$][\w$]*", source[position:])
                if method_match:
                    tool_name = method_match.group(0)
                    position += len(tool_name)
            elif position < length and source[position] == ".":
                position = skip_trivia(position + 1)
                method_match = re.match(r"[A-Za-z_$][\w$]*", source[position:])
                if method_match:
                    tool_name = method_match.group(0)
                    position += len(tool_name)
            elif position < length and source[position] == "[":
                position = skip_trivia(position + 1)
                if position < length and source[position] in {"'", '"'}:
                    tool_name, position = scan_string(position)
                    position = skip_trivia(position)
                    if position < length and source[position] == "]":
                        position += 1
                    else:
                        tool_name = ""
            position = skip_trivia(position)
            if source.startswith("?.", position):
                position = skip_trivia(position + 2)
            if tool_name and position < length and source[position] == "(":
                tool_names.append(tool_name)
                closing = closing_parenthesis(position)
                if closing is not None:
                    extract_call_workdirs(position + 1, closing)

        cursor = after_identifier

    return tool_names, list(dict.fromkeys(workdirs)), unresolved


def object_workdirs(value: Any) -> list[str]:
    workdirs: list[str] = []
    if isinstance(value, dict):
        candidate = value.get("workdir")
        if isinstance(candidate, (str, Path)) and str(candidate):
            workdirs.append(str(candidate))
        for child in value.values():
            workdirs.extend(object_workdirs(child))
    elif isinstance(value, list):
        for child in value:
            workdirs.extend(object_workdirs(child))
    return list(dict.fromkeys(workdirs))


def parse_tool_record(payload: dict[str, Any]) -> dict[str, Any] | None:
    record_type = str(payload.get("type") or "")
    if record_type not in {"function_call", "custom_tool_call"}:
        return None

    name = str(payload.get("name") or "")
    workdirs: list[str] = []
    invocations_estimate = 1
    resolved = True

    if record_type == "function_call":
        arguments = payload.get("arguments")
        if isinstance(arguments, dict):
            parsed: Any = arguments
        elif isinstance(arguments, str):
            try:
                parsed = json.loads(arguments)
            except json.JSONDecodeError:
                parsed = None
        else:
            parsed = None
        if isinstance(parsed, (dict, list)):
            workdirs = object_workdirs(parsed)
        else:
            resolved = False
    else:
        raw_input = payload.get("input")
        parsed_input: Any = None
        if isinstance(raw_input, (dict, list)):
            parsed_input = raw_input
        elif isinstance(raw_input, str):
            try:
                parsed_input = json.loads(raw_input)
            except json.JSONDecodeError:
                parsed_input = None

        if isinstance(parsed_input, (dict, list)):
            workdirs = object_workdirs(parsed_input)
        elif isinstance(raw_input, str) and name == "exec":
            nested_calls, workdirs, dynamic_workdir = javascript_wrapper_details(raw_input)
            invocations_estimate = len(nested_calls) or 1
            resolved = bool(nested_calls) and not dynamic_workdir
        elif isinstance(raw_input, str):
            resolved = True
        else:
            resolved = False

    return {
        "record_type": record_type,
        "name": name,
        "invocations_estimate": invocations_estimate,
        "workdirs": workdirs,
        "resolved": resolved,
    }


def session_scope_match(
    rows: list[dict[str, Any]],
    meta_cwd: str,
    cwd_root: Path,
    start: datetime | None = None,
    end: datetime | None = None,
) -> dict[str, str] | None:
    if meta_cwd and path_is_under(meta_cwd, cwd_root):
        return {"reason": "metadata_cwd", "matched_path": meta_cwd}
    for obj in rows:
        if start is not None and end is not None and not in_range(parse_event_ts(obj.get("timestamp")), start, end):
            continue
        payload = obj.get("payload") or {}
        if not isinstance(payload, dict):
            continue
        call = parse_tool_record(payload)
        if not call:
            continue
        for workdir in call["workdirs"]:
            if path_is_under(workdir, cwd_root):
                return {"reason": "tool_workdir", "matched_path": workdir}
    return None


def session_touches_cwd_root(
    rows: list[dict[str, Any]],
    meta_cwd: str,
    cwd_root: Path,
    start: datetime | None = None,
    end: datetime | None = None,
) -> bool:
    return session_scope_match(rows, meta_cwd, cwd_root, start, end) is not None


def collect_history(
    codex_home: Path,
    start: datetime,
    end: datetime,
    local_tz: ZoneInfo,
    limit: int,
    session_ids: set[str] | None = None,
    diagnostics: CollectorDiagnostics | None = None,
) -> list[dict[str, Any]]:
    history_path = codex_home / "history.jsonl"
    entries: list[dict[str, Any]] = []
    for obj in read_jsonl(history_path, diagnostics, "history"):
        ts = parse_event_ts(obj.get("ts") or obj.get("timestamp"))
        if not in_range(ts, start, end):
            continue
        text = str(obj.get("text") or obj.get("message") or obj.get("content") or "")
        session_id = str(obj.get("session_id") or "")
        if session_ids is not None and not session_matches(session_id, session_ids):
            continue
        secret_context = bool(SECRET_CONTEXT_RE.search(text))
        entries.append(
            {
                "local_time": ts.astimezone(local_tz).isoformat(timespec="minutes") if ts else "",
                "session": session_id[:8],
                "session_id": session_id,
                "text": "" if secret_context else preview(text, limit),
                "secret_context": "yes" if secret_context else "no",
                "preview_suppressed": secret_context,
                "preview_suppression_reason": "secret_context" if secret_context else "",
            }
        )
    return entries


def collect_history_activity_events(
    codex_home: Path,
    start: datetime,
    end: datetime,
    session_ids: set[str] | None = None,
    diagnostics: CollectorDiagnostics | None = None,
) -> list[dict[str, Any]]:
    history_path = codex_home / "history.jsonl"
    events: list[dict[str, Any]] = []
    for obj in read_jsonl(history_path, diagnostics, "history"):
        ts = parse_event_ts(obj.get("ts") or obj.get("timestamp"))
        if not in_range(ts, start, end):
            continue
        session_id = str(obj.get("session_id") or "")
        if session_ids is not None and not session_matches(session_id, session_ids):
            continue
        events.append(
            {
                "timestamp": iso_utc(ts),
                "session_id": session_id,
                "source": "history",
                "project": "",
                "cwd": "",
            }
        )
    return events


def collect_sessions(
    codex_home: Path,
    start: datetime,
    end: datetime,
    local_tz: ZoneInfo,
    session_ids: set[str] | None = None,
    cwd_root: Path | None = None,
    diagnostics: CollectorDiagnostics | None = None,
) -> list[dict[str, Any]]:
    sessions_root = codex_home / "sessions"
    sessions: list[dict[str, Any]] = []
    if not sessions_root.exists():
        if diagnostics:
            diagnostics.source("sessions").unavailable("sessions source directory does not exist")
        return sessions

    for path in sorted(sessions_root.rglob("*.jsonl")):
        rows = read_jsonl(path, diagnostics, "sessions")
        if not rows:
            continue
        meta_info = canonical_session_metadata(rows)
        meta = meta_info["canonical"]
        events_in_range = 0
        user_events = 0
        tool_call_records = 0
        tool_invocations_estimate = 0
        unresolved_tool_call_records = 0
        records_by_type = {"function_call": 0, "custom_tool_call": 0}
        explicit_workdir_records = 0
        session_cwd_fallback_records = 0
        tool_workdirs: list[str] = []
        first_event: datetime | None = None
        last_event: datetime | None = None

        for obj in rows:
            ts = parse_event_ts(obj.get("timestamp"))
            if not in_range(ts, start, end):
                continue
            events_in_range += 1
            first_event = ts if first_event is None else min(first_event, ts)  # type: ignore[arg-type]
            last_event = ts if last_event is None else max(last_event, ts)  # type: ignore[arg-type]
            payload = obj.get("payload") or {}
            if obj.get("type") == "event_msg" and isinstance(payload, dict) and payload.get("type") == "user_message":
                user_events += 1
            call = parse_tool_record(payload) if obj.get("type") == "response_item" and isinstance(payload, dict) else None
            if call:
                tool_call_records += 1
                tool_invocations_estimate += int(call["invocations_estimate"])
                records_by_type[call["record_type"]] += 1
                tool_workdirs.extend(str(item) for item in call["workdirs"])
                if not call["resolved"]:
                    unresolved_tool_call_records += 1
                elif call["workdirs"]:
                    explicit_workdir_records += 1
                else:
                    session_cwd_fallback_records += 1

        if events_in_range == 0:
            continue

        start_ts = parse_event_ts(meta.get("timestamp"))
        full_session_id = str(meta.get("id") or path.stem)
        cwd = str(meta.get("cwd") or "")
        if session_ids is not None and not session_matches(full_session_id, session_ids):
            continue
        if cwd_root is not None:
            scope_match = session_scope_match(rows, cwd, cwd_root, start, end)
            if scope_match is None:
                continue
        elif session_ids is not None:
            scope_match = {"reason": "session_id", "matched_path": ""}
        else:
            scope_match = {"reason": "time_range", "matched_path": ""}
        tool_workdirs = sorted(set(tool_workdirs))
        workdir_attribution = {
            "explicit_records": explicit_workdir_records,
            "session_cwd_fallback_records": session_cwd_fallback_records,
            "unresolved_records": unresolved_tool_call_records,
            "paths": tool_workdirs,
        }
        tool_activity = {
            "call_records": tool_call_records,
            "invocations_estimate": tool_invocations_estimate,
            "invocations_estimate_kind": "syntactic_call_site_estimate",
            "unresolved_records": unresolved_tool_call_records,
            "records_by_type": records_by_type,
            "workdir_attribution": workdir_attribution,
        }
        sessions.append(
            {
                "session": full_session_id[0:8],
                "session_id": full_session_id,
                "started": start_ts.astimezone(local_tz).isoformat(timespec="minutes") if start_ts else "",
                "first_event": first_event.astimezone(local_tz).isoformat(timespec="minutes") if first_event else "",
                "last_event": last_event.astimezone(local_tz).isoformat(timespec="minutes") if last_event else "",
                "cwd": cwd,
                "events": events_in_range,
                "user_events": user_events,
                "tool_calls": tool_call_records,
                "file": str(path),
                "identity_source": "first_session_meta" if meta_info["session_meta_records"] else "filename_fallback",
                "session_meta_records": meta_info["session_meta_records"],
                "invalid_session_meta_records": meta_info["invalid_session_meta_records"],
                "parent_session_id": meta_info["parent_session_id"],
                "forked_from_session_id": meta_info["forked_from_id"],
                "forked_from_id": meta_info["forked_from_id"],
                "thread_source": meta_info["thread_source"],
                "agent_path": meta_info["agent_path"],
                "spawn_depth": meta_info["spawn_depth"],
                "scope_match": scope_match,
                "match_reason": scope_match["reason"],
                "matched_workdirs": [scope_match["matched_path"]] if scope_match["matched_path"] else [],
                "match_uncertain": scope_match["reason"] == "tool_workdir",
                "tool_call_records": tool_call_records,
                "tool_invocations_estimate": tool_invocations_estimate,
                "tool_workdirs": tool_workdirs,
                "unresolved_tool_call_records": unresolved_tool_call_records,
                "tool_activity": tool_activity,
            }
        )
    return sessions


def collect_session_activity_events(
    codex_home: Path,
    start: datetime,
    end: datetime,
    session_ids: set[str] | None = None,
    cwd_root: Path | None = None,
    diagnostics: CollectorDiagnostics | None = None,
) -> list[dict[str, Any]]:
    sessions_root = codex_home / "sessions"
    events: list[dict[str, Any]] = []
    if not sessions_root.exists():
        if diagnostics:
            diagnostics.source("sessions").unavailable("sessions source directory does not exist")
        return events

    git_root_cache: dict[str, Path | None] = {}

    def cached_git_root(path_value: str) -> Path | None:
        if not path_value:
            return None
        if path_value not in git_root_cache:
            git_root_cache[path_value] = find_git_root(Path(path_value))
        return git_root_cache[path_value]

    for path in sorted(sessions_root.rglob("*.jsonl")):
        rows = read_jsonl(path, diagnostics, "sessions")
        if not rows:
            continue

        meta = canonical_session_metadata(rows)["canonical"]

        full_session_id = str(meta.get("id") or path.stem)
        cwd = str(meta.get("cwd") or "")
        if session_ids is not None and not session_matches(full_session_id, session_ids):
            continue
        if cwd_root is not None and not session_touches_cwd_root(rows, cwd, cwd_root, start, end):
            continue

        project_root = cached_git_root(cwd)
        project = project_root.name if project_root else (Path(cwd).name if cwd else "unknown")

        for obj in rows:
            ts = parse_event_ts(obj.get("timestamp"))
            if not in_range(ts, start, end):
                continue
            payload = obj.get("payload") or {}
            call = parse_tool_record(payload) if isinstance(payload, dict) else None
            event_cwds = call["workdirs"] if call and call["workdirs"] else [cwd]
            for event_cwd in dict.fromkeys(str(item) for item in event_cwds if item):
                if cwd_root is not None and not path_is_under(event_cwd, cwd_root):
                    continue
                event_project_root = cached_git_root(event_cwd)
                event_project = event_project_root.name if event_project_root else project
                events.append(
                    {
                        "timestamp": iso_utc(ts),
                        "session_id": full_session_id,
                        "source": "session",
                        "project": event_project,
                        "cwd": event_cwd,
                    }
                )
    return events


def parse_utc_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def estimate_active_seconds(timestamps: list[datetime], gap_cap_seconds: int) -> int:
    if len(timestamps) < 2:
        return 0
    ordered = sorted(set(timestamps))
    return int(sum(min((right - left).total_seconds(), gap_cap_seconds) for left, right in pairwise(ordered)))


def estimate_work_time(activity_events: list[dict[str, Any]], local_tz: ZoneInfo, gap_minutes: int) -> dict[str, Any]:
    gap_cap_seconds = max(1, gap_minutes) * 60
    timestamps: list[datetime] = []
    per_project: dict[str, list[datetime]] = {}

    for event in activity_events:
        try:
            ts = parse_utc_iso(str(event["timestamp"]))
        except (KeyError, ValueError):
            continue
        timestamps.append(ts)
        project = str(event.get("project") or "").strip()
        if project:
            per_project.setdefault(project, []).append(ts)

    by_day: list[dict[str, Any]] = []
    day_groups: dict[str, list[datetime]] = {}
    for ts in timestamps:
        day_groups.setdefault(ts.astimezone(local_tz).date().isoformat(), []).append(ts)

    for day, day_timestamps in sorted(day_groups.items()):
        ordered = sorted(day_timestamps)
        first = ordered[0].astimezone(local_tz)
        last = ordered[-1].astimezone(local_tz)
        span_seconds = int((ordered[-1] - ordered[0]).total_seconds()) if len(ordered) > 1 else 0
        active_seconds = estimate_active_seconds(ordered, gap_cap_seconds)
        by_day.append(
            {
                "day": day,
                "start": first.isoformat(timespec="minutes"),
                "end": last.isoformat(timespec="minutes"),
                "span_hours": round(span_seconds / 3600, 2),
                "active_hours_estimate": round(active_seconds / 3600, 2),
                "events": len(day_timestamps),
            }
        )

    project_rows: list[dict[str, Any]] = []
    for project, project_timestamps in sorted(per_project.items()):
        ordered = sorted(project_timestamps)
        first = ordered[0].astimezone(local_tz)
        last = ordered[-1].astimezone(local_tz)
        span_seconds = int((ordered[-1] - ordered[0]).total_seconds()) if len(ordered) > 1 else 0
        active_seconds = estimate_active_seconds(ordered, gap_cap_seconds)
        project_rows.append(
            {
                "project": project,
                "start": first.isoformat(timespec="minutes"),
                "end": last.isoformat(timespec="minutes"),
                "span_hours": round(span_seconds / 3600, 2),
                "active_hours_estimate": round(active_seconds / 3600, 2),
                "events": len(project_timestamps),
            }
        )
    project_rows.sort(key=lambda item: (item["active_hours_estimate"], item["events"]), reverse=True)

    extreme_days = [item["day"] for item in by_day if item["active_hours_estimate"] > 20]
    warnings: list[dict[str, str]] = [
        {
            "code": "activity_coverage_non_additive",
            "severity": "info",
            "message": "Activity coverage is not time tracking; project rows may overlap and must not be summed.",
        }
    ]
    if extreme_days:
        warnings.append(
            {
                "code": "activity_coverage_extreme_day",
                "severity": "warning",
                "message": "At least one day exceeds 20 estimated activity-coverage hours; overlapping or long-lived sessions are likely.",
            }
        )

    return {
        "metric_name": "codex_activity_coverage_estimate",
        "non_additive": True,
        "is_time_tracking": False,
        "method": (
            "Non-additive Codex activity coverage from session/tool timestamps, falling back to prompt history if no "
            f"session events exist. Gaps up to {gap_minutes} minutes contribute to coverage; longer gaps are capped. "
            "Span hours include pauses, parallel sessions may overlap, and project rows must not be summed."
        ),
        "gap_cap_minutes": gap_minutes,
        "warning_flags": {
            "extreme_day_count": len(extreme_days),
            "extreme_days": extreme_days,
            "project_totals_non_additive": True,
        },
        "warnings": warnings,
        "by_day": by_day,
        "by_project": project_rows,
    }


def infer_session_id(
    codex_home: Path,
    start: datetime,
    end: datetime,
    local_tz: ZoneInfo,
    cwd_root: Path | None = None,
) -> str | None:
    candidates = collect_sessions(codex_home, start, end, local_tz, cwd_root=cwd_root)
    if not candidates:
        return None
    candidates.sort(key=lambda item: item["last_event"], reverse=True)
    return str(candidates[0]["session_id"])


def summary_title(path: Path) -> str:
    name = path.stem
    parts = name.split("-", 5)
    if len(parts) >= 6:
        return parts[-1].replace("_", " ")
    return name.replace("_", " ")


def collect_rollout_summaries(
    codex_home: Path,
    start: datetime,
    end: datetime,
    local_tz: ZoneInfo,
    match_terms: list[str] | None = None,
    diagnostics: CollectorDiagnostics | None = None,
) -> list[dict[str, str]]:
    root = codex_home / "memories" / "rollout_summaries"
    results: list[dict[str, str]] = []
    if not root.exists():
        if diagnostics:
            diagnostics.source("rollout_summaries").unavailable("rollout summary source directory does not exist")
        return results
    for path in sorted(root.glob("*.md")):
        source_diagnostic = diagnostics.source("rollout_summaries") if diagnostics else None
        if source_diagnostic:
            source_diagnostic.consider(path)
        ts_match = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2})", path.name)
        ts = None
        if ts_match:
            try:
                ts = datetime.strptime(ts_match.group(1), "%Y-%m-%dT%H-%M-%S").replace(
                    tzinfo=timezone.utc
                )
            except ValueError:
                if source_diagnostic:
                    source_diagnostic.invalid_timestamps += 1
                continue
        if not in_range(ts, start, end):
            continue
        if match_terms:
            haystack = path.name.lower()
            try:
                haystack += "\n" + path.read_text(encoding="utf-8", errors="replace").lower()
            except OSError:
                if source_diagnostic:
                    source_diagnostic.io_errors += 1
                    source_diagnostic.unavailable("one or more rollout summaries could not be read")
                continue
            if source_diagnostic:
                source_diagnostic.read(path)
            if not any(term.lower() in haystack for term in match_terms if term):
                continue
        elif source_diagnostic:
            source_diagnostic.read(path)
        results.append(
            {
                "local_time": ts.astimezone(local_tz).isoformat(timespec="minutes") if ts else "",
                "title": summary_title(path),
                "file": str(path),
            }
        )
    return results


def default_repo_roots(home: Path) -> list[Path]:
    return [home / "gitlab", home / "github"]


def git_repos(repo_roots: list[Path], diagnostics: CollectorDiagnostics | None = None) -> list[Path]:
    repos: list[Path] = []
    for root in repo_roots:
        if not root.exists():
            if diagnostics:
                diagnostics.source("git").unavailable("one or more configured repository roots do not exist")
            continue
        if (root / ".git").exists():
            repos.append(root)
            continue
        try:
            children = sorted(root.iterdir())
        except OSError:
            if diagnostics:
                diagnostics.source("git").io_errors += 1
                diagnostics.source("git").unavailable("one or more repository roots could not be read")
            continue
        for child in children:
            if child.is_dir() and (child / ".git").exists():
                repos.append(child)
    return repos


def run_git_log(
    repo: Path,
    start: datetime,
    end: datetime,
    diagnostics: CollectorDiagnostics | None = None,
) -> list[dict[str, Any]]:
    cmd = [
        "git",
        "-C",
        str(repo),
        "log",
        "--all",
        f"--since={start.isoformat()}",
        f"--until={end.isoformat()}",
        "--date=iso-strict",
        "-z",
        "--pretty=format:%aI%x00%an%x00%ae%x00%cI%x00%cn%x00%ce%x00%h%x00%s",
    ]
    source_diagnostic = diagnostics.source("git") if diagnostics else None
    if source_diagnostic:
        source_diagnostic.consider(repo)
    try:
        proc = subprocess.run(
            cmd,
            check=False,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=12,
        )
    except subprocess.TimeoutExpired:
        if source_diagnostic:
            source_diagnostic.timeouts += 1
            source_diagnostic.unavailable("one or more git log commands timed out")
        return []
    except OSError:
        if source_diagnostic:
            source_diagnostic.command_errors += 1
            source_diagnostic.unavailable("one or more git log commands could not start")
        return []
    if proc.returncode != 0:
        if source_diagnostic:
            source_diagnostic.command_errors += 1
            source_diagnostic.unavailable("one or more git log commands failed")
        return []
    if source_diagnostic:
        source_diagnostic.read(repo)
    commits: list[dict[str, Any]] = []
    parts = proc.stdout.split("\x00")
    if parts and parts[-1] == "":
        parts.pop()
    for offset in range(0, len(parts), 8):
        fields = parts[offset : offset + 8]
        if len(fields) != 8:
            if source_diagnostic:
                source_diagnostic.malformed_records += 1
            continue
        author_date, author_name, author_email, committer_date, committer_name, committer_email, commit_hash, subject = fields
        commits.append(
            {
                "date": committer_date,
                "hash": commit_hash,
                "subject": redact(subject),
                "author": {"name": author_name, "email": author_email, "date": author_date},
                "committer": {"name": committer_name, "email": committer_email, "date": committer_date},
            }
        )
    return commits


def collect_git(
    repo_roots: list[Path],
    start: datetime,
    end: datetime,
    diagnostics: CollectorDiagnostics | None = None,
) -> dict[str, list[dict[str, Any]]]:
    activity: dict[str, list[dict[str, Any]]] = {}
    for repo in git_repos(repo_roots, diagnostics):
        commits = run_git_log(repo, start, end, diagnostics)
        if commits:
            activity[str(repo)] = commits
    return activity


def collect_notes(
    root: Path,
    start: datetime,
    end: datetime,
    local_tz: ZoneInfo,
    match_terms: list[str] | None = None,
    diagnostics: CollectorDiagnostics | None = None,
) -> list[dict[str, str]]:
    notes: list[dict[str, str]] = []
    if not root.exists():
        if diagnostics:
            diagnostics.source("notes").unavailable("notes source directory does not exist")
        return notes
    for path in sorted(root.rglob("*.md")):
        source_diagnostic = diagnostics.source("notes") if diagnostics else None
        if source_diagnostic:
            source_diagnostic.consider(path)
        try:
            mtime = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
        except OSError:
            if source_diagnostic:
                source_diagnostic.io_errors += 1
                source_diagnostic.unavailable("one or more notes could not be inspected")
            continue
        if not in_range(mtime, start, end):
            continue
        if match_terms:
            haystack = str(path).lower()
            try:
                haystack += "\n" + path.read_text(encoding="utf-8", errors="replace").lower()
            except OSError:
                if source_diagnostic:
                    source_diagnostic.io_errors += 1
                    source_diagnostic.unavailable("one or more notes could not be read")
                continue
            if source_diagnostic:
                source_diagnostic.read(path)
            if not any(term.lower() in haystack for term in match_terms if term):
                continue
        elif source_diagnostic:
            source_diagnostic.read(path)
        notes.append(
            {
                "local_time": mtime.astimezone(local_tz).isoformat(timespec="minutes"),
                "file": str(path),
            }
        )
    return notes


def resolve_scope(args: argparse.Namespace, codex_home: Path, local_tz: ZoneInfo) -> dict[str, Any]:
    cwd = normalize_path(Path(args.cwd))
    project_root = normalize_path(Path(args.project_root)) if args.project_root else find_git_root(cwd)
    effective_project_root = project_root or cwd
    now = parse_now(args.now, local_tz)
    end = parse_dt(args.end, local_tz, is_end=True) if args.end else now
    start = parse_dt(args.start, local_tz, is_end=False) if args.start else default_start_for_range(args.default_range, end, local_tz)
    warnings: list[str] = []
    if project_root is None and args.scope in {"local", "project"}:
        warnings.append("could not detect a git project root; using --cwd as project root")

    session_id = args.session_id or os.environ.get("CODEX_THREAD_ID") or os.environ.get("CODEX_SESSION_ID")
    if session_id and not args.session_id:
        warnings.append("using session_id from CODEX_THREAD_ID/CODEX_SESSION_ID environment")
    if args.scope in {"local", "session"} and not session_id:
        session_id = infer_session_id(codex_home, start, end, local_tz, cwd_root=effective_project_root if args.scope == "local" else None)
        if not session_id and args.scope == "local":
            session_id = infer_session_id(codex_home, start, end, local_tz)
            if session_id:
                warnings.append("inferred session_id from latest session in range without cwd/project match")
        if session_id:
            warnings.append(f"inferred session_id={session_id}")
        else:
            warnings.append("could not infer a current Codex session_id for this scope")

    if args.scope == "session" and not args.start and session_id:
        broad_start = datetime(1970, 1, 1, tzinfo=timezone.utc)
        matched = collect_sessions(codex_home, broad_start, end, local_tz, session_ids={session_id})
        if matched:
            started = matched[0].get("started")
            if started:
                start = parse_dt(str(started), local_tz, is_end=False)

    if end < start:
        raise SystemExit("error: --end must be after --start")

    return {
        "requested": args.scope,
        "effective": args.scope,
        "cwd": str(cwd),
        "project_root": str(effective_project_root),
        "project_root_detected": project_root is not None,
        "session_id": session_id or "",
        "default_range": args.default_range,
        "start": start,
        "end": end,
        "warnings": warnings,
    }


def current_script_sha256() -> str:
    try:
        return hashlib.sha256(SCRIPT_PATH.read_bytes()).hexdigest()
    except OSError:
        return ""


def finalize_diagnostics(
    diagnostics: CollectorDiagnostics,
    sessions: list[dict[str, Any]],
) -> dict[str, Any]:
    result = diagnostics.as_dict()
    source_rows = result["sources"]
    warnings: list[dict[str, str]] = []
    for source, item in source_rows.items():
        if item["status"] in {"partial", "unavailable"}:
            warnings.append(
                {
                    "code": f"{source}_{item['status']}",
                    "severity": "warning",
                    "source": source,
                    "message": f"The {source} source has incomplete collector coverage; inspect its counters.",
                }
            )
        elif item["status"] == "skipped":
            warnings.append(
                {
                    "code": f"{source}_skipped",
                    "severity": "info",
                    "source": source,
                    "message": f"The {source} source was intentionally skipped: {item['skipped_reason']}.",
                }
            )

    records_by_type = {"function_call": 0, "custom_tool_call": 0}
    call_records = 0
    invocations_estimate = 0
    unresolved_records = 0
    recognized_workdirs: set[str] = set()
    for session in sessions:
        tool_activity = session["tool_activity"]
        call_records += int(tool_activity["call_records"])
        invocations_estimate += int(tool_activity["invocations_estimate"])
        unresolved_records += int(tool_activity["unresolved_records"])
        for record_type, count in tool_activity["records_by_type"].items():
            records_by_type[record_type] += int(count)
        recognized_workdirs.update(tool_activity["workdir_attribution"]["paths"])

    partial = any(item["status"] in {"partial", "unavailable"} for item in source_rows.values())
    result.update(
        {
            "status": "partial" if partial else "complete",
            "complete": not partial,
            "warnings": warnings,
            "tool_parser": {
                "call_records": call_records,
                "invocations_estimate": invocations_estimate,
                "invocations_estimate_kind": "syntactic_call_site_estimate",
                "unresolved_records": unresolved_records,
                "records_by_type": records_by_type,
                "recognized_workdirs": len(recognized_workdirs),
            },
        }
    )
    return result


def build_payload(args: argparse.Namespace) -> dict[str, Any]:
    home = Path(args.home).expanduser()
    codex_home = Path(args.codex_home).expanduser() if args.codex_home else home / ".codex"
    repo_roots = [Path(root).expanduser() for root in args.repo_root] if args.repo_root else default_repo_roots(home)
    notes_root = Path(args.notes_root).expanduser() if args.notes_root else home / "Obsidian"

    try:
        local_tz = ZoneInfo(args.timezone)
    except ZoneInfoNotFoundError as exc:
        raise SystemExit(
            f"error: timezone data for {args.timezone!r} is not available. "
            "Run this script through uv, for example: "
            "uv run --with tzdata -- python extract_codex_session_evidence.py ..."
        ) from exc

    diagnostics = CollectorDiagnostics()
    scope = resolve_scope(args, codex_home, local_tz)
    start = scope["start"]
    end = scope["end"]

    selected_session_ids: set[str] | None = None
    session_cwd_root: Path | None = None
    selected_repo_roots = repo_roots
    summary_terms: list[str] | None = None
    notes_terms: list[str] | None = None

    if args.scope == "global":
        scope["notes_mode"] = "all_in_range"
    elif args.scope == "session":
        scope["notes_mode"] = "disabled"
        selected_session_ids = {scope["session_id"]} if scope["session_id"] else set()
        selected_repo_roots = [Path(scope["project_root"])]
        summary_terms = [Path(scope["project_root"]).name, scope["session_id"]]
    elif args.scope == "project":
        scope["notes_mode"] = "project_terms"
        session_cwd_root = Path(scope["project_root"])
        project_sessions = collect_sessions(codex_home, start, end, local_tz, cwd_root=session_cwd_root)
        selected_session_ids = {str(session["session_id"]) for session in project_sessions}
        selected_repo_roots = [Path(scope["project_root"])]
        summary_terms = [Path(scope["project_root"]).name]
        notes_terms = summary_terms
    else:
        scope["notes_mode"] = "project_terms"
        local_ids = {scope["session_id"]} if scope["session_id"] else set()
        project_sessions = collect_sessions(codex_home, start, end, local_tz, cwd_root=Path(scope["project_root"]))
        local_ids.update(str(session["session_id"]) for session in project_sessions)
        selected_session_ids = local_ids
        selected_repo_roots = [Path(scope["project_root"])]
        summary_terms = [Path(scope["project_root"]).name, scope["session_id"]]
        notes_terms = summary_terms

    activity_events = collect_session_activity_events(
        codex_home,
        start,
        end,
        session_ids=selected_session_ids,
        cwd_root=session_cwd_root,
        diagnostics=diagnostics,
    )
    if not activity_events:
        activity_events = collect_history_activity_events(
            codex_home,
            start,
            end,
            session_ids=selected_session_ids,
            diagnostics=diagnostics,
        )

    history = collect_history(
        codex_home,
        start,
        end,
        local_tz,
        args.prompt_preview_chars,
        session_ids=selected_session_ids,
        diagnostics=diagnostics,
    )
    sessions = collect_sessions(
        codex_home,
        start,
        end,
        local_tz,
        session_ids=selected_session_ids,
        cwd_root=session_cwd_root,
        diagnostics=diagnostics,
    )
    rollout_summaries = collect_rollout_summaries(
        codex_home,
        start,
        end,
        local_tz,
        match_terms=summary_terms,
        diagnostics=diagnostics,
    )
    git_activity = collect_git(selected_repo_roots, start, end, diagnostics)
    if args.scope == "session":
        diagnostics.source("notes").skip("session_scope_unbound")
        notes: list[dict[str, str]] = []
    else:
        notes = collect_notes(notes_root, start, end, local_tz, match_terms=notes_terms, diagnostics=diagnostics)
    work_time_estimate = estimate_work_time(activity_events, local_tz, args.activity_gap_minutes)
    collector_diagnostics = finalize_diagnostics(diagnostics, sessions)

    return {
        "schema_version": SCHEMA_VERSION,
        "collector": {
            "name": "codex-session-analysis",
            "version": COLLECTOR_VERSION,
            "script_sha256": current_script_sha256(),
            "generated_at_utc": iso_utc(parse_now(args.now, local_tz)),
        },
        "privacy": {
            "raw_prompts_included": False,
            "prompt_preview_policy": "suppress_secret_context",
            "redaction": "heuristic",
            "secret_context_previews_suppressed": sum(1 for item in history if item["preview_suppressed"]),
        },
        "machine": args.machine,
        "scope": {
            key: value
            for key, value in scope.items()
            if key not in {"start", "end"}
        },
        "range": {
            "timezone": args.timezone,
            "start_local": start.astimezone(local_tz).isoformat(timespec="minutes"),
            "end_local": end.astimezone(local_tz).isoformat(timespec="minutes"),
            "start_utc": start.isoformat(timespec="seconds"),
            "end_utc": end.isoformat(timespec="seconds"),
        },
        "paths": {
            "home": str(home),
            "codex_home": str(codex_home),
            "repo_roots": [str(root) for root in selected_repo_roots],
            "notes_root": str(notes_root),
        },
        "history": history,
        "sessions": sessions,
        "rollout_summaries": rollout_summaries,
        "git_activity": git_activity,
        "git_attribution": {
            "mode": "repository_evidence_only",
            "codex_attribution_inferred": False,
            "message": "Git activity is repository evidence only; commits are not automatically attributable to Codex.",
        },
        "notes": notes,
        "work_time_estimate": work_time_estimate,
        "diagnostics": collector_diagnostics,
    }


def emit_markdown(payload: dict[str, Any]) -> None:
    r = payload["range"]
    paths = payload["paths"]
    scope = payload["scope"]
    collector = payload["collector"]
    diagnostics = payload["diagnostics"]
    print("# Codex Activity Evidence Pack")
    print()
    print(
        f"- Contract: schema v{payload['schema_version']}; collector {collector['name']} "
        f"{collector['version']}; script SHA-256 `{collector['script_sha256']}`"
    )
    print(f"- Coverage: {diagnostics['status']}")
    print(f"- Machine: {payload['machine']}")
    print(f"- Scope: {scope['effective']}")
    print(f"- Scope cwd: {scope['cwd']}")
    print(f"- Scope project root: {scope['project_root']}")
    if scope.get("session_id"):
        print(f"- Scope session: {scope['session_id']}")
    print(f"- Local range: {r['start_local']} to {r['end_local']} ({r['timezone']})")
    print(f"- UTC range: {r['start_utc']} to {r['end_utc']}")
    print(f"- Codex home: {paths['codex_home']}")
    print(f"- Repo roots: {', '.join(paths['repo_roots'])}")
    print(f"- Notes root: {paths['notes_root']}")
    print(
        "- Safety: secret-context prompt previews are suppressed. Remaining previews and commit subjects are redacted "
        "heuristically; this is evidence, not a raw archive."
    )
    print(f"- Git attribution: {payload['git_attribution']['message']}")
    print("- Activity interpretation: coverage is non-additive and is not time tracking; project rows may overlap.")
    for warning in scope.get("warnings", []):
        print(f"- Warning: {warning}")
    print()

    estimate = payload["work_time_estimate"]
    print("## Codex Activity Coverage By Day")
    print()
    print(f"Method: {estimate['method']}")
    for warning in estimate["warnings"]:
        print(f"- {warning['severity'].title()} [{warning['code']}]: {warning['message']}")
    print()
    if estimate["by_day"]:
        print("| Day | First event | Last event | Span h | Active estimate h | Events |")
        print("| --- | --- | --- | ---: | ---: | ---: |")
        for item in estimate["by_day"]:
            print(
                f"| {item['day']} | {item['start']} | {item['end']} | "
                f"{item['span_hours']:.2f} | {item['active_hours_estimate']:.2f} | {item['events']} |"
            )
    else:
        print("No activity events found for this scope/range.")
    print()

    print("## Codex Activity Coverage By Project")
    print()
    if estimate["by_project"]:
        print("| Project | First event | Last event | Span h | Active estimate h | Events |")
        print("| --- | --- | --- | ---: | ---: | ---: |")
        for item in estimate["by_project"]:
            print(
                f"| {item['project']} | {item['start']} | {item['end']} | "
                f"{item['span_hours']:.2f} | {item['active_hours_estimate']:.2f} | {item['events']} |"
            )
    else:
        print("No project-attributed activity events found for this scope/range.")
    print()

    history = payload["history"]
    print(f"## User Prompt Index ({len(history)})")
    for item in history:
        if item["preview_suppressed"]:
            print(f"- {item['local_time']} session `{item['session']}` [secret-context; preview suppressed]")
        else:
            print(f"- {item['local_time']} session `{item['session']}`: {item['text']}")
    print()

    sessions = payload["sessions"]
    print(f"## Codex Sessions ({len(sessions)})")
    for item in sessions:
        parent = item["parent_session_id"] or "none"
        forked_from = item["forked_from_session_id"] or "none"
        print(
            f"- `{item['session']}` {item['first_event']} to {item['last_event']}: "
            f"{item['cwd'] or '(no cwd)'}; events={item['events']}, user={item['user_events']}, "
            f"tool-call records={item['tool_call_records']}, tool-invocation estimate={item['tool_invocations_estimate']}, "
            f"unresolved tool records={item['unresolved_tool_call_records']}, match={item['match_reason']}, "
            f"parent={parent}, forked-from={forked_from}"
        )
    print()

    summaries = payload["rollout_summaries"]
    print(f"## Rollout Summaries ({len(summaries)})")
    for item in summaries:
        print(f"- {item['local_time']}: {item['title']} ({item['file']})")
    print()

    git_activity = payload["git_activity"]
    total_commits = sum(len(commits) for commits in git_activity.values())
    print(f"## Git Activity ({len(git_activity)} repos, {total_commits} commits)")
    print()
    print(payload["git_attribution"]["message"])
    for repo, commits in git_activity.items():
        print(f"### {repo}")
        for commit in commits:
            author = commit["author"]
            committer = commit["committer"]
            attribution = f"author={author['name']} <{author['email']}>"
            if (author["name"], author["email"]) != (committer["name"], committer["email"]):
                attribution += f"; committer={committer['name']} <{committer['email']}>"
            print(f"- {commit['date']} `{commit['hash']}` {commit['subject']} ({attribution})")
        print()

    print("## Collector Diagnostics")
    print()
    print("| Source | Status | Files read/considered | Scans | Lines | Records | Malformed | Non-object | Schema errors | Invalid time | Unknown | I/O | Command | Timeouts |")
    print("| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for source, item in diagnostics["sources"].items():
        print(
            f"| {source} | {item['status']} | {item['files_read']}/{item['files_considered']} | "
            f"{item['scan_passes']} | {item['lines_seen']} | {item['records_read']} | {item['malformed_records']} | "
            f"{item['non_object_records']} | {item['schema_errors']} | {item['invalid_timestamps']} | {item['unknown_records']} | "
            f"{item['io_errors']} | {item['command_errors']} | {item['timeouts']} |"
        )
    for warning in diagnostics["warnings"]:
        print(f"- {warning['severity'].title()} [{warning['code']}] ({warning['source']}): {warning['message']}")
    print()

    notes = payload["notes"]
    if scope.get("notes_mode") == "disabled":
        print("## Obsidian Notes (not scanned)")
        print()
        print("Notes were not scanned because session scope has no strict session-to-note binding.")
    else:
        print(f"## Obsidian Notes ({len(notes)})")
        for item in notes:
            print(f"- {item['local_time']}: {item['file']}")


def main() -> int:
    args = parse_args()
    payload = build_payload(args)
    if args.output:
        output_path = Path(args.output).expanduser()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8", newline="\n") as handle:
            if args.format == "json":
                json.dump(payload, handle, ensure_ascii=False, indent=2)
                handle.write("\n")
            else:
                with contextlib.redirect_stdout(handle):
                    emit_markdown(payload)
    elif args.format == "json":
        json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
        print()
    else:
        emit_markdown(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
