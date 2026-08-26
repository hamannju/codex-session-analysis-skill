#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, time, timedelta, timezone
from itertools import pairwise
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

SCHEMA_VERSION = "2.1"
COLLECTOR_VERSION = "2.2.0"
SCRIPT_PATH = Path(__file__).resolve()
SOURCE_NAMES = ("history", "sessions", "rollout_summaries", "git", "notes")
TASK_HISTORY_PRELUDE_SECONDS = 5
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


@dataclass
class ScopeMetrics:
    events: int = 0
    user_events: int = 0
    tool_call_records: int = 0
    tool_invocations_estimate: int = 0
    unresolved_tool_call_records: int = 0
    invocation_unresolved_records: int = 0
    workdir_unresolved_records: int = 0
    syntax_dynamic_uncertain_records: int = 0
    records_by_type: dict[str, int] = field(
        default_factory=lambda: {"function_call": 0, "custom_tool_call": 0}
    )
    explicit_workdir_records: int = 0
    session_cwd_fallback_records: int = 0
    tool_workdirs: set[str] = field(default_factory=set)
    first_event: datetime | None = None
    last_event: datetime | None = None


@dataclass
class ActivityAnchor:
    timestamp: datetime
    kind: str
    workdirs: tuple[str, ...] = ()


@dataclass
class LocatorHit:
    timestamp: datetime | None
    kind: str
    turn_id: str


@dataclass
class TaskInventory:
    turn_id: str
    start: datetime
    end: datetime | None = None
    metrics: ScopeMetrics = field(default_factory=ScopeMetrics)
    anchors: list[ActivityAnchor] = field(default_factory=list)


@dataclass
class SessionInventory:
    path: Path
    canonical: dict[str, Any]
    session_meta_records: int
    invalid_session_meta_records: int
    parent_session_id: str
    forked_from_id: str
    thread_source: str
    agent_path: str
    spawn_depth: Any
    metrics: ScopeMetrics
    tasks: list[TaskInventory]
    unbound_anchors: list[ActivityAnchor]
    unbound_workdirs: set[str]
    locator_hits: list[LocatorHit] = field(default_factory=list)

    @property
    def session_id(self) -> str:
        return str(self.canonical.get("id") or self.path.stem)

    @property
    def cwd(self) -> str:
        return str(self.canonical.get("cwd") or "")


@dataclass
class SessionScanResult:
    inventories: list[SessionInventory]
    strategy: str
    requested_session_ids: tuple[str, ...]
    files_available: int
    files_read: int
    fallback_used: bool


@dataclass
class SessionSelection:
    inventory: SessionInventory
    scope_match: dict[str, str]
    task_indexes: tuple[int, ...] | None
    history_binding: str
    project_root: Path | None = None


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


def source_names(value: str) -> tuple[str, ...]:
    aliases = {
        "history": "history",
        "sessions": "sessions",
        "summaries": "rollout_summaries",
        "rollout_summaries": "rollout_summaries",
        "git": "git",
        "notes": "notes",
    }
    requested: list[str] = []
    unknown: list[str] = []
    for item in value.split(","):
        name = item.strip().lower()
        if not name:
            continue
        if name not in aliases:
            unknown.append(name)
            continue
        canonical = aliases[name]
        if canonical not in requested:
            requested.append(canonical)
    if unknown:
        raise argparse.ArgumentTypeError(
            "unknown source(s): " + ", ".join(sorted(unknown))
        )
    if not requested:
        raise argparse.ArgumentTypeError("at least one source is required")
    return tuple(requested)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract a sanitized evidence pack for a Codex Session Analysis."
    )
    parser.add_argument(
        "--version",
        action="version",
        version=(
            f"codex-session-analysis {COLLECTOR_VERSION} "
            f"(schema {SCHEMA_VERSION})"
        ),
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
    parser.add_argument(
        "--mode",
        choices=("evidence", "locate"),
        default="evidence",
        help="Build a full evidence pack or locate matching session/task candidates",
    )
    parser.add_argument(
        "--match",
        action="append",
        default=[],
        help="Text to locate in sanitized source fields. Repeat for multiple terms",
    )
    parser.add_argument(
        "--sources",
        type=source_names,
        help="Comma-separated sources: history,sessions,summaries,git,notes",
    )
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
    args = parser.parse_args(argv)
    if args.mode == "locate" and not any(term.strip() for term in args.match):
        parser.error("--mode locate requires at least one non-empty --match")
    return args


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


def matches_terms(values: list[str], match_terms: list[str] | tuple[str, ...]) -> bool:
    terms = [term.strip().casefold() for term in match_terms if term.strip()]
    if not terms:
        return False
    haystack = "\n".join(values).casefold()
    return any(term in haystack for term in terms)


def iter_jsonl(
    path: Path,
    diagnostics: CollectorDiagnostics | None = None,
    source: str = "sessions",
) -> Any:
    resolved = normalize_path(path)
    source_diagnostic = diagnostics.source(source) if diagnostics else None
    record_diagnostics = False
    if source_diagnostic:
        source_diagnostic.consider(resolved)
        record_diagnostics = resolved not in diagnostics.jsonl_diagnosed_paths
        diagnostics.jsonl_diagnosed_paths.add(resolved)

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
                    yield obj
                elif source_diagnostic and record_diagnostics:
                    source_diagnostic.non_object_records += 1
    except OSError:
        if source_diagnostic and record_diagnostics:
            source_diagnostic.io_errors += 1
            source_diagnostic.unavailable("one or more source files could not be read")
        return


def read_jsonl(
    path: Path,
    diagnostics: CollectorDiagnostics | None = None,
    source: str = "sessions",
) -> list[dict[str, Any]]:
    """Compatibility wrapper for small sources and direct callers."""
    return list(iter_jsonl(path, diagnostics, source))


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


def resolve_tool_workdir(value: str, session_cwd: str) -> str | None:
    """Resolve static workdirs without depending on the collector process CWD."""
    candidate = value.strip()
    if not candidate or any(marker in candidate for marker in ("$", "`", "${")):
        return None
    path = Path(candidate).expanduser()
    if not path.is_absolute():
        if not session_cwd:
            return None
        path = Path(session_cwd) / path
    return str(normalize_path(path))


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


def decode_javascript_string(value: str) -> tuple[str, bool]:
    """Decode a quoted JavaScript string without evaluating Python syntax."""
    if len(value) < 2 or value[0] not in {"'", '"'} or value[-1] != value[0]:
        return "", True
    result: list[str] = []
    uncertain = False
    cursor = 1
    limit = len(value) - 1
    simple_escapes = {
        "b": "\b",
        "f": "\f",
        "n": "\n",
        "r": "\r",
        "t": "\t",
        "v": "\v",
        "0": "\0",
        "\\": "\\",
        "'": "'",
        '"': '"',
        "/": "/",
    }
    while cursor < limit:
        char = value[cursor]
        if char != "\\":
            result.append(char)
            cursor += 1
            continue
        cursor += 1
        if cursor >= limit:
            return "", True
        escaped = value[cursor]
        if escaped in simple_escapes:
            result.append(simple_escapes[escaped])
            cursor += 1
            continue
        if escaped in {"\n", "\r"}:
            if escaped == "\r" and cursor + 1 < limit and value[cursor + 1] == "\n":
                cursor += 1
            cursor += 1
            continue
        if escaped == "x" and cursor + 2 < limit:
            digits = value[cursor + 1 : cursor + 3]
            if re.fullmatch(r"[0-9A-Fa-f]{2}", digits):
                result.append(chr(int(digits, 16)))
                cursor += 3
                continue
        if escaped == "u":
            if cursor + 1 < limit and value[cursor + 1] == "{":
                closing = value.find("}", cursor + 2, limit)
                digits = value[cursor + 2 : closing] if closing >= 0 else ""
                if digits and re.fullmatch(r"[0-9A-Fa-f]{1,6}", digits):
                    codepoint = int(digits, 16)
                    if codepoint <= 0x10FFFF:
                        result.append(chr(codepoint))
                        cursor = closing + 1
                        continue
            elif cursor + 4 < limit:
                digits = value[cursor + 1 : cursor + 5]
                if re.fullmatch(r"[0-9A-Fa-f]{4}", digits):
                    result.append(chr(int(digits, 16)))
                    cursor += 5
                    continue
        # JavaScript's legacy non-escape character form drops the backslash.
        # Preserve that value while surfacing conservative parser uncertainty.
        uncertain = True
        result.append(escaped)
        cursor += 1
    return "".join(result), uncertain


def decode_literal(value: str) -> str:
    """Compatibility wrapper used by the lexical scanner and tests."""
    return decode_javascript_string(value)[0]


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
                    decoded, decode_uncertain = decode_javascript_string(literal)
                    unresolved = unresolved or decode_uncertain
                    return decoded, cursor + 1
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
    invocation_resolved = True
    syntax_dynamic_uncertain = False
    workdir_attribution = "session_cwd_fallback"

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
            syntax_dynamic_uncertain = True
            workdir_attribution = "unresolved"
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
            invocation_resolved = bool(nested_calls)
            syntax_dynamic_uncertain = dynamic_workdir
        elif isinstance(raw_input, str):
            invocation_resolved = True
        else:
            invocation_resolved = False
            syntax_dynamic_uncertain = True

    if workdirs:
        workdir_attribution = "explicit"
    elif syntax_dynamic_uncertain or not invocation_resolved:
        workdir_attribution = "unresolved"
    resolved = (
        invocation_resolved
        and workdir_attribution != "unresolved"
        and not syntax_dynamic_uncertain
    )

    return {
        "record_type": record_type,
        "name": name,
        "invocations_estimate": invocations_estimate,
        "workdirs": workdirs,
        "resolved": resolved,
        "invocation_resolved": invocation_resolved,
        "workdir_attribution": workdir_attribution,
        "syntax_dynamic_uncertain": syntax_dynamic_uncertain,
    }


def metadata_details(
    canonical: dict[str, Any],
    session_meta_records: int,
    invalid_session_meta_records: int,
) -> dict[str, Any]:
    source = canonical.get("source")
    spawn: dict[str, Any] = {}
    if isinstance(source, dict):
        subagent = source.get("subagent")
        if isinstance(subagent, dict) and isinstance(subagent.get("thread_spawn"), dict):
            spawn = subagent["thread_spawn"]
    if isinstance(source, str):
        thread_source = source
    elif isinstance(source, dict):
        thread_source = str(source.get("type") or next(iter(source), ""))
    else:
        thread_source = ""
    return {
        "canonical": canonical,
        "session_meta_records": session_meta_records,
        "invalid_session_meta_records": invalid_session_meta_records,
        "parent_session_id": str(spawn.get("parent_thread_id") or ""),
        "forked_from_id": str(canonical.get("forked_from_id") or ""),
        "thread_source": thread_source,
        "agent_path": str(spawn.get("agent_path") or ""),
        "spawn_depth": spawn.get("depth"),
    }


def observe_metrics(
    metrics: ScopeMetrics,
    obj: dict[str, Any],
    ts: datetime,
    call: dict[str, Any] | None,
) -> None:
    metrics.events += 1
    metrics.first_event = ts if metrics.first_event is None else min(metrics.first_event, ts)
    metrics.last_event = ts if metrics.last_event is None else max(metrics.last_event, ts)
    payload = obj.get("payload")
    if (
        obj.get("type") == "event_msg"
        and isinstance(payload, dict)
        and payload.get("type") == "user_message"
    ):
        metrics.user_events += 1
    if not call:
        return
    metrics.tool_call_records += 1
    metrics.tool_invocations_estimate += int(call["invocations_estimate"])
    metrics.records_by_type[call["record_type"]] += 1
    metrics.tool_workdirs.update(str(item) for item in call["workdirs"])
    if not call["resolved"]:
        metrics.unresolved_tool_call_records += 1
    if not call["invocation_resolved"]:
        metrics.invocation_unresolved_records += 1
    if call["syntax_dynamic_uncertain"]:
        metrics.syntax_dynamic_uncertain_records += 1
    if call["workdir_attribution"] == "explicit":
        metrics.explicit_workdir_records += 1
    elif call["workdir_attribution"] == "session_cwd_fallback":
        metrics.session_cwd_fallback_records += 1
    else:
        metrics.workdir_unresolved_records += 1


def activity_anchor(
    obj: dict[str, Any],
    ts: datetime,
    call: dict[str, Any] | None,
) -> ActivityAnchor | None:
    payload = obj.get("payload")
    if not isinstance(payload, dict):
        return None
    if obj.get("type") == "event_msg" and payload.get("type") in {
        "user_message",
        "task_started",
        "task_complete",
    }:
        return ActivityAnchor(ts, str(payload.get("type")))
    if call:
        return ActivityAnchor(ts, "tool_call", tuple(str(item) for item in call["workdirs"]))
    if (
        obj.get("type") == "response_item"
        and payload.get("type") == "message"
        and payload.get("phase") == "final_answer"
    ):
        return ActivityAnchor(ts, "final_answer")
    return None


def scan_session_file(
    path: Path,
    start: datetime,
    end: datetime,
    diagnostics: CollectorDiagnostics | None = None,
    match_terms: list[str] | tuple[str, ...] = (),
) -> SessionInventory | None:
    canonical: dict[str, Any] = {}
    session_meta_records = 0
    invalid_session_meta_records = 0
    metrics = ScopeMetrics()
    tasks: list[TaskInventory] = []
    current_task: TaskInventory | None = None
    unbound_anchors: list[ActivityAnchor] = []
    unbound_workdirs: set[str] = set()
    locator_hits: list[LocatorHit] = []
    saw_record = False
    last_timestamp: datetime | None = None

    for obj in iter_jsonl(path, diagnostics, "sessions"):
        saw_record = True
        payload = obj.get("payload")
        if obj.get("type") == "session_meta":
            if isinstance(payload, dict) and isinstance(payload.get("id"), str) and payload["id"]:
                session_meta_records += 1
                if not canonical:
                    canonical = payload
            else:
                invalid_session_meta_records += 1

        ts = parse_event_ts(obj.get("timestamp"))
        if ts is not None:
            last_timestamp = ts if last_timestamp is None else max(last_timestamp, ts)

        event_type = payload.get("type") if isinstance(payload, dict) else ""
        if event_type == "task_started" and ts is not None:
            if current_task is not None:
                current_task.end = ts
                tasks.append(current_task)
            current_task = TaskInventory(str(payload.get("turn_id") or ""), ts)

        call = (
            parse_tool_record(payload)
            if obj.get("type") == "response_item" and isinstance(payload, dict)
            else None
        )
        searchable_values: list[str] = []
        if obj.get("type") == "session_meta" and isinstance(payload, dict):
            searchable_values.extend(
                str(payload.get(key) or "") for key in ("id", "cwd", "forked_from_id")
            )
        if event_type == "user_message" and isinstance(payload, dict):
            searchable_values.append(str(payload.get("message") or ""))
        if call:
            searchable_values.append(str(call["name"]))
            searchable_values.extend(str(item) for item in call["workdirs"])
        if current_task is not None:
            searchable_values.append(current_task.turn_id)
        if matches_terms(searchable_values, match_terms):
            locator_hits.append(
                LocatorHit(
                    ts,
                    (
                        "user_message"
                        if event_type == "user_message"
                        else "tool_call"
                        if call
                        else "session_metadata"
                    ),
                    current_task.turn_id if current_task is not None else "",
                )
            )
        if in_range(ts, start, end):
            assert ts is not None
            observe_metrics(metrics, obj, ts, call)
            anchor = activity_anchor(obj, ts, call)
            if current_task is not None:
                observe_metrics(current_task.metrics, obj, ts, call)
                if anchor:
                    current_task.anchors.append(anchor)
            else:
                if anchor:
                    unbound_anchors.append(anchor)
                if call:
                    unbound_workdirs.update(str(item) for item in call["workdirs"])

        if event_type == "task_complete" and current_task is not None:
            current_task.end = ts or last_timestamp
            tasks.append(current_task)
            current_task = None

    if not saw_record:
        return None
    if current_task is not None:
        current_task.end = last_timestamp
        tasks.append(current_task)

    details = metadata_details(canonical, session_meta_records, invalid_session_meta_records)
    return SessionInventory(
        path=normalize_path(path),
        metrics=metrics,
        tasks=tasks,
        unbound_anchors=unbound_anchors,
        unbound_workdirs=unbound_workdirs,
        locator_hits=locator_hits,
        **details,
    )


def build_session_inventory(
    codex_home: Path,
    start: datetime,
    end: datetime,
    session_ids: set[str] | None = None,
    diagnostics: CollectorDiagnostics | None = None,
    match_terms: list[str] | tuple[str, ...] = (),
) -> SessionScanResult:
    sessions_root = codex_home / "sessions"
    requested = tuple(sorted(session_ids or set()))
    if not sessions_root.exists():
        if diagnostics:
            diagnostics.source("sessions").unavailable("sessions source directory does not exist")
        return SessionScanResult([], "unavailable", requested, 0, 0, False)

    all_paths = sorted(sessions_root.rglob("*.jsonl"))
    candidate_paths = all_paths
    strategy = "full_scan"
    fallback_used = False
    if requested:
        filename_matches = [
            path
            for path in all_paths
            if any(session_id in path.stem for session_id in requested)
        ]
        if filename_matches:
            candidate_paths = filename_matches
            strategy = "session_id_filename_fast_path"
        else:
            strategy = "session_id_full_scan_fallback"
            fallback_used = True

    inventories = [
        inventory
        for path in candidate_paths
        if (inventory := scan_session_file(path, start, end, diagnostics, match_terms)) is not None
    ]
    matching = [
        inventory
        for inventory in inventories
        if not requested or session_matches(inventory.session_id, set(requested))
    ]

    if requested and strategy == "session_id_filename_fast_path" and not matching:
        fallback_used = True
        strategy = "session_id_validation_fallback"
        already_read = {inventory.path for inventory in inventories}
        for path in all_paths:
            if normalize_path(path) in already_read:
                continue
            inventory = scan_session_file(path, start, end, diagnostics, match_terms)
            if inventory is not None:
                inventories.append(inventory)
        matching = [
            inventory
            for inventory in inventories
            if session_matches(inventory.session_id, set(requested))
        ]

    return SessionScanResult(
        matching if requested else inventories,
        strategy,
        requested,
        len(all_paths),
        len(inventories),
        fallback_used,
    )


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
            resolved_workdir = resolve_tool_workdir(workdir, meta_cwd)
            if resolved_workdir and path_is_under(resolved_workdir, cwd_root):
                return {"reason": "tool_workdir", "matched_path": resolved_workdir}
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
    session_windows: dict[str, list[tuple[datetime, datetime]] | None] | None = None,
    match_terms: list[str] | tuple[str, ...] = (),
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
        if match_terms and not matches_terms([session_id, text], match_terms):
            continue
        if session_windows is not None:
            matching_window = next(
                (
                    windows
                    for selected_id, windows in session_windows.items()
                    if session_matches(session_id, {selected_id})
                ),
                [],
            )
            if matching_window is not None and not any(
                window_start <= ts <= window_end
                for window_start, window_end in matching_window
            ):
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


def combine_metrics(metrics_rows: list[ScopeMetrics]) -> ScopeMetrics:
    combined = ScopeMetrics()
    for metrics in metrics_rows:
        combined.events += metrics.events
        combined.user_events += metrics.user_events
        combined.tool_call_records += metrics.tool_call_records
        combined.tool_invocations_estimate += metrics.tool_invocations_estimate
        combined.unresolved_tool_call_records += metrics.unresolved_tool_call_records
        combined.invocation_unresolved_records += metrics.invocation_unresolved_records
        combined.workdir_unresolved_records += metrics.workdir_unresolved_records
        combined.syntax_dynamic_uncertain_records += metrics.syntax_dynamic_uncertain_records
        combined.explicit_workdir_records += metrics.explicit_workdir_records
        combined.session_cwd_fallback_records += metrics.session_cwd_fallback_records
        for record_type, count in metrics.records_by_type.items():
            combined.records_by_type[record_type] += count
        combined.tool_workdirs.update(metrics.tool_workdirs)
        if metrics.first_event is not None:
            combined.first_event = (
                metrics.first_event
                if combined.first_event is None
                else min(combined.first_event, metrics.first_event)
            )
        if metrics.last_event is not None:
            combined.last_event = (
                metrics.last_event
                if combined.last_event is None
                else max(combined.last_event, metrics.last_event)
            )
    return combined


def selection_metrics(selection: SessionSelection) -> ScopeMetrics:
    if selection.task_indexes is None:
        return selection.inventory.metrics
    return combine_metrics(
        [selection.inventory.tasks[index].metrics for index in selection.task_indexes]
    )


def full_session_selection(
    inventory: SessionInventory,
    reason: str,
) -> SessionSelection:
    return SessionSelection(
        inventory,
        {"reason": reason, "matched_path": ""},
        None,
        "full_session",
    )


def project_session_selection(
    inventory: SessionInventory,
    cwd_root: Path,
) -> SessionSelection | None:
    metadata_match = bool(inventory.cwd and path_is_under(inventory.cwd, cwd_root))
    matching_indexes: list[int] = []
    matching_workdirs: set[str] = set()
    for index, task in enumerate(inventory.tasks):
        if not task.metrics.events:
            continue
        task_matches = {
            resolved
            for workdir in task.metrics.tool_workdirs
            if (resolved := resolve_tool_workdir(workdir, inventory.cwd)) is not None
            and path_is_under(resolved, cwd_root)
        }
        if metadata_match or task_matches:
            matching_indexes.append(index)
            matching_workdirs.update(task_matches)

    unbound_matches = {
        resolved
        for workdir in inventory.unbound_workdirs
        if (resolved := resolve_tool_workdir(workdir, inventory.cwd)) is not None
        and path_is_under(resolved, cwd_root)
    }
    if not metadata_match and not matching_indexes and not unbound_matches:
        return None

    if metadata_match:
        scope_match = {"reason": "metadata_cwd", "matched_path": inventory.cwd}
    else:
        matched_path = min(matching_workdirs | unbound_matches)
        scope_match = {"reason": "tool_workdir", "matched_path": matched_path}
    history_binding = "task_bound" if matching_indexes else "unbound_suppressed"
    return SessionSelection(
        inventory,
        scope_match,
        tuple(matching_indexes),
        history_binding,
        normalize_path(cwd_root),
    )


def history_windows_for_selections(
    selections: list[SessionSelection],
) -> dict[str, list[tuple[datetime, datetime]] | None]:
    windows_by_session: dict[str, list[tuple[datetime, datetime]] | None] = {}
    for selection in selections:
        session_id = selection.inventory.session_id
        if selection.task_indexes is None:
            windows_by_session[session_id] = None
            continue
        if windows_by_session.get(session_id) is None and session_id in windows_by_session:
            continue
        windows = windows_by_session.setdefault(session_id, [])
        assert windows is not None
        for index in selection.task_indexes:
            task = selection.inventory.tasks[index]
            task_end = task.end or task.metrics.last_event or task.start
            if task_end >= task.start:
                windows.append(
                    (
                        task.start - timedelta(seconds=TASK_HISTORY_PRELUDE_SECONDS),
                        task_end,
                    )
                )
    return windows_by_session


def inventory_scope_match(
    inventory: SessionInventory,
    cwd_root: Path,
) -> dict[str, str] | None:
    selection = project_session_selection(inventory, cwd_root)
    return selection.scope_match if selection else None


def tool_activity_from_metrics(metrics: ScopeMetrics) -> dict[str, Any]:
    workdirs = sorted(metrics.tool_workdirs)
    return {
        "call_records": metrics.tool_call_records,
        "invocations_estimate": metrics.tool_invocations_estimate,
        "invocations_estimate_kind": "syntactic_call_site_estimate",
        "unresolved_records": metrics.unresolved_tool_call_records,
        "records_by_type": dict(metrics.records_by_type),
        "workdir_attribution": {
            "explicit_records": metrics.explicit_workdir_records,
            "session_cwd_fallback_records": metrics.session_cwd_fallback_records,
            "unresolved_records": metrics.workdir_unresolved_records,
            "paths": workdirs,
        },
        "parser_resolution": {
            "invocation": {
                "resolved_records": (
                    metrics.tool_call_records - metrics.invocation_unresolved_records
                ),
                "unresolved_records": metrics.invocation_unresolved_records,
            },
            "workdir": {
                "explicit_records": metrics.explicit_workdir_records,
                "session_cwd_fallback_records": metrics.session_cwd_fallback_records,
                "unresolved_records": metrics.workdir_unresolved_records,
            },
            "syntax_dynamic_uncertain_records": metrics.syntax_dynamic_uncertain_records,
        },
    }


def session_from_selection(
    selection: SessionSelection,
    local_tz: ZoneInfo,
) -> dict[str, Any]:
    inventory = selection.inventory
    scope_match = selection.scope_match
    metrics = selection_metrics(selection)
    start_ts = parse_event_ts(inventory.canonical.get("timestamp"))
    tool_activity = tool_activity_from_metrics(metrics)
    matched_path = scope_match["matched_path"]
    return {
        "session": inventory.session_id[:8],
        "session_id": inventory.session_id,
        "started": start_ts.astimezone(local_tz).isoformat(timespec="minutes") if start_ts else "",
        "first_event": metrics.first_event.astimezone(local_tz).isoformat(timespec="minutes") if metrics.first_event else "",
        "last_event": metrics.last_event.astimezone(local_tz).isoformat(timespec="minutes") if metrics.last_event else "",
        "cwd": inventory.cwd,
        "events": metrics.events,
        "user_events": metrics.user_events,
        "tool_calls": metrics.tool_call_records,
        "file": str(inventory.path),
        "identity_source": "first_session_meta" if inventory.session_meta_records else "filename_fallback",
        "session_meta_records": inventory.session_meta_records,
        "invalid_session_meta_records": inventory.invalid_session_meta_records,
        "parent_session_id": inventory.parent_session_id,
        "forked_from_session_id": inventory.forked_from_id,
        "forked_from_id": inventory.forked_from_id,
        "thread_source": inventory.thread_source,
        "agent_path": inventory.agent_path,
        "spawn_depth": inventory.spawn_depth,
        "scope_match": scope_match,
        "match_reason": scope_match["reason"],
        "matched_workdirs": [matched_path] if matched_path else [],
        "match_uncertain": (
            scope_match["reason"] == "tool_workdir"
            or selection.history_binding == "unbound_suppressed"
        ),
        "task_scope": {
            "mode": selection.history_binding,
            "matched_tasks": (
                len(selection.task_indexes)
                if selection.task_indexes is not None
                else len([task for task in inventory.tasks if task.metrics.events])
            ),
            "tasks_in_range": len([task for task in inventory.tasks if task.metrics.events]),
            "history_previews_bound": selection.history_binding != "unbound_suppressed",
        },
        "tool_call_records": metrics.tool_call_records,
        "tool_invocations_estimate": metrics.tool_invocations_estimate,
        "tool_workdirs": sorted(metrics.tool_workdirs),
        "unresolved_tool_call_records": metrics.unresolved_tool_call_records,
        "tool_activity": tool_activity,
    }


def sessions_from_inventory(
    inventories: list[SessionInventory],
    local_tz: ZoneInfo,
    session_ids: set[str] | None = None,
    cwd_root: Path | None = None,
) -> list[dict[str, Any]]:
    sessions: list[dict[str, Any]] = []
    for inventory in inventories:
        if inventory.metrics.events == 0:
            continue
        if session_ids is not None and not session_matches(inventory.session_id, session_ids):
            continue
        if cwd_root is not None:
            selection = project_session_selection(inventory, cwd_root)
            if selection is None:
                continue
        elif session_ids is not None:
            selection = full_session_selection(inventory, "session_id")
        else:
            selection = full_session_selection(inventory, "time_range")
        sessions.append(session_from_selection(selection, local_tz))
    return sessions


def collect_sessions(
    codex_home: Path,
    start: datetime,
    end: datetime,
    local_tz: ZoneInfo,
    session_ids: set[str] | None = None,
    cwd_root: Path | None = None,
    diagnostics: CollectorDiagnostics | None = None,
) -> list[dict[str, Any]]:
    scan = build_session_inventory(codex_home, start, end, session_ids, diagnostics)
    return sessions_from_inventory(scan.inventories, local_tz, session_ids, cwd_root)


def activity_events_from_selections(
    selections: list[SessionSelection],
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    git_root_cache: dict[str, Path | None] = {}

    def cached_git_root(path_value: str) -> Path | None:
        if not path_value:
            return None
        if path_value not in git_root_cache:
            git_root_cache[path_value] = find_git_root(Path(path_value))
        return git_root_cache[path_value]

    for selection in selections:
        inventory = selection.inventory
        project_root = cached_git_root(inventory.cwd)
        project = project_root.name if project_root else (Path(inventory.cwd).name if inventory.cwd else "unknown")
        if selection.task_indexes is None:
            anchors = [anchor for task in inventory.tasks for anchor in task.anchors]
            anchors.extend(inventory.unbound_anchors)
        elif selection.history_binding == "unbound_suppressed":
            anchors = inventory.unbound_anchors
        else:
            anchors = [
                anchor
                for index in selection.task_indexes
                for anchor in inventory.tasks[index].anchors
            ]
        for anchor in anchors:
            if selection.project_root is not None:
                matching_anchor_workdirs = tuple(
                    resolved
                    for workdir in anchor.workdirs
                    if (
                        resolved := resolve_tool_workdir(workdir, inventory.cwd)
                    )
                    is not None
                    and path_is_under(resolved, selection.project_root)
                )
                event_cwds = matching_anchor_workdirs or (
                    (selection.scope_match["matched_path"],)
                    if selection.scope_match["matched_path"]
                    else ()
                )
            else:
                resolved_anchor_workdirs = tuple(
                    resolved
                    for workdir in anchor.workdirs
                    if (resolved := resolve_tool_workdir(workdir, inventory.cwd))
                    is not None
                )
                event_cwds = resolved_anchor_workdirs or (
                    (inventory.cwd,) if inventory.cwd else ()
                )
            for event_cwd in dict.fromkeys(str(item) for item in event_cwds if item):
                event_project_root = cached_git_root(event_cwd)
                event_project = event_project_root.name if event_project_root else project
                events.append(
                    {
                        "timestamp": iso_utc(anchor.timestamp),
                        "session_id": inventory.session_id,
                        "source": "session",
                        "project": event_project,
                        "cwd": event_cwd,
                    }
                )
    return events


def activity_events_from_inventory(
    inventories: list[SessionInventory],
    session_ids: set[str] | None = None,
    cwd_root: Path | None = None,
) -> list[dict[str, Any]]:
    selections: list[SessionSelection] = []
    for inventory in inventories:
        if not inventory.metrics.events:
            continue
        if session_ids is not None and not session_matches(inventory.session_id, session_ids):
            continue
        if cwd_root is not None:
            selection = project_session_selection(inventory, cwd_root)
            if selection is None:
                continue
        else:
            selection = full_session_selection(
                inventory,
                "session_id" if session_ids is not None else "time_range",
            )
        selections.append(selection)
    return activity_events_from_selections(selections)


def collect_session_activity_events(
    codex_home: Path,
    start: datetime,
    end: datetime,
    session_ids: set[str] | None = None,
    cwd_root: Path | None = None,
    diagnostics: CollectorDiagnostics | None = None,
) -> list[dict[str, Any]]:
    scan = build_session_inventory(codex_home, start, end, session_ids, diagnostics)
    return activity_events_from_inventory(scan.inventories, session_ids, cwd_root)


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


def infer_session_id_from_inventory(
    inventories: list[SessionInventory],
    cwd_root: Path | None = None,
) -> str | None:
    candidates = [
        inventory
        for inventory in inventories
        if inventory.metrics.events
        and (cwd_root is None or inventory_scope_match(inventory, cwd_root) is not None)
    ]
    if not candidates:
        return None
    candidates.sort(
        key=lambda inventory: inventory.metrics.last_event or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    return candidates[0].session_id


def current_script_sha256() -> str:
    try:
        return hashlib.sha256(SCRIPT_PATH.read_bytes()).hexdigest()
    except OSError:
        return ""


def enabled_sources(args: argparse.Namespace) -> set[str]:
    if args.sources:
        return set(args.sources)
    if args.mode == "locate":
        return {"history", "sessions", "rollout_summaries"}
    return set(SOURCE_NAMES)


def selection_locator_hits(selection: SessionSelection) -> list[LocatorHit]:
    if selection.task_indexes is None:
        return selection.inventory.locator_hits
    turn_ids = {
        selection.inventory.tasks[index].turn_id
        for index in selection.task_indexes
    }
    if selection.history_binding == "unbound_suppressed":
        return [hit for hit in selection.inventory.locator_hits if not hit.turn_id]
    return [hit for hit in selection.inventory.locator_hits if hit.turn_id in turn_ids]


def build_locator_summary(
    selections: list[SessionSelection],
    history: list[dict[str, Any]],
    sources: set[str],
) -> dict[str, Any]:
    history_session_ids = {str(item["session_id"]) for item in history}
    candidates: list[dict[str, Any]] = []
    represented_session_ids: set[str] = set()
    for selection in selections:
        hits = selection_locator_hits(selection)
        inventory = selection.inventory
        if not hits and not any(
            session_matches(inventory.session_id, {history_id})
            for history_id in history_session_ids
        ):
            continue
        represented_session_ids.add(inventory.session_id)
        task_rows: list[dict[str, Any]] = []
        for task in inventory.tasks:
            task_hits = [hit for hit in hits if hit.turn_id == task.turn_id]
            if not task_hits:
                continue
            task_rows.append(
                {
                    "turn_id": task.turn_id,
                    "start_utc": iso_utc(task.start),
                    "end_utc": iso_utc(task.end) if task.end else "",
                    "hit_count": len(task_hits),
                    "hit_kinds": sorted({hit.kind for hit in task_hits}),
                }
            )
        hit_timestamps = [hit.timestamp for hit in hits if hit.timestamp is not None]
        candidates.append(
            {
                "session_id": inventory.session_id,
                "cwd": inventory.cwd,
                "file": str(inventory.path),
                "scope_match": selection.scope_match,
                "history_binding": selection.history_binding,
                "hit_count": len(hits),
                "hit_kinds": sorted({hit.kind for hit in hits}),
                "last_hit_utc": iso_utc(max(hit_timestamps)) if hit_timestamps else "",
                "tasks": task_rows,
            }
        )
    candidates.sort(
        key=lambda candidate: (candidate["hit_count"], candidate["last_hit_utc"]),
        reverse=True,
    )
    for rank, candidate in enumerate(candidates, 1):
        candidate["rank"] = rank
    history_only_ids = sorted(
        history_id
        for history_id in history_session_ids
        if not any(
            session_matches(history_id, {represented})
            for represented in represented_session_ids
        )
    )
    return {
        "query": {
            "term_count": 0,
            "terms_included": False,
            "sources": [name for name in SOURCE_NAMES if name in sources],
        },
        "candidate_count": len(candidates) + len(history_only_ids),
        "candidates": candidates,
        "history_only_session_ids": history_only_ids,
    }


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
    invocation_unresolved_records = 0
    explicit_workdir_records = 0
    fallback_workdir_records = 0
    workdir_unresolved_records = 0
    syntax_dynamic_uncertain_records = 0
    recognized_workdirs: set[str] = set()
    for session in sessions:
        tool_activity = session["tool_activity"]
        call_records += int(tool_activity["call_records"])
        invocations_estimate += int(tool_activity["invocations_estimate"])
        unresolved_records += int(tool_activity["unresolved_records"])
        parser_resolution = tool_activity["parser_resolution"]
        invocation_unresolved_records += int(
            parser_resolution["invocation"]["unresolved_records"]
        )
        explicit_workdir_records += int(parser_resolution["workdir"]["explicit_records"])
        fallback_workdir_records += int(
            parser_resolution["workdir"]["session_cwd_fallback_records"]
        )
        workdir_unresolved_records += int(
            parser_resolution["workdir"]["unresolved_records"]
        )
        syntax_dynamic_uncertain_records += int(
            parser_resolution["syntax_dynamic_uncertain_records"]
        )
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
                "resolution": {
                    "invocation": {
                        "resolved_records": call_records - invocation_unresolved_records,
                        "unresolved_records": invocation_unresolved_records,
                    },
                    "workdir": {
                        "explicit_records": explicit_workdir_records,
                        "session_cwd_fallback_records": fallback_workdir_records,
                        "unresolved_records": workdir_unresolved_records,
                    },
                    "syntax_dynamic_uncertain_records": syntax_dynamic_uncertain_records,
                },
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
    sources = enabled_sources(args)
    for source_name in SOURCE_NAMES:
        if source_name not in sources:
            diagnostics.source(source_name).skip("source_filter")
    scope = resolve_scope(args, codex_home, local_tz)
    start = scope["start"]
    end = scope["end"]

    # A known session ID can be resolved from its rollout filename and scanned
    # directly. Session scope without an explicit start scans the selected
    # session from its beginning, while every other scope keeps the requested
    # time window.
    requested_scan_ids = (
        {scope["session_id"]}
        if args.scope == "session" and scope["session_id"]
        else None
    )
    scan_start = (
        datetime(1970, 1, 1, tzinfo=timezone.utc)
        if args.scope == "session" and not args.start
        else start
    )
    if "sessions" in sources:
        session_scan = build_session_inventory(
            codex_home,
            scan_start,
            end,
            requested_scan_ids,
            diagnostics,
            args.match if args.mode == "locate" else (),
        )
    else:
        session_scan = SessionScanResult(
            [], "source_filter", tuple(sorted(requested_scan_ids or set())), 0, 0, False
        )

    if args.scope in {"local", "session"} and not scope["session_id"]:
        inferred = infer_session_id_from_inventory(
            session_scan.inventories,
            Path(scope["project_root"]) if args.scope == "local" else None,
        )
        if not inferred and args.scope == "local":
            inferred = infer_session_id_from_inventory(session_scan.inventories)
            if inferred:
                scope["warnings"].append(
                    "inferred session_id from latest session in range without cwd/project match"
                )
        if inferred:
            scope["session_id"] = inferred
            scope["warnings"].append(f"inferred session_id={inferred}")
        else:
            scope["warnings"].append(
                "could not infer a current Codex session_id for this scope"
            )

    if args.scope == "session" and not args.start and scope["session_id"]:
        selected_for_start = next(
            (
                inventory
                for inventory in session_scan.inventories
                if session_matches(inventory.session_id, {scope["session_id"]})
            ),
            None,
        )
        if selected_for_start:
            session_started = parse_event_ts(selected_for_start.canonical.get("timestamp"))
            if session_started:
                start = session_started
                scope["start"] = start

    scope["session_scan"] = {
        "strategy": session_scan.strategy,
        "files_available": session_scan.files_available,
        "files_read": session_scan.files_read,
        "fallback_used": session_scan.fallback_used,
    }

    selected_session_ids: set[str] | None = None
    selected_repo_roots = repo_roots
    summary_terms: list[str] | None = None
    notes_terms: list[str] | None = None
    selected: list[SessionSelection] = []

    if args.scope == "global":
        scope["notes_mode"] = "all_in_range"
        selected = [
            full_session_selection(inventory, "time_range")
            for inventory in session_scan.inventories
            if inventory.metrics.events
        ]
    elif args.scope == "session":
        scope["notes_mode"] = "disabled"
        selected_session_ids = {scope["session_id"]} if scope["session_id"] else set()
        selected_repo_roots = [Path(scope["project_root"])]
        summary_terms = [Path(scope["project_root"]).name, scope["session_id"]]
        selected = [
            full_session_selection(inventory, "session_id")
            for inventory in session_scan.inventories
            if inventory.metrics.events
            and session_matches(inventory.session_id, selected_session_ids)
        ]
    elif args.scope == "project":
        scope["notes_mode"] = "project_terms"
        project_root = Path(scope["project_root"])
        selected = [
            selection
            for inventory in session_scan.inventories
            if inventory.metrics.events
            and (selection := project_session_selection(inventory, project_root))
            is not None
        ]
        selected_session_ids = {selection.inventory.session_id for selection in selected}
        selected_repo_roots = [Path(scope["project_root"])]
        summary_terms = [Path(scope["project_root"]).name]
        notes_terms = summary_terms
    else:
        scope["notes_mode"] = "project_terms"
        local_ids = {scope["session_id"]} if scope["session_id"] else set()
        project_root = Path(scope["project_root"])
        for inventory in session_scan.inventories:
            if not inventory.metrics.events:
                continue
            if session_matches(inventory.session_id, local_ids):
                selected.append(full_session_selection(inventory, "session_id"))
                continue
            project_selection = project_session_selection(inventory, project_root)
            if project_selection is not None:
                selected.append(project_selection)
                local_ids.add(inventory.session_id)
        selected_session_ids = local_ids
        selected_repo_roots = [Path(scope["project_root"])]
        summary_terms = [Path(scope["project_root"]).name, scope["session_id"]]
        notes_terms = summary_terms

    if "history" in sources:
        history = collect_history(
            codex_home,
            start,
            end,
            local_tz,
            args.prompt_preview_chars,
            session_ids=selected_session_ids,
            session_windows=(
                None
                if args.scope in {"global", "session"}
                else history_windows_for_selections(selected)
            ),
            match_terms=args.match if args.mode == "locate" else (),
            diagnostics=diagnostics,
        )
    else:
        history = []

    if args.mode == "locate":
        history_session_ids = {str(item["session_id"]) for item in history}
        selected = [
            selection
            for selection in selected
            if selection_locator_hits(selection)
            or any(
                session_matches(selection.inventory.session_id, {history_id})
                for history_id in history_session_ids
            )
        ]
    activity_events = activity_events_from_selections(selected)
    if not activity_events:
        activity_events = [
            {
                "timestamp": iso_utc(timestamp),
                "session_id": item["session_id"],
                "source": "history",
                "project": "",
                "cwd": "",
            }
            for item in history
            if (timestamp := parse_event_ts(item["local_time"])) is not None
        ]
    sessions = [session_from_selection(selection, local_tz) for selection in selected]
    if "rollout_summaries" in sources:
        rollout_summaries = collect_rollout_summaries(
            codex_home,
            start,
            end,
            local_tz,
            match_terms=(args.match if args.mode == "locate" else summary_terms),
            diagnostics=diagnostics,
        )
    else:
        rollout_summaries = []
    if "git" in sources:
        git_activity = collect_git(selected_repo_roots, start, end, diagnostics)
        if args.mode == "locate":
            git_activity = {
                repo: [
                    commit
                    for commit in commits
                    if matches_terms(
                        [
                            repo,
                            str(commit["subject"]),
                            str(commit["author"]["name"]),
                            str(commit["committer"]["name"]),
                        ],
                        args.match,
                    )
                ]
                for repo, commits in git_activity.items()
            }
            git_activity = {repo: commits for repo, commits in git_activity.items() if commits}
    else:
        git_activity = {}
    if "notes" not in sources:
        notes = []
    elif args.scope == "session":
        diagnostics.source("notes").skip("session_scope_unbound")
        notes: list[dict[str, str]] = []
    else:
        notes = collect_notes(
            notes_root,
            start,
            end,
            local_tz,
            match_terms=(args.match if args.mode == "locate" else notes_terms),
            diagnostics=diagnostics,
        )
    work_time_estimate = estimate_work_time(activity_events, local_tz, args.activity_gap_minutes)
    collector_diagnostics = finalize_diagnostics(diagnostics, sessions)
    locator = (
        build_locator_summary(selected, history, sources)
        if args.mode == "locate"
        else None
    )
    if locator is not None:
        locator["query"]["term_count"] = len(
            [term for term in args.match if term.strip()]
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "mode": args.mode,
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
        "sources_enabled": [name for name in SOURCE_NAMES if name in sources],
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
        "locator": locator,
    }


def emit_locator_markdown(payload: dict[str, Any]) -> None:
    locator = payload["locator"]
    collector = payload["collector"]
    report_range = payload["range"]
    print("# Codex Session Locator")
    print()
    print(
        f"- Provenance: schema v{payload['schema_version']}; {collector['name']} "
        f"{collector['version']}; `{collector['script_sha256']}`; coverage={payload['diagnostics']['status']}"
    )
    print(f"- Scope: {payload['scope']['effective']}")
    print(
        f"- Range: {report_range['start_local']} to {report_range['end_local']} "
        f"({report_range['timezone']})"
    )
    print(f"- Sources: {', '.join(locator['query']['sources'])}")
    print(
        f"- Query: {locator['query']['term_count']} term(s); terms intentionally omitted from metadata"
    )
    print(f"- Candidates: {locator['candidate_count']}")
    print()
    print("## Session And Task Candidates")
    print()
    if not locator["candidates"]:
        print("No session-backed candidates found.")
    for candidate in locator["candidates"]:
        print(
            f"- #{candidate['rank']} `{candidate['session_id']}`; cwd={candidate['cwd'] or '(unknown)'}; "
            f"match={candidate['scope_match']['reason']}; hits={candidate['hit_count']} "
            f"({', '.join(candidate['hit_kinds']) or 'history'})"
        )
        for task in candidate["tasks"]:
            print(
                f"  - task `{task['turn_id'] or '(unbound)'}` {task['start_utc']} to "
                f"{task['end_utc'] or '(open)'}; hits={task['hit_count']} "
                f"({', '.join(task['hit_kinds'])})"
            )
    for session_id in locator["history_only_session_ids"]:
        print(f"- `{session_id}`; history-only candidate")
    print()
    print(f"## Matching Prompt Previews ({len(payload['history'])})")
    print()
    for item in payload["history"]:
        if item["preview_suppressed"]:
            print(
                f"- {item['local_time']} session `{item['session']}` "
                "[secret-context; preview suppressed]"
            )
        else:
            print(f"- {item['local_time']} session `{item['session']}`: {item['text']}")
    print()
    print(f"## Matching Rollout Summaries ({len(payload['rollout_summaries'])})")
    print()
    for item in payload["rollout_summaries"]:
        print(f"- {item['local_time']}: {item['title']} ({item['file']})")
    print()
    print(
        "Next step: choose a candidate session ID, then run evidence mode with "
        "`--scope session --session-id <id> --output <private-path>`."
    )


def emit_markdown(payload: dict[str, Any]) -> None:
    if payload.get("mode") == "locate":
        emit_locator_markdown(payload)
        return
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
            f"task-scope={item['task_scope']['mode']} ({item['task_scope']['matched_tasks']} matched), "
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


def write_private_output(
    output_path: Path,
    output_format: str,
    payload: dict[str, Any],
) -> None:
    output_path = output_path.expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output_path.name}.",
        suffix=".tmp",
        dir=output_path.parent,
        text=True,
    )
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(file_descriptor, 0o600)
        with os.fdopen(file_descriptor, "w", encoding="utf-8", newline="\n") as handle:
            if output_format == "json":
                json.dump(payload, handle, ensure_ascii=False, indent=2)
                handle.write("\n")
            else:
                with contextlib.redirect_stdout(handle):
                    emit_markdown(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, output_path)
        output_path.chmod(0o600)
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(file_descriptor)
        with contextlib.suppress(OSError):
            temporary_path.unlink()
        raise


def main() -> int:
    args = parse_args()
    payload = build_payload(args)
    if args.output:
        write_private_output(Path(args.output), args.format, payload)
    elif args.format == "json":
        json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
        print()
    else:
        emit_markdown(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
