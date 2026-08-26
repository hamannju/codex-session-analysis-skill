"""Self-contained fallback for the Codex skill-creator quick validator."""

import re
import sys
from pathlib import Path

import yaml

MAX_SKILL_NAME_LENGTH = 64
ALLOWED_FRONTMATTER_PROPERTIES = {
    "allowed-tools",
    "description",
    "license",
    "metadata",
    "name",
}


def validate_skill(skill_path: str) -> tuple[bool, str]:
    """Validate the portable subset of the Codex SKILL.md contract."""
    skill_md = Path(skill_path) / "SKILL.md"
    if not skill_md.exists():
        return False, "SKILL.md not found"

    content = skill_md.read_text(encoding="utf-8")
    if not content.startswith("---"):
        return False, "No YAML frontmatter found"

    match = re.match(r"^---\n(.*?)\n---", content, re.DOTALL)
    if not match:
        return False, "Invalid frontmatter format"

    try:
        frontmatter = yaml.safe_load(match.group(1))
    except yaml.YAMLError as error:
        return False, f"Invalid YAML in frontmatter: {error}"

    if not isinstance(frontmatter, dict):
        return False, "Frontmatter must be a YAML dictionary"

    unexpected_keys = set(frontmatter) - ALLOWED_FRONTMATTER_PROPERTIES
    if unexpected_keys:
        allowed = ", ".join(sorted(ALLOWED_FRONTMATTER_PROPERTIES))
        unexpected = ", ".join(sorted(unexpected_keys))
        return (
            False,
            (
                f"Unexpected key(s) in SKILL.md frontmatter: {unexpected}. "
                f"Allowed properties are: {allowed}"
            ),
        )

    if "name" not in frontmatter:
        return False, "Missing 'name' in frontmatter"
    if "description" not in frontmatter:
        return False, "Missing 'description' in frontmatter"

    name = frontmatter.get("name", "")
    if not isinstance(name, str):
        return False, f"Name must be a string, got {type(name).__name__}"
    name = name.strip()
    if name:
        if not re.fullmatch(r"[a-z0-9-]+", name):
            return (
                False,
                (
                    f"Name '{name}' should be hyphen-case "
                    "(lowercase letters, digits, and hyphens only)"
                ),
            )
        if name.startswith("-") or name.endswith("-") or "--" in name:
            return (
                False,
                f"Name '{name}' cannot start/end with hyphen or contain consecutive hyphens",
            )
        if len(name) > MAX_SKILL_NAME_LENGTH:
            return (
                False,
                (
                    f"Name is too long ({len(name)} characters). "
                    f"Maximum is {MAX_SKILL_NAME_LENGTH} characters."
                ),
            )

    description = frontmatter.get("description", "")
    if not isinstance(description, str):
        return False, f"Description must be a string, got {type(description).__name__}"
    description = description.strip()
    if description.startswith("[TODO:"):
        return False, "Description contains an unfinished TODO placeholder"
    if description:
        if "<" in description or ">" in description:
            return False, "Description cannot contain angle brackets (< or >)"
        if len(description) > 1024:
            return (
                False,
                (
                    f"Description is too long ({len(description)} characters). "
                    "Maximum is 1024 characters."
                ),
            )

    fence_marker = None
    fence_length = 0
    for line in content[match.end() :].splitlines():
        fence = re.match(
            r"^[ \t]*(?:(?:[-+*]|\d+[.)])[ \t]+)?(`{3,}|~{3,})(.*)$",
            line,
        )
        if fence:
            marker = fence.group(1)
            if fence_marker is None:
                fence_marker = marker[0]
                fence_length = len(marker)
            elif (
                marker[0] == fence_marker
                and len(marker) >= fence_length
                and not fence.group(2).strip()
            ):
                fence_marker = None
                fence_length = 0
            continue

        if fence_marker is None and re.fullmatch(
            r"[ ]{0,3}\[TODO:[^\n]*\][ \t]*",
            line,
        ):
            return False, "Skill instructions contain an unfinished TODO placeholder"

    return True, "Skill is valid!"


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python quick_validate_skill.py <skill_directory>")
        return 1

    valid, message = validate_skill(sys.argv[1])
    print(message)
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
