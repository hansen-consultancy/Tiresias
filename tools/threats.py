"""Validates docs/threats/*.md and prints the risk summary.

Each finding is one file with a small front matter block (see docs/threats/README.md). The
summary is printed, never committed, so no two branches ever edit the same line of it.

    python -I tools/threats.py            summary, highest score first
    python -I tools/threats.py --check    validation only; exit 1 on any problem
"""

import pathlib
import re
import sys

FOLDER = pathlib.Path(__file__).resolve().parent.parent / "docs" / "threats"
CATEGORIES = {
    "S": "Spoofing",
    "T": "Tampering",
    "R": "Repudiation",
    "I": "Information disclosure",
    "D": "Denial of service",
    "E": "Elevation of privilege",
}
STATUSES = ("open", "mitigated", "accepted", "resolved")
REQUIRED = ("id", "title", "stride", "likelihood", "impact", "status", "control")
HIGH = 8


def front_matter(text):
    match = re.match(r"---\r?\n(.*?)\r?\n---\r?\n", text, re.DOTALL)
    if not match:
        return None
    fields = {}
    for line in match.group(1).splitlines():
        key, sep, value = line.partition(":")
        if sep:
            fields[key.strip()] = value.strip()
    return fields


def problems_of(path, fields):
    if fields is None:
        return ["no front matter"]
    found = [f"missing '{key}'" for key in REQUIRED if not fields.get(key)]
    if found:
        return found
    if fields["id"] != path.stem:
        found.append(f"id '{fields['id']}' differs from the file name")
    letter, _, rest = fields["id"].partition("-")
    if CATEGORIES.get(letter) != fields["stride"]:
        found.append(f"stride '{fields['stride']}' doesn't match the id's letter '{letter}'")
    if not re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", rest):
        found.append("id must be <letter>-<issue number> or <letter>-<lowercase-slug>")
    for key in ("likelihood", "impact"):
        if fields[key] not in ("1", "2", "3", "4"):
            found.append(f"{key} must be 1 to 4")
    if fields["status"] not in STATUSES:
        found.append(f"status must be one of {', '.join(STATUSES)}")
    issue = fields.get("issue", "")
    if issue and not issue.isdigit():
        found.append("issue must be a number")
    if rest.isdigit() and issue != rest:
        found.append(f"id names issue {rest} but issue is '{issue}'")
    if not found and fields["status"] == "open" and score(fields) >= HIGH and not issue:
        found.append(f"an open finding scoring {HIGH} or more needs an issue")
    return found


def score(fields):
    return int(fields["likelihood"]) * int(fields["impact"])


def main(argv):
    check_only = "--check" in argv
    findings, failed = [], False
    for path in sorted(FOLDER.glob("*.md")):
        if path.name == "README.md":
            continue
        fields = front_matter(path.read_text(encoding="utf-8"))
        problems = problems_of(path, fields)
        for problem in problems:
            print(f"{path.name}: {problem}", file=sys.stderr)
        failed |= bool(problems)
        if not problems:
            findings.append(fields)
    if failed:
        return 1
    if check_only:
        print(f"{len(findings)} findings, all valid")
        return 0
    order = {status: i for i, status in enumerate(STATUSES)}
    findings.sort(key=lambda f: (order[f["status"]], -score(f), f["id"]))
    print("| ID | Finding | Score | Status | Issue |")
    print("|---|---|---|---|---|")
    for f in findings:
        level = " (high)" if score(f) >= HIGH else ""
        issue = f"#{f['issue']}" if f.get("issue") else ""
        print(f"| {f['id']} | {f['title']} | {score(f)}{level} | {f['status']} | {issue} |")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
